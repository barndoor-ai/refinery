//! Postgres TLS support for the refinery CLI.
//!
//! # Provenance — keep this in sync
//!
//! This module is a **copy** of `bdai-platform/libs/pg-tls/src/lib.rs` (and the
//! sibling `dsn.rs`, `tls.rs`, `verifier.rs` files, each of which names its
//! counterpart in its own header). It is a copy rather than a dependency
//! because refinery lives in a separate repository and this fork is rebased on
//! upstream refinery; it cannot take a path or git dependency on the platform
//! workspace. **The two must stay behaviourally identical** — if you change the
//! mode mapping, the query-string handling or the verifier semantics here, make
//! the same change there, and vice versa.
//!
//! The only intentional divergences from the sibling crate are called out where
//! they occur:
//!
//! * `currentSchema` is additionally consumed out of the query string (refinery
//!   uses it to pick the migration table's schema, and `postgres::Config`
//!   rejects it as an unknown option).
//! * the crypto provider is `ring`, not `aws-lc-rs`, because this binary is
//!   built statically against musl in a `FROM scratch` image and `aws-lc-rs`
//!   needs cmake/nasm in the builder.
//! * errors are `anyhow` rather than a `thiserror` enum, matching this crate.
//!
//! One further divergence is **not** intentional in the sibling's favour: the
//! consumed query values are percent-decoded here with `percent-encoding`,
//! where the sibling still uses `url::form_urlencoded::parse` and therefore
//! turns a `+` into a space that the driver would have left literal. The
//! sibling needs the same fix — see `dsn.rs`'s header.
//!
//! # Why this exists
//!
//! `postgres`/`tokio-postgres` understands only three `sslmode` values —
//! `disable`, `prefer` and `require` — and rejects every other libpq value as a
//! **connection-string parse error**. It also rejects `sslrootcert`, `sslcert`
//! and `sslkey` outright as unknown options. Operators and Helm charts,
//! however, write libpq DSNs. [`dsn::resolve`] rewrites the DSN into something
//! `postgres::Config` accepts while remembering the verification tier the
//! operator actually asked for, and [`tls::client_config`] builds a rustls
//! connector configured for that tier.
//!
//! # Mode mapping
//!
//! | DSN `sslmode` | rewritten to | verification |
//! |---|---|---|
//! | absent | *(DSN left untouched)* | [`Verification::None`] |
//! | `disable` | `disable` | [`Verification::None`] |
//! | `allow` | `prefer` | [`Verification::None`] |
//! | `prefer` | `prefer` | [`Verification::None`] |
//! | `require` | `require` | [`Verification::None`], **or [`Verification::ChainOnly`] when a CA bundle is configured** |
//! | `verify-ca` | `require` | [`Verification::ChainOnly`] |
//! | `verify-full` | `require` | [`Verification::Full`] |
//!
//! # Caveats, in the order they will bite you
//!
//! * **`allow` → `prefer` is an approximation.** libpq's `allow` attempts a
//!   *plaintext* connection first and only negotiates TLS if the server
//!   insists. `postgres` cannot express that ordering, so `allow` is mapped to
//!   `prefer`, which tries TLS first. Both end up "encrypted if the server
//!   supports it", which is the property operators pick `allow` for.
//!
//! * **`require` verifies the chain when — and only when — a CA bundle is
//!   configured.** That is libpq parity, and the parity is conditional:
//!   > For backwards compatibility with earlier versions of PostgreSQL, if a
//!   > root CA file exists, the behavior of `sslmode=require` will be the same
//!   > as that of `verify-ca`, meaning the server certificate is validated
//!   > against the CA.
//!
//!   ([PostgreSQL docs, 32.19.1](https://www.postgresql.org/docs/current/libpq-ssl.html);
//!   `sslrootcert`'s own entry in
//!   [32.1.2](https://www.postgresql.org/docs/current/libpq-connect.html) says
//!   the same unconditionally — "if the file exists, the server's certificate
//!   will be verified to be signed by one of these authorities".) So with an
//!   `sslrootcert` in the DSN, `require` resolves to
//!   [`Verification::ChainOnly`]; with no bundle it resolves to
//!   [`Verification::None`] — encryption without authentication, which is all
//!   libpq's `require` promises in that case. Do not "harden" the no-bundle
//!   case into `verify-full`: it would break every deployment pointed at a
//!   private-CA or self-signed server that correctly asked for `require`.
//!   Equally, do not drop the escalation — silently ignoring a configured
//!   bundle is a fail-open.
//!
//! * **rustls requires a `subjectAltName` and does not fall back to CN.** A
//!   certificate issued with only `/CN=host` will be rejected under
//!   `verify-full` no matter how the CA bundle is configured. Such a server
//!   needs `verify-ca`, or `require` (whose escalated
//!   [`Verification::ChainOnly`] tolerates the name mismatch), or `require`
//!   with no bundle at all.
//!
//! * **A configured CA bundle augments the public webpki roots, it never
//!   replaces them.** An unreadable bundle, or one containing no certificates,
//!   is a hard error rather than a silent fallback to public roots only.
//!
//! * **Parameters this module does not own are preserved byte-for-byte.** Only
//!   `sslmode`, `sslrootcert`, `sslcert`, `sslkey` and `currentSchema` are
//!   decoded; every other query parameter is carried through with its original
//!   percent-encoding, so a value like `options=-c%20statement_timeout%3D5000`
//!   reaches `postgres` intact. Keys are matched case-sensitively, matching
//!   `tokio-postgres`.
//!
//! * **Only the URL DSN form is supported.** `postgres::Config::from_str` also
//!   accepts libpq's keyword/value form
//!   (`host=db.example.com sslmode=verify-full`), dispatching on the
//!   `postgres://` / `postgresql://` prefix. This module's rewriter parses only
//!   the URL form, so a keyword/value DSN is a hard error rather than an
//!   unexamined passthrough that would misreport the verification tier.

pub mod dsn;
pub mod tls;
mod verifier;

use std::path::PathBuf;

use anyhow::Context;
use refinery_core::postgres::Config as PgConfig;

/// The six `sslmode` values libpq documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

/// How much of the server certificate the TLS connector checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Accept any certificate. Encryption without authentication.
    None,
    /// Verify the chain against the root store, but tolerate a hostname
    /// mismatch. Chain, expiry and revocation failures still reject.
    ChainOnly,
    /// Full webpki verification, including hostname.
    Full,
}

/// The outcome of [`dsn::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The rewritten DSN — safe to hand to `postgres::Config`.
    pub dsn: String,
    /// The mode requested in the original DSN. `None` means it was absent.
    pub requested: Option<SslMode>,
    /// The `sslmode` `postgres` will act on: `"disable"`, `"prefer"` or
    /// `"require"`. For an absent `sslmode` this reports `"prefer"`, which is
    /// `postgres::Config`'s default.
    pub effective: &'static str,
    /// The verification tier the connector must apply.
    ///
    /// This is the *post-escalation* tier: `sslmode=require` with a CA bundle
    /// configured reports [`Verification::ChainOnly`], matching libpq. See
    /// [`dsn::resolve`].
    pub verification: Verification,
    /// Extra trust anchors, from an `sslrootcert` lifted out of the DSN.
    pub ca_bundle_path: Option<PathBuf>,
    /// The `currentSchema` lifted out of the DSN, used as the fallback for
    /// refinery's migration-table schema. **Refinery-specific**: the sibling
    /// `pg-tls` crate has no equivalent field.
    pub current_schema: Option<String>,
}

/// The parsed driver config plus the resolved TLS decision, from a **raw** DSN.
///
/// This is the whole of the Postgres call site's pure logic, extracted so it
/// can be tested without a server: [`dsn::resolve`] rewrites the DSN, and the
/// **rewritten** DSN — never the raw one — is what `postgres::Config` parses.
/// Parsing the raw DSN instead is the exact bug BCP-4264 fixes (`verify-ca` and
/// friends are connection-string parse errors to the driver), so a test that
/// asserts on the returned `Config`'s `get_ssl_mode()` fails if the rewrite is
/// bypassed.
///
/// The caller is responsible for the impure remainder: applying any password
/// override, choosing `NoTls` for [`Resolved::effective`] `== "disable"`, and
/// building the connector with [`tls::client_config`] otherwise.
pub fn prepare(raw_dsn: &str) -> anyhow::Result<(PgConfig, Resolved)> {
    let resolved =
        dsn::resolve(raw_dsn).context("could not interpret the database connection string")?;
    let pg_config: PgConfig = resolved
        .dsn
        .parse()
        .context("could not parse the database connection string")?;
    Ok((pg_config, resolved))
}

impl SslMode {
    /// The canonical libpq spelling.
    ///
    /// Unused by the CLI today; kept so this module stays a line-for-line
    /// mirror of the sibling `pg-tls` crate (see the module header).
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Allow => "allow",
            SslMode::Prefer => "prefer",
            SslMode::Require => "require",
            SslMode::VerifyCa => "verify-ca",
            SslMode::VerifyFull => "verify-full",
        }
    }

    /// Parse a libpq `sslmode` value.
    pub fn parse(value: &str) -> anyhow::Result<SslMode> {
        match value {
            "disable" => Ok(SslMode::Disable),
            "allow" => Ok(SslMode::Allow),
            "prefer" => Ok(SslMode::Prefer),
            "require" => Ok(SslMode::Require),
            "verify-ca" => Ok(SslMode::VerifyCa),
            "verify-full" => Ok(SslMode::VerifyFull),
            other => Err(anyhow::anyhow!(
                "unknown sslmode value {:?}; expected one of disable, allow, prefer, \
                 require, verify-ca, verify-full",
                other
            )),
        }
    }

    /// The `sslmode` `postgres` is given in its place.
    pub fn effective(self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Allow | SslMode::Prefer => "prefer",
            SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull => "require",
        }
    }

    /// The verification tier this mode implies.
    pub fn verification(self) -> Verification {
        match self {
            SslMode::Disable | SslMode::Allow | SslMode::Prefer | SslMode::Require => {
                Verification::None
            }
            SslMode::VerifyCa => Verification::ChainOnly,
            SslMode::VerifyFull => Verification::Full,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use refinery_core::postgres::config::SslMode as PgSslMode;

    const BASE: &str = "postgresql://user:pw@db.example.com:5432/app";

    /// `prepare` is the Postgres call site's whole pure path, so this is the
    /// test that covers `migrate.rs`'s arm without a server.
    ///
    /// Every case starts from a **raw** libpq DSN, query string and all, and
    /// asserts on both halves of the returned pair. Red if `prepare` parsed
    /// `raw_dsn` instead of `resolved.dsn` — the driver rejects `allow`,
    /// `verify-ca` and `verify-full` as connection-string parse errors, so
    /// those three rows would not even reach an assertion.
    #[test]
    fn prepare_maps_every_mode_from_a_raw_dsn() {
        let cases: &[(&str, PgSslMode, &str, Verification)] = &[
            ("disable", PgSslMode::Disable, "disable", Verification::None),
            ("allow", PgSslMode::Prefer, "prefer", Verification::None),
            ("prefer", PgSslMode::Prefer, "prefer", Verification::None),
            ("require", PgSslMode::Require, "require", Verification::None),
            (
                "verify-ca",
                PgSslMode::Require,
                "require",
                Verification::ChainOnly,
            ),
            (
                "verify-full",
                PgSslMode::Require,
                "require",
                Verification::Full,
            ),
        ];

        for (mode, expected_ssl_mode, effective, verification) in cases {
            let raw = format!("{}?application_name=refinery&sslmode={}", BASE, mode);
            let (pg_config, resolved) = prepare(&raw)
                .unwrap_or_else(|err| panic!("sslmode={} must prepare: {}", mode, err));

            assert_eq!(
                pg_config.get_ssl_mode(),
                *expected_ssl_mode,
                "sslmode={} must reach postgres as {:?}",
                mode,
                expected_ssl_mode
            );
            assert_eq!(resolved.effective, *effective, "{}: effective", mode);
            assert_eq!(
                resolved.verification, *verification,
                "{}: verification tier",
                mode
            );
            assert_eq!(
                resolved.requested,
                Some(SslMode::parse(mode).unwrap()),
                "{}: requested mode round-trips",
                mode
            );
            // The retained parameter proves the driver really parsed the
            // rewritten query and not just the bare base.
            assert_eq!(
                pg_config.get_application_name(),
                Some("refinery"),
                "{}: retained params must reach the driver",
                mode
            );
        }
    }

    /// The absent case: `postgres`' own `prefer` default, no verification, and
    /// a DSN handed to the driver untouched.
    #[test]
    fn prepare_handles_an_absent_sslmode() {
        let (pg_config, resolved) = prepare(BASE).unwrap();

        assert_eq!(pg_config.get_ssl_mode(), PgSslMode::Prefer);
        assert_eq!(resolved.effective, "prefer");
        assert_eq!(resolved.verification, Verification::None);
        assert_eq!(resolved.requested, None);
        assert_eq!(resolved.dsn, BASE);
    }

    /// `prepare` surfaces the escalated tier, so the call site's
    /// `client_config` gets a verifying config for `require` + `sslrootcert`.
    ///
    /// Red if the escalation is removed from `dsn::resolve`.
    #[test]
    fn prepare_surfaces_the_require_escalation_and_the_lifted_keys() {
        let (pg_config, resolved) = prepare(&format!(
            "{}?sslmode=require&sslrootcert=/etc/ssl/ca.pem&currentSchema=llm_gw",
            BASE
        ))
        .unwrap();

        assert_eq!(pg_config.get_ssl_mode(), PgSslMode::Require);
        assert_eq!(resolved.effective, "require");
        assert_eq!(
            resolved.verification,
            Verification::ChainOnly,
            "require + sslrootcert must reach the connector as a verifying tier"
        );
        assert_eq!(
            resolved.ca_bundle_path.as_deref(),
            Some(std::path::Path::new("/etc/ssl/ca.pem"))
        );
        assert_eq!(resolved.current_schema.as_deref(), Some("llm_gw"));
    }

    /// `disable` is the one tier the call site routes to `NoTls`, so pin the
    /// discriminator it branches on. Red if the `== "disable"` check is
    /// inverted, because every other mode reports something else.
    #[test]
    fn prepare_reports_disable_only_for_disable() {
        assert_eq!(
            prepare(&format!("{}?sslmode=disable", BASE))
                .unwrap()
                .1
                .effective,
            "disable"
        );
        for mode in ["allow", "prefer", "require", "verify-ca", "verify-full"].iter() {
            let effective = prepare(&format!("{}?sslmode={}", BASE, mode))
                .unwrap()
                .1
                .effective;
            assert_ne!(
                effective, "disable",
                "sslmode={} must not be routed to NoTls",
                mode
            );
        }
        assert_ne!(prepare(BASE).unwrap().1.effective, "disable");
    }

    /// A DSN `dsn::resolve` rejects must not reach the driver, and the error
    /// must not carry the DSN (it can hold a password).
    #[test]
    fn prepare_propagates_resolve_errors_without_leaking_the_dsn() {
        const SECRET_DSN: &str = "postgresql://user:sup3rsecret@db.example.com/app?sslmode=banana";

        let err = prepare(SECRET_DSN).expect_err("an unknown sslmode must not prepare");
        let rendered = format!("{:?}", err);
        assert!(
            !rendered.contains("sup3rsecret"),
            "the error chain must not carry the DSN's password: {}",
            rendered
        );
    }
}
