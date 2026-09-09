//! Postgres TLS support for the refinery CLI.
//!
//! # Provenance -- keep this in sync
//!
//! This module is a **copy** of `bdai-platform/libs/pg-tls/src/lib.rs` (and the
//! sibling `dsn.rs`, `tls.rs`, `verifier.rs` files, each of which names its
//! counterpart in its own header). It is a copy rather than a dependency
//! because refinery lives in a separate repository and this fork is rebased on
//! upstream refinery; it cannot take a path or git dependency on the platform
//! workspace. **The two must stay behaviorally identical** -- if you change the
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
//! sibling needs the same fix -- see `dsn.rs`'s header.
//!
//! # Why this exists
//!
//! `postgres`/`tokio-postgres` understands only three `sslmode` values --
//! `disable`, `prefer` and `require` -- and rejects every other libpq value as
//! a **connection-string parse error**. It also rejects `sslrootcert`,
//! `sslcert` and `sslkey` outright as unknown options. Operators and Helm
//! charts, however, write libpq DSNs. [`dsn::resolve`] rewrites the DSN into
//! something `postgres::Config` accepts while remembering the verification
//! tier the operator actually asked for, and [`tls::client_config`] builds a
//! rustls connector configured for that tier.
//!
//! # Mode mapping
//!
//! Every row but `disable` is **conditional on the trust anchors**, because
//! that is how libpq behaves: `sslrootcert` sets `have_rootcert`, and
//! `if (have_rootcert) SSL_set_verify(conn->ssl, SSL_VERIFY_PEER, verify_cb);`
//! is not scoped by `sslmode`. "Anchored" below means
//! [`TrustAnchors::is_configured`] -- an `sslrootcert` naming a bundle file, or
//! the reserved `sslrootcert=system`.
//!
//! | DSN `sslmode` | rewritten to | no anchors | anchored |
//! |---|---|---|---|
//! | absent | *(DSN left untouched)* | [`Verification::None`] | [`Verification::ChainOnly`] (or [`Verification::Full`] for `system`, which promotes the mode -- see below) |
//! | `disable` | `disable` | [`Verification::None`] | [`Verification::None`] -- no SSL at all, so the anchors go unused |
//! | `allow` | `prefer` | [`Verification::None`] | [`Verification::ChainOnly`] |
//! | `prefer` | `prefer` | [`Verification::None`] | [`Verification::ChainOnly`] |
//! | `require` | `require` | [`Verification::None`] | [`Verification::ChainOnly`] |
//! | `verify-ca` | `require` | **hard error** | [`Verification::ChainOnly`] |
//! | `verify-full` | `require` | **hard error** | [`Verification::Full`] |
//!
//! `sslrootcert=system` additionally *requires* `verify-full` (absent
//! `sslmode` is promoted to it; anything weaker is a hard error), per
//! PostgreSQL's documented rule -- see [`dsn::resolve`].
//!
//! # Caveats, in the order they will bite you
//!
//! * **`allow` -> `prefer` is an approximation.** libpq's `allow` attempts a
//!   *plaintext* connection first and only negotiates TLS if the server
//!   insists. `postgres` cannot express that ordering, so `allow` is mapped to
//!   `prefer`, which tries TLS first. Both end up "encrypted if the server
//!   supports it", which is the property operators pick `allow` for.
//!
//! * **Every non-`disable` mode verifies the chain when -- and only when --
//!   trust anchors are configured.** That is libpq parity, and the parity is
//!   conditional on the anchors, not on the mode:
//!   > For backwards compatibility with earlier versions of PostgreSQL, if a
//!   > root CA file exists, the behavior of `sslmode=require` will be the same
//!   > as that of `verify-ca`, meaning the server certificate is validated
//!   > against the CA.
//!
//!   ([PostgreSQL docs, 32.19.1](https://www.postgresql.org/docs/current/libpq-ssl.html);
//!   `sslrootcert`'s own entry in
//!   [32.1.2](https://www.postgresql.org/docs/current/libpq-connect.html) says
//!   the same unconditionally -- "if the file exists, the server's certificate
//!   will be verified to be signed by one of these authorities".) libpq
//!   implements this with a `have_rootcert` flag set purely on the root file
//!   being present and then `if (have_rootcert) SSL_set_verify(conn->ssl,
//!   SSL_VERIFY_PEER, verify_cb);` -- no `sslmode` in the condition. So the
//!   escalation here applies to `require`, `prefer`, `allow` **and** an absent
//!   `sslmode` alike; `disable` is the sole exception, because libpq does no
//!   SSL at all there and never loads the root file. With no anchors, those
//!   modes resolve to [`Verification::None`] -- encryption without
//!   authentication, which is all libpq's `require` promises in that case. Do
//!   not "harden" the no-anchor case into `verify-full`: it would break every
//!   deployment pointed at a private-CA or self-signed server that correctly
//!   asked for `require`. Equally, do not narrow the escalation back to
//!   `require` alone, and do not drop it -- silently ignoring configured
//!   anchors is a fail-open.
//!
//! * **rustls requires a `subjectAltName` and does not fall back to CN.** A
//!   certificate issued with only `/CN=host` will be rejected under
//!   `verify-full` no matter how the CA bundle is configured. Such a server
//!   needs `verify-ca`, or `require` (whose escalated
//!   [`Verification::ChainOnly`] tolerates the name mismatch), or `require`
//!   with no anchors at all.
//!
//! * **A configured CA bundle *is* the trust store; it never adds to the
//!   public webpki roots.** libpq's `sslrootcert` names the whole trust store
//!   (`SSL_CTX_load_verify_locations(ctx, sslrootcert, NULL)`), so
//!   [`TrustAnchors::Bundle`] means "exactly these certificates and nothing
//!   else". The public web PKI is reachable only through the explicit,
//!   reserved opt-in `sslrootcert=system` ([`TrustAnchors::System`]). Adding
//!   the bundle to the public roots instead would mean a certificate issued by
//!   any public CA for any hostname satisfies `verify-ca` and the escalated
//!   `require` -- which, because those tiers do not check the name, is a full
//!   MITM. An unreadable bundle, or one containing no certificates, is a hard
//!   error rather than a silent fallback to the public roots.
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

/// Where the connector's trust anchors come from -- libpq's `sslrootcert`.
///
/// libpq's `sslrootcert` names *the* trust store, it does not add to a default
/// one: `SSL_CTX_load_verify_locations(ctx, sslrootcert, NULL)`. The public web
/// PKI is a separate, explicit opt-in reached only by the reserved value
/// `sslrootcert=system`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAnchors {
    /// No trust anchors. Only valid for the tiers that do not verify.
    None,
    /// The public webpki roots -- libpq's `sslrootcert=system`.
    System,
    /// Exactly the certificates in this file, and nothing else.
    Bundle(PathBuf),
}

impl TrustAnchors {
    /// Whether an anchor source was configured at all.
    ///
    /// This is the libpq `have_rootcert` flag: it gates the chain-verification
    /// escalation for every non-`disable` mode. See [`dsn::resolve`].
    pub fn is_configured(&self) -> bool {
        !matches!(self, TrustAnchors::None)
    }
}

/// The outcome of [`dsn::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The rewritten DSN -- safe to hand to `postgres::Config`.
    pub dsn: String,
    /// The mode requested in the original DSN. `None` means it was absent.
    ///
    /// `sslrootcert=system` with no `sslmode` reports
    /// `Some(SslMode::VerifyFull)`, because PostgreSQL documents `system` as
    /// changing the default mode to `verify-full`.
    pub requested: Option<SslMode>,
    /// The `sslmode` `postgres` will act on: `"disable"`, `"prefer"` or
    /// `"require"`. For an absent `sslmode` this reports `"prefer"`, which is
    /// `postgres::Config`'s default.
    pub effective: &'static str,
    /// The verification tier the connector must apply.
    ///
    /// This is the *post-escalation* tier: any non-`disable` mode with trust
    /// anchors configured reports at least [`Verification::ChainOnly`],
    /// matching libpq's mode-independent `have_rootcert` gate. See
    /// [`dsn::resolve`].
    pub verification: Verification,
    /// The connector's trust store, from an `sslrootcert` lifted out of the
    /// DSN. [`TrustAnchors::Bundle`] *replaces* the public roots rather than
    /// adding to them; [`TrustAnchors::System`] is the explicit opt-in to the
    /// public web PKI.
    pub trust_anchors: TrustAnchors,
    /// The `currentSchema` lifted out of the DSN, used as the fallback for
    /// refinery's migration-table schema. **Refinery-specific**: the sibling
    /// `pg-tls` crate has no equivalent field.
    pub current_schema: Option<String>,
}

/// The parsed driver config plus the resolved TLS decision, from a **raw** DSN.
///
/// This is the whole of the Postgres call site's pure logic, extracted so it
/// can be tested without a server: [`dsn::resolve`] rewrites the DSN, and the
/// **rewritten** DSN -- never the raw one -- is what `postgres::Config` parses.
/// Parsing the raw DSN instead is the exact bug this module exists to fix
/// (`verify-ca` and friends are connection-string parse errors to the driver),
/// so a test that asserts on the returned `Config`'s `get_ssl_mode()` fails if
/// the rewrite is bypassed.
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
    /// Used by [`dsn::resolve`]'s error messages, which name the requested mode
    /// but never the DSN.
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

    /// The verification tier this mode implies **on its own**.
    ///
    /// This is the mode-only base tier, not the whole story: [`dsn::resolve`]
    /// owns the anchor-conditional escalation (any non-`disable` mode with
    /// [`TrustAnchors::is_configured`] rises to at least
    /// [`Verification::ChainOnly`]) and the rule that `verify-ca` /
    /// `verify-full` with no anchor source is a hard error. Read
    /// [`Resolved::verification`], never this function, for what the connector
    /// will actually do.
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
    /// `raw_dsn` instead of `resolved.dsn` -- the driver rejects `allow`,
    /// `verify-ca` and `verify-full` as connection-string parse errors, so
    /// those three rows would not even reach an assertion.
    ///
    /// The `verify-*` rows carry an `sslrootcert`: those two modes now require
    /// a trust anchor, so without one they are a hard error before the driver
    /// is ever reached.
    #[test]
    fn prepare_maps_every_mode_from_a_raw_dsn() {
        // `extra` is appended to the query verbatim.
        let cases: &[(&str, &str, PgSslMode, &str, Verification)] = &[
            (
                "disable",
                "",
                PgSslMode::Disable,
                "disable",
                Verification::None,
            ),
            ("allow", "", PgSslMode::Prefer, "prefer", Verification::None),
            (
                "prefer",
                "",
                PgSslMode::Prefer,
                "prefer",
                Verification::None,
            ),
            (
                "require",
                "",
                PgSslMode::Require,
                "require",
                Verification::None,
            ),
            (
                "verify-ca",
                "&sslrootcert=/etc/ssl/ca.pem",
                PgSslMode::Require,
                "require",
                Verification::ChainOnly,
            ),
            (
                "verify-full",
                "&sslrootcert=/etc/ssl/ca.pem",
                PgSslMode::Require,
                "require",
                Verification::Full,
            ),
        ];

        for (mode, extra, expected_ssl_mode, effective, verification) in cases {
            let raw = format!(
                "{}?application_name=refinery&sslmode={}{}",
                BASE, mode, extra
            );
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
            resolved.trust_anchors,
            TrustAnchors::Bundle(PathBuf::from("/etc/ssl/ca.pem"))
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
        // The `verify-*` rows need a trust anchor to resolve at all.
        for (mode, extra) in [
            ("allow", ""),
            ("prefer", ""),
            ("require", ""),
            ("verify-ca", "&sslrootcert=/etc/ssl/ca.pem"),
            ("verify-full", "&sslrootcert=/etc/ssl/ca.pem"),
        ]
        .iter()
        {
            let effective = prepare(&format!("{}?sslmode={}{}", BASE, mode, extra))
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
