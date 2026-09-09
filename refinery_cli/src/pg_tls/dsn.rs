//! libpq → `postgres` DSN rewriting.
//!
//! Copy of `bdai-platform/libs/pg-tls/src/dsn.rs`; the two must stay
//! behaviourally identical. See `super`'s header for why this is a copy and for
//! the list of intentional divergences (here: `currentSchema` is additionally
//! consumed, and errors are `anyhow`).
//!
//! The base of the URL (scheme, credentials, authority, path) is copied
//! verbatim, because round-tripping the whole URL through `url::Url` would
//! renormalise the authority — which matters for the comma-separated
//! multi-host and percent-encoded unix-socket forms `postgres` accepts.
//!
//! The query string is handled the same way, one level down: it is split on
//! `&` and each `k=v` segment is carried through as a **raw, still-encoded
//! string slice**. Only the keys this module consumes are decoded. Decoding and
//! re-encoding every parameter would corrupt the ones we have no business
//! touching: `form_urlencoded::Serializer` emits a space as `+`, while
//! `tokio-postgres` percent-decodes query values and would read that `+`
//! literally — turning `options=-c%20statement_timeout%3D5000` into the
//! nonsense `-c+statement_timeout=5000`. A DSN whose query needs no
//! modification therefore comes back byte-identical.
//!
//! The same asymmetry is why the values we *do* consume are decoded with plain
//! [`percent_encoding::percent_decode_str`] rather than
//! `url::form_urlencoded::parse`: `form_urlencoded` implements the HTML form
//! encoding, in which `+` means a space, while `tokio-postgres` decodes query
//! values with `percent_encoding::percent_decode` and leaves a `+` literal. So
//! `?sslrootcert=/etc/ssl/my+ca.pem` must open `my+ca.pem`, not `my ca.pem`.
//!
//! **Divergence caveat:** the sibling `bdai-platform/libs/pg-tls/src/dsn.rs`
//! still uses `form_urlencoded::parse` here and therefore still has that `+`
//! defect. It needs the same fix; do not "resync" this file back to it.

use std::path::PathBuf;

use anyhow::anyhow;

use crate::pg_tls::{Resolved, SslMode, Verification};

/// The parameters this module consumes out of the query string.
///
/// Matched **case-sensitively**, deliberately: `tokio-postgres` dispatches on
/// a bare `match key { "sslmode" => ..., key => Err(UnknownOption) }`, so
/// `SSLMODE=require` is an unknown option there and treating it as an `sslmode`
/// here would silently invent a behaviour the database driver does not have.
const SSL_MODE: &str = "sslmode";
const SSL_ROOT_CERT: &str = "sslrootcert";
const SSL_CERT: &str = "sslcert";
const SSL_KEY: &str = "sslkey";
/// Refinery-specific; the sibling `pg-tls` crate does not consume this.
const CURRENT_SCHEMA: &str = "currentSchema";

/// The two prefixes that make `postgres::Config::from_str` take its URL branch,
/// copied from `tokio-postgres`' `UrlParser::remove_url_prefix`. Anything else
/// is libpq's keyword/value form, which this rewriter does not parse.
const URL_PREFIXES: [&str; 2] = ["postgres://", "postgresql://"];

/// Rewrite `dsn` so `postgres` can parse it, reporting what the operator asked
/// for.
///
/// * `sslmode` is consumed and replaced with the mapped value.
/// * `sslrootcert` is consumed and lifted into [`Resolved::ca_bundle_path`]
///   (`postgres` rejects it as an unknown option). It escalates
///   `sslmode=require` to [`Verification::ChainOnly`] — see below.
/// * `currentSchema` is consumed and lifted into [`Resolved::current_schema`]
///   (same reason), where the CLI uses it as the migration-table schema
///   fallback.
/// * `sslcert` / `sslkey` are a hard error: client-certificate auth is not
///   implemented, and dropping them would fail open on the operator's intent —
///   silently, as an authentication failure that reads like a bad password.
/// * every other parameter is preserved **byte-for-byte**, in order, with its
///   original percent-encoding intact.
///
/// When nothing is consumed the DSN is returned untouched — no `?` is
/// appended — and the tier is [`Verification::None`], matching
/// `postgres::Config`'s `Prefer` default.
///
/// # CA-bundle escalation of `require`
///
/// `sslmode=require` *with* an `sslrootcert` resolves to
/// [`Verification::ChainOnly`], not [`Verification::None`]. That is libpq's
/// documented behaviour: "if a root CA file exists, the behavior of
/// `sslmode=require` will be the same as that of `verify-ca`, meaning the
/// server certificate is validated against the CA"
/// ([PostgreSQL docs, 32.19.1 Client Verification of Server
/// Certificates](https://www.postgresql.org/docs/current/libpq-ssl.html)), and
/// `sslrootcert`'s own entry says "if the file exists, the server's certificate
/// will be verified to be signed by one of these authorities" without
/// qualifying it by `sslmode`. Without the escalation a configured bundle would
/// be silently discarded and the connection would be encrypted but
/// unauthenticated — a fail-open. `require` with **no** bundle stays at
/// [`Verification::None`].
///
/// # Only the URL DSN form is supported
///
/// `postgres::Config::from_str` accepts two forms and dispatches on the
/// `postgres://` / `postgresql://` prefix: `UrlParser::parse` for the URL form,
/// falling back to `Parser::parse` for libpq's keyword/value form. This
/// rewriter only understands the URL form, so a keyword/value DSN is rejected
/// rather than passed through unexamined — which would leak
/// `sslmode=verify-ca` straight to the driver as a parse failure and misreport
/// the verification tier for `sslmode=require`.
pub fn resolve(dsn: &str) -> anyhow::Result<Resolved> {
    if !URL_PREFIXES.iter().any(|prefix| dsn.starts_with(prefix)) {
        // Deliberately does NOT quote the DSN: it can carry a password, and
        // this error is printed to stderr by the CLI's `Termination` impl.
        return Err(anyhow!(
            "the database connection string must use the URL form \
             (postgres://... or postgresql://...); libpq's keyword/value form \
             (\"host=... sslmode=...\") is not supported"
        ));
    }

    let (base, query) = match dsn.find('?') {
        // Split on the FIRST `?` only; anything after it is query, `?` included.
        Some(idx) => (&dsn[..idx], Some(&dsn[idx + 1..])),
        None => (dsn, None),
    };

    let mut requested: Option<SslMode> = None;
    let mut dsn_root_cert: Option<PathBuf> = None;
    let mut current_schema: Option<String> = None;
    // Raw, still-encoded `k=v` segments, kept exactly as the operator wrote
    // them.
    let mut retained: Vec<&str> = Vec::new();

    for segment in query.unwrap_or("").split('&').filter(|s| !s.is_empty()) {
        let key = match segment.find('=') {
            Some(idx) => &segment[..idx],
            None => segment,
        };
        match key {
            SSL_MODE => requested = Some(SslMode::parse(&decode_value(segment))?),
            SSL_ROOT_CERT => dsn_root_cert = Some(PathBuf::from(decode_value(segment))),
            CURRENT_SCHEMA => current_schema = Some(decode_value(segment)),
            SSL_CERT | SSL_KEY => {
                return Err(anyhow!(
                    "client-certificate authentication is not supported; remove {:?} \
                     from the database connection string",
                    key
                ))
            }
            _ => retained.push(segment),
        }
    }

    let effective = requested.map_or("prefer", SslMode::effective);
    let ca_bundle_path = dsn_root_cert;

    // The escalation lives here rather than in `SslMode::verification`, which
    // sees only the mode and has no way to know a bundle was configured.
    let verification = match requested {
        Some(SslMode::Require) if ca_bundle_path.is_some() => Verification::ChainOnly,
        Some(mode) => mode.verification(),
        None => Verification::None,
    };

    let rewritten = if requested.is_none() && ca_bundle_path.is_none() && current_schema.is_none() {
        // Nothing was consumed, so nothing needs rebuilding: hand back the
        // input byte-for-byte. Notably this leaves a query-less DSN without
        // a trailing `?`.
        dsn.to_string()
    } else {
        let mut rebuilt = retained.join("&");
        if requested.is_some() {
            if !rebuilt.is_empty() {
                rebuilt.push('&');
            }
            // Every value `SslMode::effective` can return is lowercase
            // ASCII, so it needs no escaping.
            rebuilt.push_str(SSL_MODE);
            rebuilt.push('=');
            rebuilt.push_str(effective);
        }
        if rebuilt.is_empty() {
            base.to_string()
        } else {
            format!("{}?{}", base, rebuilt)
        }
    };

    Ok(Resolved {
        dsn: rewritten,
        requested,
        effective,
        verification,
        ca_bundle_path,
        current_schema,
    })
}

/// Decode the value half of a single raw `k=v` segment.
///
/// Applied only to the keys this module consumes and strips, never to a
/// parameter that is passed through to `postgres`.
///
/// Plain percent-decoding, matching the driver: `tokio-postgres` decodes query
/// values with `percent_encoding::percent_decode`, so a `+` is a literal `+`
/// and not a space. See the module header.
fn decode_value(segment: &str) -> String {
    let raw = match segment.find('=') {
        Some(idx) => &segment[idx + 1..],
        None => "",
    };
    percent_encoding::percent_decode_str(raw)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use refinery_core::postgres::config::SslMode as PgSslMode;
    use refinery_core::postgres::Config as PgConfig;

    const BASE: &str = "postgresql://user:pw@db.example.com:5432/app";

    const ALL_MODES: [&str; 6] = [
        "disable",
        "allow",
        "prefer",
        "require",
        "verify-ca",
        "verify-full",
    ];

    fn resolve_mode(mode: &str) -> Resolved {
        resolve(&format!("{}?sslmode={}", BASE, mode)).expect("resolve should succeed")
    }

    /// Every documented mode, plus absent, maps to the documented effective
    /// `sslmode` and verification tier.
    ///
    /// These are the **no-CA-bundle** rows — `resolve_mode` passes no
    /// `sslrootcert`. `require`'s bundle-conditional escalation is covered by
    /// `require_with_a_configured_bundle_escalates_to_chain_only` and friends
    /// below.
    #[test]
    fn mode_mapping_table() {
        let cases: &[(&str, &str, Verification)] = &[
            ("disable", "disable", Verification::None),
            ("allow", "prefer", Verification::None),
            ("prefer", "prefer", Verification::None),
            ("require", "require", Verification::None),
            ("verify-ca", "require", Verification::ChainOnly),
            ("verify-full", "require", Verification::Full),
        ];

        for (requested, effective, verification) in cases {
            let resolved = resolve_mode(requested);
            assert_eq!(
                resolved.requested,
                Some(SslMode::parse(requested).unwrap()),
                "{}: requested mode round-trips",
                requested
            );
            assert_eq!(resolved.effective, *effective, "{}: effective", requested);
            assert_eq!(
                resolved.dsn,
                format!("{}?sslmode={}", BASE, effective),
                "{}: rewritten sslmode in the DSN",
                requested
            );
            assert_eq!(
                resolved.verification, *verification,
                "{}: verification tier",
                requested
            );
        }

        let absent = resolve(BASE).unwrap();
        assert_eq!(absent.requested, None);
        assert_eq!(absent.effective, "prefer");
        assert_eq!(absent.verification, Verification::None);
        assert_eq!(absent.dsn, BASE, "absent sslmode leaves the DSN untouched");
        assert!(
            !absent.dsn.contains('?'),
            "absent sslmode must not append a query string"
        );
    }

    /// The load-bearing pair: the modes we rewrite are the modes `postgres`
    /// *cannot* parse today, and the rewrite makes them parseable. Without
    /// this, a no-op rewrite would still satisfy the mapping test above.
    #[test]
    fn rewrite_is_load_bearing() {
        for mode in ["allow", "verify-ca", "verify-full"].iter() {
            let original = format!("{}?sslmode={}", BASE, mode);
            assert!(
                original.parse::<PgConfig>().is_err(),
                "postgres is expected to reject sslmode={} before rewriting",
                mode
            );
        }

        for mode in ALL_MODES.iter() {
            let resolved = resolve_mode(mode);
            resolved.dsn.parse::<PgConfig>().unwrap_or_else(|err| {
                panic!("rewritten DSN for sslmode={} must parse: {}", mode, err)
            });
        }

        // And the untouched, sslmode-less DSN still parses.
        resolve(BASE)
            .unwrap()
            .dsn
            .parse::<PgConfig>()
            .expect("DSN without sslmode must parse");
    }

    /// The ticket's acceptance criterion: assert on the `SslMode` the parsed
    /// `postgres::Config` actually carries, not on a connection.
    #[test]
    fn parsed_config_carries_expected_ssl_mode() {
        let cases: &[(&str, PgSslMode)] = &[
            ("disable", PgSslMode::Disable),
            ("allow", PgSslMode::Prefer),
            ("prefer", PgSslMode::Prefer),
            ("require", PgSslMode::Require),
            ("verify-ca", PgSslMode::Require),
            ("verify-full", PgSslMode::Require),
        ];

        for (mode, expected) in cases {
            let cfg = resolve_mode(mode)
                .dsn
                .parse::<PgConfig>()
                .unwrap_or_else(|err| panic!("sslmode={} must parse: {}", mode, err));
            assert_eq!(
                cfg.get_ssl_mode(),
                *expected,
                "sslmode={} must reach postgres as {:?}",
                mode,
                expected
            );
        }

        // Absent `sslmode` is libpq's (and postgres') `prefer` default.
        let cfg = resolve(BASE).unwrap().dsn.parse::<PgConfig>().unwrap();
        assert_eq!(cfg.get_ssl_mode(), PgSslMode::Prefer);
    }

    /// Parameters we do not own survive byte-for-byte, in their original order.
    ///
    /// Rebuilding the query through `form_urlencoded::Serializer` re-encodes a
    /// space as `+`, which `tokio-postgres` percent-decodes back to a literal
    /// `+` — so `options=-c%20statement_timeout%3D5000` would reach the server
    /// as `-c+statement_timeout=5000`.
    #[test]
    fn unrelated_params_round_trip_byte_for_byte() {
        const OPTIONS: &str = "options=-c%20statement_timeout%3D5000";

        let resolved = resolve(&format!(
            "{}?{}&application_name=refinery&connect_timeout=5&sslmode=verify-full",
            BASE, OPTIONS
        ))
        .unwrap();

        assert_eq!(
            resolved.dsn,
            format!(
                "{}?{}&application_name=refinery&connect_timeout=5&sslmode=require",
                BASE, OPTIONS
            ),
            "every retained parameter must keep its bytes and its position"
        );

        // And round-trip it through postgres' own decoder, not just a string
        // match.
        let cfg = resolved
            .dsn
            .parse::<PgConfig>()
            .expect("rewritten DSN with extra params must parse");
        assert_eq!(
            cfg.get_options(),
            Some("-c statement_timeout=5000"),
            "postgres must decode the preserved options value back to a space"
        );
        assert_eq!(cfg.get_application_name(), Some("refinery"));
        assert_eq!(
            cfg.get_connect_timeout(),
            Some(&std::time::Duration::from_secs(5))
        );
    }

    /// A segment with no `=` at all is passed through verbatim.
    ///
    /// Only the rewrite is asserted here, not parseability: `tokio-postgres`
    /// rejects a value-less URL parameter itself (it scans for the next `=`
    /// across the `&`), so the correct behaviour is to hand its own error
    /// back to the operator rather than to reshape or silently drop the
    /// segment.
    #[test]
    fn valueless_param_is_preserved_verbatim() {
        let resolved = resolve(&format!(
            "{}?application_name=refinery&keepalives&sslmode=verify-ca",
            BASE
        ))
        .unwrap();

        assert_eq!(
            resolved.dsn,
            format!(
                "{}?application_name=refinery&keepalives&sslmode=require",
                BASE
            )
        );
        assert_eq!(resolved.verification, Verification::ChainOnly);
    }

    /// A DSN with no query string comes back identical to the input.
    #[test]
    fn query_less_dsn_is_identical() {
        let resolved = resolve(BASE).unwrap();
        assert_eq!(resolved.dsn, BASE);
        assert_eq!(resolved.requested, None);
        assert_eq!(resolved.ca_bundle_path, None);
        assert_eq!(resolved.current_schema, None);
    }

    /// And a query we change nothing in is likewise untouched.
    #[test]
    fn untouched_query_is_byte_identical() {
        let dsn = format!(
            "{}?options=-c%20statement_timeout%3D5000&application_name=refinery&connect_timeout=5",
            BASE
        );

        let resolved = resolve(&dsn).unwrap();

        assert_eq!(resolved.dsn, dsn, "an unmodified query must not be rebuilt");
        assert_eq!(resolved.requested, None);
        dsn.parse::<PgConfig>()
            .expect("the untouched DSN must parse");
    }

    /// An uppercase key is NOT ours to consume: `tokio-postgres` matches keys
    /// case-sensitively, so `SSLMODE` is an unknown option there too.
    #[test]
    fn keys_are_matched_case_sensitively() {
        let resolved = resolve(&format!("{}?SSLMODE=verify-full&CurrentSchema=x", BASE)).unwrap();

        assert_eq!(resolved.requested, None, "SSLMODE is not sslmode");
        assert_eq!(
            resolved.current_schema, None,
            "CurrentSchema is not currentSchema"
        );
        assert_eq!(
            resolved.dsn,
            format!("{}?SSLMODE=verify-full&CurrentSchema=x", BASE),
            "an uppercase key must be passed through untouched"
        );
    }

    #[test]
    fn current_schema_is_consumed_and_surfaced() {
        let resolved = resolve(&format!("{}?currentSchema=llm_gw&sslmode=require", BASE)).unwrap();

        assert_eq!(resolved.current_schema.as_deref(), Some("llm_gw"));
        assert!(
            !resolved.dsn.contains("currentSchema"),
            "currentSchema must be stripped (postgres rejects it): {}",
            resolved.dsn
        );
        assert_eq!(resolved.dsn, format!("{}?sslmode=require", BASE));
        resolved
            .dsn
            .parse::<PgConfig>()
            .expect("DSN with currentSchema stripped must parse");
    }

    /// `currentSchema` alone still has to be stripped, and must not leave a
    /// dangling `?`.
    #[test]
    fn current_schema_alone_is_stripped() {
        let resolved = resolve(&format!("{}?currentSchema=llm_gw", BASE)).unwrap();

        assert_eq!(resolved.current_schema.as_deref(), Some("llm_gw"));
        assert_eq!(resolved.dsn, BASE);
        resolved
            .dsn
            .parse::<PgConfig>()
            .expect("DSN with currentSchema stripped must parse");
    }

    #[test]
    fn sslrootcert_is_lifted_and_stripped() {
        for mode in ["verify-ca", "require"].iter() {
            let resolved = resolve(&format!(
                "{}?sslmode={}&sslrootcert=/etc/ssl/ca.pem",
                BASE, mode
            ))
            .unwrap();

            assert_eq!(
                resolved.ca_bundle_path.as_deref(),
                Some(std::path::Path::new("/etc/ssl/ca.pem")),
                "sslmode={}: the bundle must be lifted",
                mode
            );
            assert!(
                !resolved.dsn.contains("sslrootcert"),
                "sslmode={}: sslrootcert must be stripped (postgres rejects it): {}",
                mode,
                resolved.dsn
            );
            assert_eq!(resolved.dsn, format!("{}?sslmode=require", BASE));
            resolved
                .dsn
                .parse::<PgConfig>()
                .expect("DSN with sslrootcert stripped must parse");
            // Both modes end at a verifying tier — `require` by escalation.
            assert_eq!(
                resolved.verification,
                Verification::ChainOnly,
                "sslmode={}: a lifted bundle must be verified against",
                mode
            );
        }
    }

    #[test]
    fn sslrootcert_is_lifted_even_without_sslmode() {
        let resolved = resolve(&format!("{}?sslrootcert=/etc/ssl/ca.pem", BASE)).unwrap();

        assert_eq!(
            resolved.ca_bundle_path.as_deref(),
            Some(std::path::Path::new("/etc/ssl/ca.pem"))
        );
        assert_eq!(resolved.dsn, BASE);
    }

    #[test]
    fn client_certificate_params_are_rejected() {
        for key in ["sslcert", "sslkey"].iter() {
            let err = resolve(&format!(
                "{}?sslmode=verify-full&{}=/etc/ssl/client.pem",
                BASE, key
            ))
            .expect_err("client-certificate params must be rejected, not dropped");
            let msg = err.to_string();
            assert!(
                msg.contains("client-certificate authentication is not supported")
                    && msg.contains(key),
                "unexpected error for {}: {}",
                key,
                msg
            );
        }
    }

    #[test]
    fn unknown_sslmode_is_rejected() {
        let err =
            resolve(&format!("{}?sslmode=banana", BASE)).expect_err("unknown sslmode must error");
        let msg = err.to_string();
        assert!(
            msg.contains("banana"),
            "error should quote the value: {}",
            msg
        );
        for mode in ALL_MODES.iter() {
            assert!(msg.contains(mode), "error should list {}: {}", mode, msg);
        }
    }

    // ---------------------------------------------------------------------
    // `require` + CA bundle → ChainOnly (libpq's bundle-conditional parity)
    // ---------------------------------------------------------------------

    /// `sslmode=require` with a bundle escalates to `ChainOnly`, and `require`
    /// with **no** bundle does not.
    ///
    /// Both halves are load-bearing. Removing the escalation makes the first
    /// assertion fail (it would report `None`); widening the escalation to
    /// unconditional makes the second fail.
    ///
    /// The fork has no non-DSN `TlsSettings::ca_bundle_path`, so unlike the
    /// sibling's version of this test the "configured" bundle here is the
    /// DSN's own `sslrootcert` — it is the only source there is.
    #[test]
    fn require_with_a_configured_bundle_escalates_to_chain_only() {
        let with_bundle = resolve(&format!(
            "{}?sslmode=require&sslrootcert=/config/ca.pem",
            BASE
        ))
        .unwrap();

        assert_eq!(
            with_bundle.requested,
            Some(SslMode::Require),
            "the escalation must not rewrite what the operator asked for"
        );
        assert_eq!(
            with_bundle.effective, "require",
            "the wire-level sslmode is unchanged; only the verifier escalates"
        );
        assert_eq!(
            with_bundle.verification,
            Verification::ChainOnly,
            "a configured CA bundle must not be silently discarded at sslmode=require"
        );
        assert_eq!(
            with_bundle.dsn,
            format!("{}?sslmode=require", BASE),
            "the rewritten DSN is unaffected by the escalation"
        );

        let without_bundle = resolve(&format!("{}?sslmode=require", BASE))
            .expect("require with no bundle must still resolve");
        assert_eq!(
            without_bundle.verification,
            Verification::None,
            "require with no bundle stays unverified — libpq promises no more than encryption there"
        );
    }

    /// The same escalation stated from the DSN's own `sslrootcert`, which is an
    /// operator's obvious first move and used to be lifted and then ignored.
    #[test]
    fn require_with_sslrootcert_in_the_dsn_escalates_to_chain_only() {
        let resolved = resolve(&format!(
            "{}?sslmode=require&sslrootcert=/etc/ssl/ca.pem",
            BASE
        ))
        .unwrap();

        assert_eq!(resolved.verification, Verification::ChainOnly);
        assert_eq!(
            resolved.ca_bundle_path.as_deref(),
            Some(std::path::Path::new("/etc/ssl/ca.pem"))
        );
        assert!(
            !resolved.dsn.contains("sslrootcert"),
            "sslrootcert must still be stripped: {}",
            resolved.dsn
        );
        resolved
            .dsn
            .parse::<PgConfig>()
            .expect("the rewritten DSN must parse");
    }

    /// Precedence is unchanged by the escalation.
    ///
    /// The sibling's version of this test asserts that an explicitly configured
    /// `TlsSettings::ca_bundle_path` still wins over the DSN's `sslrootcert`
    /// and that the escalation fires on the winner. The fork has no such
    /// settings struct — `sslrootcert` is the only bundle source — so only the
    /// DSN-driven half applies: the escalation must be computed from the
    /// **merged** `Resolved::ca_bundle_path` that the connector actually reads,
    /// not from some earlier value.
    #[test]
    fn explicit_settings_still_win_over_sslrootcert_at_require() {
        let resolved = resolve(&format!(
            "{}?sslmode=require&sslrootcert=/etc/ssl/dsn.pem",
            BASE
        ))
        .unwrap();

        assert_eq!(
            resolved.ca_bundle_path.as_deref(),
            Some(std::path::Path::new("/etc/ssl/dsn.pem")),
            "the bundle the connector reads is the one lifted from the DSN"
        );
        assert_eq!(resolved.verification, Verification::ChainOnly);
    }

    /// The escalation is only for `require`. `prefer`, `allow` and `disable`
    /// with a bundle configured stay unverified — for `disable` that is the
    /// deliberate documented non-error.
    ///
    /// Red if the escalation's `Some(SslMode::Require)` guard were widened.
    #[test]
    fn a_bundle_does_not_escalate_the_other_modes() {
        for mode in ["disable", "allow", "prefer"].iter() {
            let resolved = resolve(&format!(
                "{}?sslmode={}&sslrootcert=/config/ca.pem",
                BASE, mode
            ))
            .unwrap();
            assert_eq!(
                resolved.verification,
                Verification::None,
                "{} must not be escalated by a configured bundle",
                mode
            );
        }

        // An absent sslmode likewise. libpq's note is about `require`
        // specifically, and postgres' default here is `prefer`.
        let absent = resolve(&format!("{}?sslrootcert=/config/ca.pem", BASE)).unwrap();
        assert_eq!(absent.verification, Verification::None);
    }

    /// The escalation is worthless unless the bundle's anchors actually reach
    /// the root store the verifier is built from. This composes the real
    /// `resolve` with the real `root_store`, so it proves the wiring rather
    /// than the enum value.
    ///
    /// Red if the escalation is removed (the tier would be `None`, so the tier
    /// assertion fails), or if `root_store` stopped adding the bundle.
    #[test]
    fn require_escalation_puts_the_bundles_anchors_in_the_root_store() {
        const TEST_CA_PEM: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/test-ca.pem"
        ));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_CA_PEM).unwrap();

        let resolved = resolve(&format!(
            "{}?sslmode=require&sslrootcert={}",
            BASE,
            path.display()
        ))
        .unwrap();

        assert_eq!(
            resolved.verification,
            Verification::ChainOnly,
            "require + sslrootcert must be a verifying tier"
        );

        let baseline = crate::pg_tls::tls::root_store(None).unwrap();
        let store = crate::pg_tls::tls::root_store(resolved.ca_bundle_path.as_deref()).unwrap();
        assert_eq!(
            store.roots.len(),
            baseline.roots.len() + 1,
            "the bundle's anchor must be present in the store the verifier uses"
        );

        let fixture_anchor = {
            let der = rustls_pemfile::certs(&mut TEST_CA_PEM.as_bytes())
                .next()
                .unwrap()
                .unwrap();
            let mut single = rustls::RootCertStore::empty();
            single.add(der).unwrap();
            single.roots.into_iter().next().unwrap()
        };
        assert!(
            store.roots.contains(&fixture_anchor),
            "the fixture CA must be the anchor that was added"
        );
        assert!(
            !baseline.roots.contains(&fixture_anchor),
            "precondition: the fixture CA is not already a public webpki root"
        );
    }

    // ---------------------------------------------------------------------
    // The authority is copied verbatim
    // ---------------------------------------------------------------------

    /// The authority is copied verbatim, which is the whole reason this module
    /// does not round-trip through `url::Url` (module header). A
    /// percent-encoded password is where a renormalising rewrite would show up
    /// as a failed login — and the `%3F` is the direct guard on splitting at
    /// the FIRST `?`.
    #[test]
    fn percent_encoded_password_in_the_authority_survives() {
        // `p@ss?word` — both the `@` and the `?` are percent-encoded, which a
        // valid URL requires and which this rewriter's first-`?` split
        // depends on.
        const AUTHORITY: &str = "postgresql://user:p%40ss%3Fword@db.example.com:5432/app";

        let resolved = resolve(&format!("{}?sslmode=verify-full", AUTHORITY)).unwrap();

        assert_eq!(
            resolved.dsn,
            format!("{}?sslmode=require", AUTHORITY),
            "the authority must be copied byte-for-byte"
        );
        let cfg = resolved
            .dsn
            .parse::<PgConfig>()
            .expect("rewritten DSN with an encoded password must parse");
        assert_eq!(
            cfg.get_password(),
            Some(b"p@ss?word".as_slice()),
            "postgres must decode the preserved password back to its literal form"
        );
    }

    /// The comma-separated multi-host form the module header names — the other
    /// authority shape `url::Url` would mangle.
    #[test]
    fn comma_separated_multi_host_base_survives() {
        const MULTI_HOST: &str = "postgresql://user@host1:1234,host2,host3:5678/app";

        let resolved = resolve(&format!("{}?sslmode=verify-ca", MULTI_HOST)).unwrap();

        assert_eq!(resolved.dsn, format!("{}?sslmode=require", MULTI_HOST));
        let cfg = resolved
            .dsn
            .parse::<PgConfig>()
            .expect("rewritten multi-host DSN must parse");
        assert_eq!(cfg.get_hosts().len(), 3, "all three hosts must survive");
        assert_eq!(
            cfg.get_ports(),
            &[1234, 5432, 5678],
            "per-host ports (and the default for the bare host) must survive"
        );
    }

    // ---------------------------------------------------------------------
    // DSN form
    // ---------------------------------------------------------------------

    /// libpq's keyword/value connection-string form is rejected outright.
    ///
    /// `postgres::Config::from_str` accepts it (dispatching on the absence of a
    /// `postgres://` / `postgresql://` prefix), so without this guard such a
    /// DSN sails through `resolve` untouched with `requested: None` —
    /// misreporting the tier for `sslmode=require` and leaking
    /// `sslmode=verify-ca` to the driver as a raw parse failure.
    ///
    /// Red if the prefix check is removed: `resolve` would return `Ok`.
    #[test]
    fn keyword_value_dsn_form_is_rejected() {
        for dsn in [
            "host=db.example.com sslmode=verify-full",
            "host=db.example.com port=5432 user=app sslmode=require",
            // No `?`, so without the guard the whole string is treated as an
            // opaque base and no requested mode is reported at all.
            "host=db.example.com",
            "dbname=app",
        ]
        .iter()
        {
            let err = resolve(dsn).expect_err("the keyword/value form must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("postgres://") && msg.contains("keyword/value"),
                "the error must name both the supported and the rejected form: {}",
                msg
            );
            assert!(
                !msg.contains("db.example.com"),
                "the error must not echo the connection string back: {}",
                msg
            );
        }
    }

    /// Both URL prefixes `postgres` recognises are accepted, so the guard
    /// cannot be satisfied by hard-coding one of them.
    #[test]
    fn both_url_prefixes_are_accepted() {
        for prefix in ["postgres", "postgresql"].iter() {
            let dsn = format!(
                "{}://user@db.example.com:5432/app?sslmode=verify-full",
                prefix
            );
            let resolved = resolve(&dsn)
                .unwrap_or_else(|err| panic!("{}:// must be accepted: {}", prefix, err));
            assert_eq!(
                resolved.dsn,
                format!("{}://user@db.example.com:5432/app?sslmode=require", prefix)
            );
            resolved
                .dsn
                .parse::<PgConfig>()
                .expect("the rewritten DSN must parse");
        }
    }

    // ---------------------------------------------------------------------
    // Percent-decoding of the values we consume
    // ---------------------------------------------------------------------

    /// A `+` in a consumed value is a **literal** `+`, not a space.
    ///
    /// `tokio-postgres` decodes query values with
    /// `percent_encoding::percent_decode`, so `/etc/ssl/my+ca.pem` is a path
    /// with a `+` in it. Decoding these with `url::form_urlencoded::parse` —
    /// the HTML form encoding, where `+` means a space — turned that into
    /// `/etc/ssl/my ca.pem` and the bundle open failed with ENOENT.
    ///
    /// Red if `decode_value` goes back to `form_urlencoded`.
    #[test]
    fn plus_in_a_consumed_value_is_literal() {
        let resolved = resolve(&format!(
            "{}?sslmode=verify-ca&sslrootcert=/etc/ssl/my+ca.pem&currentSchema=llm+gw",
            BASE
        ))
        .unwrap();

        assert_eq!(
            resolved.ca_bundle_path.as_deref(),
            Some(std::path::Path::new("/etc/ssl/my+ca.pem")),
            "a `+` in sslrootcert must survive as a `+`"
        );
        assert_eq!(
            resolved.current_schema.as_deref(),
            Some("llm+gw"),
            "a `+` in currentSchema must survive as a `+`"
        );
    }

    /// Percent escapes in a consumed value ARE decoded, so the test above is
    /// not just asserting that decoding was dropped altogether.
    #[test]
    fn percent_escapes_in_a_consumed_value_are_decoded() {
        let resolved = resolve(&format!(
            "{}?sslmode=verify-ca&sslrootcert=/etc/ssl/my%20ca.pem&currentSchema=llm%2Dgw",
            BASE
        ))
        .unwrap();

        assert_eq!(
            resolved.ca_bundle_path.as_deref(),
            Some(std::path::Path::new("/etc/ssl/my ca.pem")),
            "%20 must decode to a space"
        );
        assert_eq!(resolved.current_schema.as_deref(), Some("llm-gw"));
    }
}
