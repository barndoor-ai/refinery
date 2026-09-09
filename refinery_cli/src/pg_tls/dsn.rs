//! libpq -> `postgres` DSN rewriting.
//!
//! Copy of `bdai-platform/libs/pg-tls/src/dsn.rs`; the two must stay
//! behaviorally identical. See `super`'s header for why this is a copy and for
//! the list of intentional divergences (here: `currentSchema` is additionally
//! consumed, and errors are `anyhow`).
//!
//! The base of the URL (scheme, credentials, authority, path) is copied
//! verbatim, because round-tripping the whole URL through `url::Url` would
//! renormalize the authority -- which matters for the comma-separated
//! multi-host and percent-encoded unix-socket forms `postgres` accepts.
//!
//! The query string is handled the same way, one level down: it is split on
//! `&` and each `k=v` segment is carried through as a **raw, still-encoded
//! string slice**. Only the keys this module consumes are decoded. Decoding and
//! re-encoding every parameter would corrupt the ones we have no business
//! touching: `form_urlencoded::Serializer` emits a space as `+`, while
//! `tokio-postgres` percent-decodes query values and would read that `+`
//! literally -- turning `options=-c%20statement_timeout%3D5000` into the
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

use crate::pg_tls::{Resolved, SslMode, TrustAnchors, Verification};

/// The parameters this module consumes out of the query string.
///
/// Matched **case-sensitively**, deliberately: `tokio-postgres` dispatches on
/// a bare `match key { "sslmode" => ..., key => Err(UnknownOption) }`, so
/// `SSLMODE=require` is an unknown option there and treating it as an `sslmode`
/// here would silently invent a behavior the database driver does not have.
const SSL_MODE: &str = "sslmode";
const SSL_ROOT_CERT: &str = "sslrootcert";
const SSL_CERT: &str = "sslcert";
const SSL_KEY: &str = "sslkey";
/// Refinery-specific; the sibling `pg-tls` crate does not consume this.
const CURRENT_SCHEMA: &str = "currentSchema";

/// libpq's reserved `sslrootcert` value selecting the platform's certificate
/// authorities instead of a file. Matched case-sensitively, like the keys.
const SYSTEM_ROOT_CERT: &str = "system";

/// The two prefixes that make `postgres::Config::from_str` take its URL branch,
/// copied from `tokio-postgres`' `UrlParser::remove_url_prefix`. Anything else
/// is libpq's keyword/value form, which this rewriter does not parse.
const URL_PREFIXES: [&str; 2] = ["postgres://", "postgresql://"];

/// Rewrite `dsn` so `postgres` can parse it, reporting what the operator asked
/// for.
///
/// * `sslmode` is consumed and replaced with the mapped value.
/// * `sslrootcert` is consumed and lifted into [`Resolved::trust_anchors`]
///   (`postgres` rejects it as an unknown option). It *is* the trust store, it
///   does not add to a default one, and it escalates every non-`disable`
///   `sslmode` to [`Verification::ChainOnly`] -- see below. The reserved value
///   `system` selects the public webpki roots instead of a file. An **empty**
///   value is treated as unset, matching libpq -- the key is still consumed and
///   stripped, because `postgres` rejects it either way.
/// * `currentSchema` is consumed and lifted into [`Resolved::current_schema`]
///   (same reason), where the CLI uses it as the migration-table schema
///   fallback.
/// * `sslcert` / `sslkey` are a hard error: client-certificate auth is not
///   implemented, and dropping them would fail open on the operator's intent --
///   silently, as an authentication failure that reads like a bad password.
/// * every other parameter is preserved **byte-for-byte**, in order, with its
///   original percent-encoding intact.
///
/// When nothing is consumed the DSN is returned untouched -- no `?` is
/// appended -- and the tier is [`Verification::None`], matching
/// `postgres::Config`'s `Prefer` default.
///
/// # Trust-anchor escalation of every non-`disable` mode
///
/// Any `sslmode` other than `disable` resolves to at least
/// [`Verification::ChainOnly`] once trust anchors are configured, instead of
/// [`Verification::None`]. That is libpq's documented behavior: "if a root CA
/// file exists, the behavior of `sslmode=require` will be the same as that of
/// `verify-ca`, meaning the server certificate is validated against the CA"
/// ([PostgreSQL docs, 32.19.1 Client Verification of Server
/// Certificates](https://www.postgresql.org/docs/current/libpq-ssl.html)), and
/// `sslrootcert`'s own entry says "if the file exists, the server's certificate
/// will be verified to be signed by one of these authorities" without
/// qualifying it by `sslmode`. libpq's implementation is likewise unqualified:
/// it sets a `have_rootcert` flag purely on the root file being readable and
/// then does `if (have_rootcert) SSL_set_verify(conn->ssl, SSL_VERIFY_PEER,
/// verify_cb);`. So `prefer`, `allow` and an absent `sslmode` escalate too, not
/// just `require` -- scoping the escalation to `require` silently discarded a
/// bundle supplied with any of the others, a fail-open. `disable` is the one
/// exception: libpq does no SSL there and never loads the root file, so a
/// configured `sslrootcert` is simply unused. With **no** anchors those modes
/// stay at [`Verification::None`].
///
/// # `verify-ca` / `verify-full` require an anchor source
///
/// Both are a hard error when `sslrootcert` is absent, mirroring libpq, which
/// refuses to continue when `sslmode[0] == 'v'` and the root file cannot be
/// read: `root certificate file "%s" does not exist ... or change sslmode to
/// disable server certificate verification`. Resolving them to
/// [`Verification::ChainOnly`] over the public roots instead would mean "any
/// certificate from any public CA for any hostname" -- the tier does not check
/// the name -- which is not verification at all.
///
/// # `sslrootcert=system` implies `verify-full`
///
/// PostgreSQL documents: "When using `sslrootcert=system`, the default
/// `sslmode` is changed to `verify-full`, and any weaker setting will result in
/// an error. In most cases it is trivial for anyone to obtain a certificate
/// trusted by the system for a hostname they control, rendering `verify-ca`
/// and all weaker modes useless." So `sslrootcert=system` with no `sslmode` is
/// promoted to `verify-full`, and `sslrootcert=system` with any other explicit
/// mode -- `disable`, `require`, `verify-ca` included -- is a hard error. That
/// is what makes "verify-ca over the public web PKI" unrepresentable here.
///
/// That rule is the DSN half of a two-layer guard:
/// [`Verification::ChainOnly`] with [`TrustAnchors::System`] is an invalid pair
/// that `resolve` never returns, and
/// [`crate::pg_tls::tls::client_config`] refuses to build it as well, so a
/// hand-built [`Resolved`] cannot reconstruct it.
///
/// # Only the URL DSN form is supported
///
/// `postgres::Config::from_str` accepts two forms and dispatches on the
/// `postgres://` / `postgresql://` prefix: `UrlParser::parse` for the URL form,
/// falling back to `Parser::parse` for libpq's keyword/value form. This
/// rewriter only understands the URL form, so a keyword/value DSN is rejected
/// rather than passed through unexamined -- which would leak
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
    let mut trust_anchors = TrustAnchors::None;
    let mut current_schema: Option<String> = None;
    // Whether any key was consumed and stripped, which is what decides between
    // handing the input back byte-for-byte and rebuilding the query. It is not
    // the same question as "did a value survive": an empty `sslrootcert` means
    // "unset", but the key is still stripped, because `postgres::Config`
    // rejects `sslrootcert` as an unknown option.
    let mut consumed_any = false;
    // Raw, still-encoded `k=v` segments, kept exactly as the operator wrote
    // them.
    let mut retained: Vec<&str> = Vec::new();

    for segment in query.unwrap_or("").split('&').filter(|s| !s.is_empty()) {
        let key = match segment.find('=') {
            Some(idx) => &segment[..idx],
            None => segment,
        };
        match key {
            SSL_MODE => {
                consumed_any = true;
                requested = Some(SslMode::parse(&decode_value(segment))?);
            }
            SSL_ROOT_CERT => {
                consumed_any = true;
                let value = decode_value(segment);
                trust_anchors = if value.is_empty() {
                    // libpq treats an empty `sslrootcert` as unset. Taking it
                    // as a path instead would satisfy the `verify-ca` /
                    // `verify-full` anchor gate, escalate the weaker modes, and
                    // then die at `File::open("")` with a blank path in the
                    // message.
                    TrustAnchors::None
                } else if value == SYSTEM_ROOT_CERT {
                    // `system` is libpq's reserved value for the platform's
                    // certificate authorities; anything else is a file path.
                    TrustAnchors::System
                } else {
                    TrustAnchors::Bundle(PathBuf::from(value))
                };
            }
            CURRENT_SCHEMA => {
                consumed_any = true;
                current_schema = Some(decode_value(segment));
            }
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

    // `sslrootcert=system` fixes the mode at `verify-full`. PostgreSQL
    // documents this default change -- it is not an invention here: "When using
    // sslrootcert=system, the default sslmode is changed to verify-full, and
    // any weaker setting will result in an error. In most cases it is trivial
    // for anyone to obtain a certificate trusted by the system for a hostname
    // they control, rendering verify-ca and all weaker modes useless."
    if trust_anchors == TrustAnchors::System {
        match requested {
            None => requested = Some(SslMode::VerifyFull),
            Some(SslMode::VerifyFull) => {}
            Some(other) => {
                return Err(anyhow!(
                    "sslrootcert=system requires sslmode=verify-full, but sslmode={} was \
                     requested; anyone can obtain a publicly trusted certificate for a \
                     hostname they control, so verifying against the public certificate \
                     authorities is only meaningful with a hostname check",
                    other.as_str()
                ))
            }
        }
    }

    // libpq refuses to continue when `sslmode[0] == 'v'` and the root
    // certificate file cannot be read. Resolving these to a chain check over
    // the public roots instead would accept any publicly issued certificate
    // for any hostname, which is not verification.
    if let Some(mode) = requested {
        let verifies_the_name_or_the_chain =
            mode == SslMode::VerifyCa || mode == SslMode::VerifyFull;
        if verifies_the_name_or_the_chain && !trust_anchors.is_configured() {
            // Deliberately names only the mode, never the DSN: it can carry a
            // password and the CLI prints this to stderr.
            return Err(anyhow!(
                "sslmode={} requires a trust anchor: set sslrootcert to the CA certificate \
                 file, or sslrootcert=system to verify against the public certificate \
                 authorities, or change sslmode to disable server certificate verification",
                mode.as_str()
            ));
        }
    }

    let effective = requested.map_or("prefer", SslMode::effective);

    // The escalation lives here rather than in `SslMode::verification`, which
    // sees only the mode and has no way to know anchors were configured. It is
    // written so it can only ever RAISE the tier: the mode's own tier is
    // computed first and only a `Verification::None` is replaced.
    let verification = {
        let base = requested.map_or(Verification::None, SslMode::verification);
        // `disable` is excluded because libpq does no SSL at all there and
        // never loads the root file, so configured anchors go unused.
        let escalates = requested != Some(SslMode::Disable) && trust_anchors.is_configured();
        if base == Verification::None && escalates {
            Verification::ChainOnly
        } else {
            base
        }
    };

    let rewritten = if !consumed_any {
        // Nothing was consumed, so nothing needs rebuilding: hand back the
        // input byte-for-byte. Notably this leaves a query-less DSN without
        // a trailing `?`. Note that `sslrootcert=system` promotes `requested`
        // to `Some(VerifyFull)` above, so that case rebuilds with
        // `sslmode=require` as it must -- and an empty `sslrootcert`, which
        // resolves to no anchors at all, still rebuilds, because the key has
        // to be stripped either way.
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
        trust_anchors,
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

    fn resolve_mode_with_bundle(mode: &str) -> Resolved {
        resolve(&format!(
            "{}?sslmode={}&sslrootcert=/config/ca.pem",
            BASE, mode
        ))
        .expect("resolve should succeed")
    }

    /// Every documented mode, plus absent, maps to the documented effective
    /// `sslmode` and verification tier -- with **no** trust anchors configured.
    ///
    /// `resolve_mode` passes no `sslrootcert`, so `verify-ca` and `verify-full`
    /// are hard errors here (libpq's `sslmode[0] == 'v'` + unreadable root file
    /// refusal) and every other mode is unverified. The anchored rows are
    /// `anchored_mode_mapping_table` below.
    #[test]
    fn mode_mapping_table() {
        let cases: &[(&str, &str, Verification)] = &[
            ("disable", "disable", Verification::None),
            ("allow", "prefer", Verification::None),
            ("prefer", "prefer", Verification::None),
            ("require", "require", Verification::None),
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
            assert_eq!(
                resolved.trust_anchors,
                TrustAnchors::None,
                "{}: no sslrootcert means no anchors",
                requested
            );
        }

        for requested in ["verify-ca", "verify-full"].iter() {
            resolve(&format!("{}?sslmode={}", BASE, requested)).expect_err(
                "a verify-* mode with no trust anchor must be a hard error, not a chain \
                 check over the public roots",
            );
        }

        let absent = resolve(BASE).unwrap();
        assert_eq!(absent.requested, None);
        assert_eq!(absent.effective, "prefer");
        assert_eq!(absent.verification, Verification::None);
        assert_eq!(absent.trust_anchors, TrustAnchors::None);
        assert_eq!(absent.dsn, BASE, "absent sslmode leaves the DSN untouched");
        assert!(
            !absent.dsn.contains('?'),
            "absent sslmode must not append a query string"
        );
    }

    /// The same table with a CA bundle configured. Every mode but `disable`
    /// rises to at least `ChainOnly`, because libpq's `have_rootcert` gate is
    /// not scoped by `sslmode`.
    #[test]
    fn anchored_mode_mapping_table() {
        let cases: &[(&str, &str, Verification)] = &[
            ("disable", "disable", Verification::None),
            ("allow", "prefer", Verification::ChainOnly),
            ("prefer", "prefer", Verification::ChainOnly),
            ("require", "require", Verification::ChainOnly),
            ("verify-ca", "require", Verification::ChainOnly),
            ("verify-full", "require", Verification::Full),
        ];

        for (requested, effective, verification) in cases {
            let resolved = resolve_mode_with_bundle(requested);
            assert_eq!(
                resolved.requested,
                Some(SslMode::parse(requested).unwrap()),
                "{}: the escalation must not rewrite what the operator asked for",
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
                "{}: verification tier with a bundle configured",
                requested
            );
            assert_eq!(
                resolved.trust_anchors,
                TrustAnchors::Bundle(PathBuf::from("/config/ca.pem")),
                "{}: the bundle must be lifted",
                requested
            );
        }

        // Absent `sslmode` escalates too -- postgres' own default is `prefer`,
        // and libpq loads the root file regardless of the mode.
        let absent = resolve(&format!("{}?sslrootcert=/config/ca.pem", BASE)).unwrap();
        assert_eq!(absent.requested, None);
        assert_eq!(absent.effective, "prefer");
        assert_eq!(absent.verification, Verification::ChainOnly);
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
            // A bundle for every mode, so `verify-ca`/`verify-full` -- which
            // now require a trust anchor -- still get exercised here.
            let resolved = resolve_mode_with_bundle(mode);
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
            // Every row carries a bundle, so the two `verify-*` rows -- which
            // now require a trust anchor -- are still covered.
            let cfg = resolve_mode_with_bundle(mode)
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
    /// `+` -- so `options=-c%20statement_timeout%3D5000` would reach the server
    /// as `-c+statement_timeout=5000`.
    #[test]
    fn unrelated_params_round_trip_byte_for_byte() {
        const OPTIONS: &str = "options=-c%20statement_timeout%3D5000";

        let resolved = resolve(&format!(
            "{}?{}&application_name=refinery&connect_timeout=5&sslmode=verify-full\
             &sslrootcert=/config/ca.pem",
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
    /// across the `&`), so the correct behavior is to hand its own error
    /// back to the operator rather than to reshape or silently drop the
    /// segment.
    #[test]
    fn valueless_param_is_preserved_verbatim() {
        let resolved = resolve(&format!(
            "{}?application_name=refinery&keepalives&sslmode=verify-ca&sslrootcert=/config/ca.pem",
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
        assert_eq!(resolved.trust_anchors, TrustAnchors::None);
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
                resolved.trust_anchors,
                TrustAnchors::Bundle(PathBuf::from("/etc/ssl/ca.pem")),
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
            // Both modes end at a verifying tier -- `require` by escalation.
            assert_eq!(
                resolved.verification,
                Verification::ChainOnly,
                "sslmode={}: a lifted bundle must be verified against",
                mode
            );
        }
    }

    /// `sslrootcert` with no `sslmode` at all is still lifted -- and still
    /// escalates. libpq's `have_rootcert` gate does not consult the mode, so an
    /// operator who supplies a bundle and leaves `sslmode` to its default gets
    /// the chain checked rather than silently ignored.
    #[test]
    fn sslrootcert_is_lifted_and_escalates_even_without_sslmode() {
        let resolved = resolve(&format!("{}?sslrootcert=/etc/ssl/ca.pem", BASE)).unwrap();

        assert_eq!(
            resolved.trust_anchors,
            TrustAnchors::Bundle(PathBuf::from("/etc/ssl/ca.pem"))
        );
        assert_eq!(
            resolved.verification,
            Verification::ChainOnly,
            "a bundle supplied with no sslmode must not be silently discarded"
        );
        assert_eq!(resolved.dsn, BASE);
    }

    /// An empty `sslrootcert` means "unset", exactly as libpq treats it.
    ///
    /// Read as a path instead, `PathBuf::from("")` reports `is_configured()`
    /// true: it would satisfy the `verify-ca` / `verify-full` anchor gate,
    /// escalate `prefer` / `require` to `ChainOnly`, and then fail at
    /// `File::open("")` with a message ending in a blank path. Red on every
    /// count if the empty case stops mapping to `TrustAnchors::None`.
    #[test]
    fn an_empty_sslrootcert_is_treated_as_unset() {
        // Alone: no anchors, and the key is still stripped -- `postgres`
        // rejects `sslrootcert` as an unknown option, so it cannot be handed
        // through by the untouched-DSN passthrough. With nothing else in the
        // query that leaves the bare base and no trailing `?`.
        let alone = resolve(&format!("{}?sslrootcert=", BASE)).unwrap();
        assert_eq!(alone.trust_anchors, TrustAnchors::None);
        assert_eq!(alone.verification, Verification::None);
        assert_eq!(alone.dsn, BASE, "an empty sslrootcert must be stripped");
        assert!(
            !alone.dsn.contains('?'),
            "stripping the only parameter must not leave a dangling `?`: {}",
            alone.dsn
        );
        alone
            .dsn
            .parse::<PgConfig>()
            .expect("the rewritten DSN must parse");

        // And alongside other parameters it is stripped without disturbing
        // them.
        let with_others = resolve(&format!(
            "{}?application_name=refinery&sslrootcert=&sslmode=require",
            BASE
        ))
        .unwrap();
        assert_eq!(with_others.trust_anchors, TrustAnchors::None);
        assert_eq!(
            with_others.dsn,
            format!("{}?application_name=refinery&sslmode=require", BASE)
        );

        // It must not escalate the weaker modes: there is no anchor to verify
        // against.
        for mode in ["prefer", "require"].iter() {
            let resolved = resolve(&format!("{}?sslmode={}&sslrootcert=", BASE, mode)).unwrap();
            assert_eq!(
                resolved.verification,
                Verification::None,
                "sslmode={} + an empty sslrootcert must not escalate",
                mode
            );
        }

        // And it must not satisfy the verify-* anchor gate: the operator gets
        // the "requires a trust anchor" error, not a confusing file-open
        // failure on an empty path.
        for mode in ["verify-ca", "verify-full"].iter() {
            let err = resolve(&format!("{}?sslmode={}&sslrootcert=", BASE, mode))
                .expect_err("an empty sslrootcert must not satisfy the anchor requirement");
            let msg = err.to_string();
            assert!(
                msg.contains(&format!("sslmode={}", mode)),
                "sslmode={}: expected the trust-anchor error: {}",
                mode,
                msg
            );
            assert!(
                !msg.contains("failed to read CA bundle"),
                "sslmode={}: must not surface as a file-open failure: {}",
                mode,
                msg
            );
        }
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
    // `require` + CA bundle -> ChainOnly (libpq's bundle-conditional parity)
    // ---------------------------------------------------------------------

    /// `sslmode=require` with a bundle escalates to `ChainOnly`, and `require`
    /// with **no** bundle does not.
    ///
    /// Both halves are load-bearing. Removing the escalation makes the first
    /// assertion fail (it would report `None`); widening the escalation to
    /// unconditional makes the second fail.
    ///
    /// The fork has no non-DSN `TlsSettings` bundle field, so unlike the
    /// sibling's version of this test the "configured" bundle here is the
    /// DSN's own `sslrootcert` -- it is the only source there is.
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
            "require with no bundle stays unverified -- libpq promises no more than encryption there"
        );
    }

    /// The same escalation stated from the DSN's own `sslrootcert`, which is an
    /// operator's obvious first move and used to be lifted and then ignored.
    ///
    /// The escalation must be computed from the **merged**
    /// [`Resolved::trust_anchors`] the connector actually reads, not from some
    /// earlier value -- hence the assertion on the lifted bundle alongside the
    /// tier. (The sibling `pg-tls` crate states that as a separate
    /// precedence test, because it has a `TlsSettings` bundle field that can
    /// compete with the DSN's. This fork has no such field: `sslrootcert` is
    /// the only bundle source, so there is nothing for it to win over and the
    /// two tests collapse into this one.)
    #[test]
    fn require_with_sslrootcert_in_the_dsn_escalates_to_chain_only() {
        let resolved = resolve(&format!(
            "{}?sslmode=require&sslrootcert=/etc/ssl/ca.pem",
            BASE
        ))
        .unwrap();

        assert_eq!(resolved.verification, Verification::ChainOnly);
        assert_eq!(
            resolved.trust_anchors,
            TrustAnchors::Bundle(PathBuf::from("/etc/ssl/ca.pem"))
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

    /// The escalation applies to **every** mode but `disable`.
    ///
    /// libpq's gate is `if (have_rootcert) SSL_set_verify(...)` -- not scoped
    /// by `sslmode` -- so a bundle handed to `prefer`, `allow` or no `sslmode`
    /// at all must be verified against too. Scoping it to `require` (as this
    /// test's predecessor pinned) silently discarded the bundle for the
    /// others: a fail-open.
    ///
    /// Red if the escalation is narrowed back to `Some(SslMode::Require)`, and
    /// red the other way if `disable` starts escalating.
    #[test]
    fn a_bundle_escalates_every_non_disable_mode() {
        for mode in ["allow", "prefer", "require"].iter() {
            let resolved = resolve(&format!(
                "{}?sslmode={}&sslrootcert=/config/ca.pem",
                BASE, mode
            ))
            .unwrap();
            assert_eq!(
                resolved.verification,
                Verification::ChainOnly,
                "sslmode={} must be escalated by a configured bundle",
                mode
            );
            assert_eq!(
                resolved.requested,
                Some(SslMode::parse(mode).unwrap()),
                "sslmode={}: the escalation must not rewrite the requested mode",
                mode
            );
        }

        // An absent sslmode likewise: the gate is on the root file, not the
        // mode, and postgres' default here is `prefer`.
        let absent = resolve(&format!("{}?sslrootcert=/config/ca.pem", BASE)).unwrap();
        assert_eq!(absent.verification, Verification::ChainOnly);

        // `disable` is the one exception -- libpq does no SSL there and never
        // loads the root file, so a configured bundle is simply unused.
        let disabled = resolve(&format!(
            "{}?sslmode=disable&sslrootcert=/config/ca.pem",
            BASE
        ))
        .unwrap();
        assert_eq!(
            disabled.verification,
            Verification::None,
            "sslmode=disable does no SSL at all, so a bundle cannot escalate it"
        );
        assert_eq!(
            disabled.trust_anchors,
            TrustAnchors::Bundle(PathBuf::from("/config/ca.pem")),
            "the bundle is still lifted, it is just unused"
        );
    }

    /// `verify-ca` and `verify-full` with no `sslrootcert` are hard errors.
    ///
    /// libpq refuses here too (`sslmode[0] == 'v'` with an unreadable root
    /// file). Resolving them to `ChainOnly` over the public roots -- which is
    /// what this code used to do -- means "any certificate from any public CA
    /// for any hostname", because `ChainOnly` skips the name check. Red if
    /// either mode starts resolving instead of erroring.
    #[test]
    fn verify_modes_require_a_trust_anchor() {
        const SECRET_DSN_BASE: &str = "postgresql://user:sup3rsecret@db.example.com:5432/app";

        for mode in ["verify-ca", "verify-full"].iter() {
            let err = match resolve(&format!("{}?sslmode={}", SECRET_DSN_BASE, mode)) {
                Ok(_) => panic!("sslmode={} with no trust anchor must be refused", mode),
                Err(err) => err,
            };
            let msg = err.to_string();
            // The mode-specific substring, not a bare `contains(mode)` and not
            // `contains("sslrootcert")`: the latter is in the fixed help text
            // whatever the input was, so it can never fail. `sslmode=<mode>` is
            // falsifiable for both rows.
            assert!(
                msg.contains(&format!("sslmode={}", mode)),
                "sslmode={}: the error must name the mode: {}",
                mode,
                msg
            );
            // Every new error path gets this check: the CLI prints these to
            // stderr and the DSN can carry a password.
            assert!(
                !msg.contains("sup3rsecret") && !msg.contains("db.example.com"),
                "sslmode={}: the error must not echo the DSN: {}",
                mode,
                msg
            );
        }

        // And both resolve fine once an anchor source is named, so the test is
        // not just asserting that the modes were removed.
        assert_eq!(
            resolve(&format!(
                "{}?sslmode=verify-ca&sslrootcert=/config/ca.pem",
                BASE
            ))
            .unwrap()
            .verification,
            Verification::ChainOnly
        );
        assert_eq!(
            resolve(&format!(
                "{}?sslmode=verify-full&sslrootcert=/config/ca.pem",
                BASE
            ))
            .unwrap()
            .verification,
            Verification::Full
        );
    }

    /// `sslrootcert=system` fixes the mode at `verify-full`.
    ///
    /// PostgreSQL: "When using `sslrootcert=system`, the default `sslmode` is
    /// changed to `verify-full`, and any weaker setting will result in an
    /// error. In most cases it is trivial for anyone to obtain a certificate
    /// trusted by the system for a hostname they control, rendering `verify-ca`
    /// and all weaker modes useless." That rule is what makes "verify-ca over
    /// the public web PKI" -- the MITM-friendly combination -- unrepresentable.
    #[test]
    fn system_trust_anchors_require_verify_full() {
        let promoted = resolve(&format!("{}?sslrootcert=system", BASE)).unwrap();
        assert_eq!(
            promoted.verification,
            Verification::Full,
            "sslrootcert=system with no sslmode must default to verify-full"
        );
        assert_eq!(promoted.requested, Some(SslMode::VerifyFull));
        assert_eq!(promoted.effective, "require");
        assert_eq!(promoted.trust_anchors, TrustAnchors::System);
        assert_eq!(
            promoted.dsn,
            format!("{}?sslmode=require", BASE),
            "the promoted mode is consumed, so the DSN is rebuilt with it"
        );

        for mode in ["disable", "allow", "prefer", "require", "verify-ca"].iter() {
            let err = match resolve(&format!("{}?sslmode={}&sslrootcert=system", BASE, mode)) {
                Ok(_) => panic!("sslmode={} + sslrootcert=system must be refused", mode),
                Err(err) => err,
            };
            let msg = err.to_string();
            // Asserted as `sslmode=<mode>`, not a bare `contains(mode)`: the
            // fixed message text already carries the words "requires" and
            // "requested", so for the `require` row a bare substring check is
            // satisfied whatever the input was. "verify-full" is likewise in
            // the fixed text on every row.
            assert!(
                msg.contains("verify-full") && msg.contains(&format!("sslmode={}", mode)),
                "sslmode={} + system must be refused, naming both modes: {}",
                mode,
                msg
            );
            assert!(
                !msg.contains("db.example.com"),
                "sslmode={}: the error must not echo the DSN: {}",
                mode,
                msg
            );
        }

        let explicit =
            resolve(&format!("{}?sslmode=verify-full&sslrootcert=system", BASE)).unwrap();
        assert_eq!(explicit.verification, Verification::Full);
        assert_eq!(explicit.trust_anchors, TrustAnchors::System);
    }

    /// `system` is the reserved keyword, not a relative path called "system".
    ///
    /// Red if the parse became an unconditional `TrustAnchors::Bundle`, which
    /// would try to `File::open("system")` and fail with ENOENT -- and red the
    /// other way if the keyword check widened to any path *containing*
    /// "system", which would silently swap an operator's private bundle for
    /// the public web PKI.
    #[test]
    fn system_is_a_keyword_not_a_path() {
        let resolved = resolve(&format!("{}?sslrootcert=system", BASE)).unwrap();

        assert_eq!(resolved.trust_anchors, TrustAnchors::System);

        // A path that merely contains "system" is still a bundle.
        let bundle = resolve(&format!(
            "{}?sslmode=verify-full&sslrootcert=/etc/ssl/system.pem",
            BASE
        ))
        .unwrap();
        assert_eq!(
            bundle.trust_anchors,
            TrustAnchors::Bundle(PathBuf::from("/etc/ssl/system.pem"))
        );
    }

    /// The escalation is worthless unless the bundle's anchors actually reach
    /// the root store the verifier is built from, and *only* the bundle's
    /// anchors do. This composes the real `resolve` with the real `root_store`,
    /// so it proves the wiring rather than the enum value.
    ///
    /// The exact-length assertion is the direct regression test for the
    /// public-roots seed: with `RootCertStore::from_iter(TLS_SERVER_ROOTS)` as
    /// the starting point this store held ~150 anchors and any public CA's
    /// certificate for any hostname satisfied the (name-blind) `ChainOnly`
    /// tier.
    #[test]
    fn require_escalation_puts_only_the_bundles_anchors_in_the_root_store() {
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

        let store = crate::pg_tls::tls::root_store(&resolved.trust_anchors).unwrap();
        assert_eq!(
            store.roots.len(),
            1,
            "the single-certificate bundle must be the WHOLE trust store, not an addition \
             to the public roots"
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
        assert_eq!(
            store.roots[0], fixture_anchor,
            "and the one anchor must be the fixture CA"
        );
        let public = crate::pg_tls::tls::root_store(&TrustAnchors::System).unwrap();
        assert!(
            !public.roots.contains(&fixture_anchor),
            "precondition: the fixture CA is not already a public webpki root"
        );
    }

    // ---------------------------------------------------------------------
    // The authority is copied verbatim
    // ---------------------------------------------------------------------

    /// The authority is copied verbatim, which is the whole reason this module
    /// does not round-trip through `url::Url` (module header). A
    /// percent-encoded password is where a renormalizing rewrite would show up
    /// as a failed login -- and the `%3F` is the direct guard on splitting at
    /// the FIRST `?`.
    #[test]
    fn percent_encoded_password_in_the_authority_survives() {
        // `p@ss?word` -- both the `@` and the `?` are percent-encoded, which a
        // valid URL requires and which this rewriter's first-`?` split
        // depends on.
        const AUTHORITY: &str = "postgresql://user:p%40ss%3Fword@db.example.com:5432/app";

        let resolved = resolve(&format!(
            "{}?sslmode=verify-full&sslrootcert=/config/ca.pem",
            AUTHORITY
        ))
        .unwrap();

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

    /// The comma-separated multi-host form the module header names -- the other
    /// authority shape `url::Url` would mangle.
    #[test]
    fn comma_separated_multi_host_base_survives() {
        const MULTI_HOST: &str = "postgresql://user@host1:1234,host2,host3:5678/app";

        let resolved = resolve(&format!(
            "{}?sslmode=verify-ca&sslrootcert=/config/ca.pem",
            MULTI_HOST
        ))
        .unwrap();

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
    /// DSN sails through `resolve` untouched with `requested: None` --
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

    /// Both URL prefixes `postgres` recognizes are accepted, so the guard
    /// cannot be satisfied by hard-coding one of them.
    #[test]
    fn both_url_prefixes_are_accepted() {
        for prefix in ["postgres", "postgresql"].iter() {
            let dsn = format!(
                "{}://user@db.example.com:5432/app?sslmode=verify-full&sslrootcert=/config/ca.pem",
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
    /// with a `+` in it. Decoding these with `url::form_urlencoded::parse` --
    /// the HTML form encoding, where `+` means a space -- turned that into
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
            resolved.trust_anchors,
            TrustAnchors::Bundle(PathBuf::from("/etc/ssl/my+ca.pem")),
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
            resolved.trust_anchors,
            TrustAnchors::Bundle(PathBuf::from("/etc/ssl/my ca.pem")),
            "%20 must decode to a space"
        );
        assert_eq!(resolved.current_schema.as_deref(), Some("llm-gw"));
    }
}
