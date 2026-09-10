//! Root store and [`rustls::ClientConfig`] construction.
//!
//! Copy of `bdai-platform/libs/pg-tls/src/tls.rs`; the two must stay
//! behaviorally identical. See `super`'s header for why this is a copy and for
//! the one intentional divergence: the crypto provider here is `ring`, not
//! `aws-lc-rs`, because this binary is built statically against musl in a
//! `FROM scratch` image and `aws-lc-rs` needs cmake/nasm in the builder.

use std::fs::File;
use std::io::BufReader;
use std::iter::FromIterator;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};

use crate::pg_tls::verifier::{AcceptAnyVerifier, ChainOnlyVerifier};
use crate::pg_tls::{Resolved, TrustAnchors, Verification};

/// The crypto provider is named explicitly rather than resolved from crate
/// features.
///
/// `CryptoProvider::from_crate_features()` returns `None` -- and the bare
/// `ClientConfig::builder()` then panics inside its `.expect()` -- as soon as
/// two provider features are unified into a build. Naming the provider means
/// that can never happen here, whatever else lands in the dependency graph. Do
/// not reintroduce `ClientConfig::builder()` or
/// `WebPkiServerVerifier::builder()` in this file.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// The connector's trust store, built from exactly what `sslrootcert` named.
///
/// libpq's `sslrootcert` *is* the trust store, it does not add to a default
/// one: `SSL_CTX_load_verify_locations(ctx, sslrootcert, NULL)` replaces
/// OpenSSL's default locations for that context. So
/// [`TrustAnchors::Bundle`] yields a store holding **only** that file's
/// certificates, and the public web PKI is reachable only through the explicit,
/// reserved opt-in `sslrootcert=system` ([`TrustAnchors::System`]). Seeding the
/// store with the public roots and then *adding* the bundle would mean a
/// certificate issued by any public CA for any hostname satisfies `verify-ca`
/// and the escalated `require` -- neither of which checks the name -- i.e. a
/// MITM that also gets to pick the authentication method.
///
/// An unreadable bundle, or a bundle containing no certificates, is a hard
/// error: silently falling back to the public roots would turn an operator's
/// private-CA configuration into an unverifiable connection.
///
/// [`TrustAnchors::None`] is likewise a hard error rather than an empty store.
/// Only the verifying tiers call this, and a verifier over zero anchors is a
/// configuration bug; [`crate::pg_tls::dsn::resolve`] already makes the
/// combination unreachable from the CLI, so this guard exists so that a
/// hand-built [`Resolved`] cannot fail open either.
pub(crate) fn root_store(trust_anchors: &TrustAnchors) -> anyhow::Result<RootCertStore> {
    let path = match trust_anchors {
        TrustAnchors::None => {
            return Err(anyhow!(
                "a verifying TLS tier was requested with no trust anchors; set sslrootcert \
                 to the CA certificate file, or sslrootcert=system to verify against the \
                 public certificate authorities"
            ))
        }
        TrustAnchors::System => {
            return Ok(RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
        }
        TrustAnchors::Bundle(path) => path.as_path(),
    };

    // Starts EMPTY, deliberately: the bundle is the whole trust store.
    let mut roots = RootCertStore::empty();

    let file =
        File::open(path).with_context(|| format!("failed to read CA bundle {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.with_context(|| format!("failed to read CA bundle {}", path.display()))?;
        roots.add(cert).with_context(|| {
            format!(
                "CA bundle {} contained a certificate rustls rejected",
                path.display()
            )
        })?;
        added += 1;
    }

    if added == 0 {
        return Err(anyhow!(
            "CA bundle {} contained no certificates",
            path.display()
        ));
    }

    Ok(roots)
}

/// Build a [`ClientConfig`] for the tier `resolved` asked for.
///
/// The root store -- and therefore the CA bundle -- is only read for the tiers
/// that consult it. Note that an `sslrootcert` alongside `sslmode=require` (or
/// `prefer`, or `allow`, or no `sslmode` at all) is *not* one of the tiers that
/// skips it: [`crate::pg_tls::dsn::resolve`] escalates every non-`disable` mode
/// with configured anchors to [`Verification::ChainOnly`], so the bundle is
/// read and an unreadable one is a hard error.
///
/// [`Verification::ChainOnly`] over [`TrustAnchors::System`] is a hard error.
/// That tier does not check the hostname, so over the public web PKI it would
/// accept any publicly issued certificate for any name -- see the guard below.
pub fn client_config(resolved: &Resolved) -> anyhow::Result<ClientConfig> {
    let trust_anchors = &resolved.trust_anchors;
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to build TLS client configuration")?;

    let config = match resolved.verification {
        Verification::Full => builder
            .with_webpki_verifier(webpki_verifier(&provider, trust_anchors)?)
            .with_no_client_auth(),
        Verification::ChainOnly => {
            // The public web PKI with no hostname check is not verification.
            // `dsn::resolve` already forbids this pair at the DSN layer --
            // PostgreSQL's documented rule that `sslrootcert=system` requires
            // `sslmode=verify-full` -- so it is unreachable from a CLI
            // invocation. This is the defense-in-depth second half, so that a
            // hand-built `Resolved` cannot fail open either, exactly like the
            // `TrustAnchors::None` guard in `root_store`.
            if matches!(trust_anchors, TrustAnchors::System) {
                return Err(anyhow!(
                    "chain-only verification over the public certificate authorities is not \
                     a supported combination: with no hostname check, any publicly issued \
                     certificate for any name would be accepted. Use sslmode=verify-full \
                     with sslrootcert=system, or name a private CA bundle"
                ));
            }
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ChainOnlyVerifier::new(
                    webpki_verifier(&provider, trust_anchors)?,
                )))
                .with_no_client_auth()
        }
        // Never reads the anchors: there is nothing to verify against.
        Verification::None => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier::new(provider)))
            .with_no_client_auth(),
    };

    Ok(config)
}

/// Build the webpki verifier against an **explicitly named** provider.
///
/// `WebPkiServerVerifier::builder` is the same trap as `ClientConfig::builder`:
/// it calls `CryptoProvider::get_default_or_install_from_crate_features()`,
/// which panics when the crate features name two providers.
fn webpki_verifier(
    provider: &Arc<CryptoProvider>,
    trust_anchors: &TrustAnchors,
) -> anyhow::Result<Arc<WebPkiServerVerifier>> {
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_store(trust_anchors)?),
        provider.clone(),
    )
    .build()
    .context("failed to build certificate verifier")
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::io::Write;

    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::*;
    use crate::pg_tls::dsn;

    /// A self-signed CA, PEM-encoded -- the same fixture as the sibling
    /// `pg-tls` crate's `tests/fixtures/test-ca.pem`. Content is irrelevant
    /// beyond being a parseable X.509 certificate rustls will accept as a
    /// trust anchor, and *not* being a public webpki root.
    ///
    /// Resolved from `CARGO_MANIFEST_DIR` at compile time, so it does not
    /// depend on the working directory the test binary is run from.
    const TEST_CA_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test-ca.pem"
    ));

    fn resolved(verification: Verification, trust_anchors: TrustAnchors) -> Resolved {
        Resolved {
            dsn: "postgresql://user@db.example.com/app".to_string(),
            requested: None,
            effective: "require",
            verification,
            trust_anchors,
            current_schema: None,
        }
    }

    /// Write the fixture CA out to a temporary file and return it as a bundle.
    fn fixture_bundle(dir: &tempfile::TempDir) -> TrustAnchors {
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_CA_PEM).unwrap();
        TrustAnchors::Bundle(path)
    }

    /// The fixture CA as the single anchor rustls builds from it, for set
    /// comparisons against a root store.
    fn fixture_anchor() -> rustls::pki_types::TrustAnchor<'static> {
        let der = rustls_pemfile::certs(&mut TEST_CA_PEM.as_bytes())
            .next()
            .expect("fixture must contain a certificate")
            .expect("fixture certificate must parse");
        let mut single = RootCertStore::empty();
        single.add(der).unwrap();
        single.roots.into_iter().next().unwrap()
    }

    /// A `ClientConfig` actually builds for every tier. This is the regression
    /// test for the crypto-provider panic -- no assertion about mode mapping
    /// can catch it, because the panic happens at construction.
    ///
    /// The verifying tiers need an anchor source now (a verifier over zero
    /// anchors is a hard error). `Full` is given the public roots; `ChainOnly`
    /// is given a private bundle, because `ChainOnly` over the public roots is
    /// itself a hard error -- see
    /// `chain_only_over_the_public_roots_is_rejected`.
    #[test]
    fn client_config_builds_for_every_tier() {
        let dir = tempfile::tempdir().unwrap();
        let tiers = [
            (Verification::None, TrustAnchors::None),
            (Verification::ChainOnly, fixture_bundle(&dir)),
            (Verification::Full, TrustAnchors::System),
        ];
        for (verification, anchors) in tiers.iter() {
            let config = client_config(&resolved(*verification, anchors.clone()))
                .unwrap_or_else(|err| panic!("{:?} config must build: {}", verification, err));
            assert!(
                !config.crypto_provider().cipher_suites.is_empty(),
                "{:?} config must carry the ring provider's cipher suites",
                verification
            );
        }
    }

    /// `ChainOnly` over the public web PKI is refused at the connector layer.
    ///
    /// That pair would build a verifier over every public webpki root and then
    /// wrap it in `ChainOnlyVerifier`, which maps a name mismatch to `Ok` --
    /// i.e. any publicly issued certificate for any hostname would be accepted,
    /// which is a full MITM. `dsn::resolve` already makes the pair unreachable
    /// from a DSN (PostgreSQL's `sslrootcert=system` implies `verify-full`
    /// rule), so this pins the second half of that defense: a hand-built
    /// `Resolved` cannot fail open either.
    ///
    /// Red if the guard in `client_config` is removed -- the config would build.
    #[test]
    fn chain_only_over_the_public_roots_is_rejected() {
        let err = client_config(&resolved(Verification::ChainOnly, TrustAnchors::System))
            .expect_err("chain-only over the public roots must be a hard error");
        let msg = err.to_string();
        assert!(
            msg.contains("public certificate authorities"),
            "the error must say why the pair is refused: {}",
            msg
        );

        // And the neighboring pairs still build, so this is not asserting that
        // `ChainOnly` or `System` was removed wholesale.
        let dir = tempfile::tempdir().unwrap();
        client_config(&resolved(Verification::ChainOnly, fixture_bundle(&dir)))
            .expect("chain-only over a private bundle must still build");
        client_config(&resolved(Verification::Full, TrustAnchors::System))
            .expect("verify-full over the public roots must still build");
    }

    /// A publicly trusted CA is **not** a trust anchor when a private bundle is
    /// configured. This is the direct regression test for the fail-open the
    /// bundle-augments-the-public-roots model created: with `ChainOnlyVerifier`
    /// skipping the hostname check, any certificate chaining to any public CA
    /// for any hostname satisfied `verify-ca` and the escalated `require`, so a
    /// MITM could complete the handshake and then select
    /// `AuthenticationCleartextPassword` (`tokio-postgres` defaults
    /// `channel_binding` to `Prefer`) and harvest the migration role's
    /// password.
    ///
    /// The assertion is deliberately **structural**, on the anchor set itself:
    /// there is no publicly signed leaf fixture in this repo to verify against
    /// at test time, and fetching one over the network from a unit test is not
    /// an option. Asserting that the bundle store holds exactly the bundle's
    /// anchor -- and that none of them is a webpki root -- catches any
    /// reintroduction of a public-roots seed, which is the only way the
    /// fail-open comes back.
    #[test]
    fn a_private_bundle_replaces_the_public_roots() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = fixture_bundle(&dir);

        let store = root_store(&bundle).expect("the fixture bundle must build a root store");
        assert_eq!(
            store.roots.len(),
            1,
            "a single-certificate bundle must yield exactly one anchor, not the public \
             roots plus one"
        );
        assert_eq!(
            store.roots[0],
            fixture_anchor(),
            "and that anchor must be the bundle's certificate"
        );

        let public_subjects: Vec<&[u8]> = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|anchor| anchor.subject.as_ref())
            .collect();
        assert!(
            !public_subjects.is_empty(),
            "precondition: webpki_roots must be non-empty, or the next assertion is vacuous"
        );
        for anchor in store.roots.iter() {
            assert!(
                !public_subjects.contains(&anchor.subject.as_ref()),
                "no anchor in a private bundle's store may be a public webpki root"
            );
        }

        let system = root_store(&TrustAnchors::System).expect("system anchors must build");
        assert_eq!(
            system.roots.len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "sslrootcert=system is the ONLY way to reach the public web PKI, and it must \
             reach all of it"
        );
    }

    /// A verifier over zero anchors is a configuration bug, not an
    /// accept-nothing store -- and certainly not an accept-anything one.
    #[test]
    fn no_trust_anchors_is_an_error_for_a_verifying_tier() {
        let err = root_store(&TrustAnchors::None)
            .expect_err("a verifying tier with no anchors must be a hard error");
        assert!(err.to_string().contains("no trust anchors"), "got {}", err);

        for verification in [Verification::ChainOnly, Verification::Full].iter() {
            assert!(
                client_config(&resolved(*verification, TrustAnchors::None)).is_err(),
                "{:?} must refuse to build with no trust anchors",
                verification
            );
        }
    }

    #[test]
    fn missing_bundle_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.pem");
        let bundle = TrustAnchors::Bundle(path);

        let err = root_store(&bundle).expect_err("a missing bundle must be a hard error");
        assert!(
            err.to_string().contains("failed to read CA bundle"),
            "got {}",
            err
        );

        // And it must fail through the tiers that consult the root store, not
        // only through `root_store` directly.
        for verification in [Verification::ChainOnly, Verification::Full].iter() {
            assert!(
                client_config(&resolved(*verification, bundle.clone())).is_err(),
                "{:?} must refuse to build with an unreadable CA bundle",
                verification
            );
        }
    }

    #[test]
    fn certless_bundle_is_an_error() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "# no certificates in here at all").unwrap();
        file.flush().unwrap();
        let bundle = TrustAnchors::Bundle(file.path().to_path_buf());

        let err =
            root_store(&bundle).expect_err("a bundle with no certificates must be a hard error");
        assert!(
            err.to_string().contains("contained no certificates"),
            "got {}",
            err
        );

        for verification in [Verification::ChainOnly, Verification::Full].iter() {
            assert!(
                client_config(&resolved(*verification, bundle.clone())).is_err(),
                "{:?} must refuse to build with a certificate-less CA bundle",
                verification
            );
        }
    }

    /// A bundle configured alongside a **genuinely** unverified tier is not
    /// read, so it cannot fail the run.
    ///
    /// After the trust-anchor fix that set is much smaller than it was:
    /// `disable` is the only mode that stays at [`Verification::None`] with a
    /// bundle in play (libpq does no SSL there and never loads the root file),
    /// plus `require` -- and `prefer`, and `allow` -- with **no** bundle at
    /// all. `allow`, `prefer` and `require` *with* a bundle are deliberately
    /// absent: they escalate to [`Verification::ChainOnly`] and the second
    /// half of this test pins that, so this test can never again be satisfied
    /// by the fail-open it used to encode.
    #[test]
    fn unverified_tier_ignores_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.pem");
        let unreadable = TrustAnchors::Bundle(path.clone());

        client_config(&resolved(Verification::None, unreadable))
            .expect("Verification::None must not read the CA bundle");

        // Driven through the real `resolve`, so the set of modes that reach
        // `Verification::None` is asserted, not assumed.
        const BASE: &str = "postgresql://user@db.example.com:5432/app";

        // `disable` is the one mode a configured bundle does not escalate.
        let disabled = dsn::resolve(&format!(
            "{}?sslmode=disable&sslrootcert={}",
            BASE,
            path.display()
        ))
        .unwrap();
        assert_eq!(
            disabled.verification,
            Verification::None,
            "sslmode=disable must stay unverified even with a bundle configured"
        );
        client_config(&disabled).expect("sslmode=disable must not read the CA bundle");

        // And the modes that are unverified only because there is no anchor.
        for mode in ["allow", "prefer", "require"].iter() {
            let unverified = dsn::resolve(&format!("{}?sslmode={}", BASE, mode)).unwrap();
            assert_eq!(
                unverified.verification,
                Verification::None,
                "sslmode={} with no anchor must stay unverified",
                mode
            );
            client_config(&unverified)
                .unwrap_or_else(|err| panic!("sslmode={} must build, got: {}", mode, err));
        }

        // And the case this test used to (wrongly) cover: an unreadable bundle
        // at a verifying tier IS a hard error, for every mode that escalates.
        for mode in ["allow", "prefer", "require", "verify-ca", "verify-full"].iter() {
            let with_bundle = dsn::resolve(&format!(
                "{}?sslmode={}&sslrootcert={}",
                BASE,
                mode,
                path.display()
            ))
            .unwrap();
            assert_ne!(
                with_bundle.verification,
                Verification::None,
                "sslmode={} + sslrootcert must not be an unverified tier",
                mode
            );
            assert!(
                client_config(&with_bundle).is_err(),
                "sslmode={} + an unreadable sslrootcert must fail rather than fail open",
                mode
            );
        }
    }

    /// The `verify-ca` relaxation is narrow: `ChainOnlyVerifier` tolerates a
    /// hostname mismatch and nothing else, so a real certificate that does not
    /// chain to a trust anchor is still rejected.
    ///
    /// Red if `ChainOnlyVerifier::verify_server_cert` were replaced with a bare
    /// `Ok(ServerCertVerified::assertion())` -- i.e. if `verify-ca` silently
    /// degraded to accept-any. Every other test in this crate would stay green.
    ///
    /// The verifier is built from [`TrustAnchors::System`] so the assertion
    /// still means "the fixture CA does not chain to a public root".
    ///
    /// The assertion is deliberately only `is_err()`: the fixture CA's validity
    /// window is not the point, so its eventual expiry (or a not-yet-valid
    /// clock) cannot turn this into a false *pass* -- it stays an error either
    /// way, just for a different reason.
    #[test]
    fn chain_only_verifier_rejects_untrusted_chain() {
        let verifier =
            ChainOnlyVerifier::new(webpki_verifier(&provider(), &TrustAnchors::System).unwrap());
        let der = rustls_pemfile::certs(&mut TEST_CA_PEM.as_bytes())
            .next()
            .expect("fixture must contain a certificate")
            .expect("fixture certificate must parse");

        let result = verifier.verify_server_cert(
            &CertificateDer::from(der.to_vec()),
            &[],
            &ServerName::try_from("db.example.com").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(
            result.is_err(),
            "a cert that does not chain to a webpki root must be rejected even under verify-ca"
        );
    }
}
