//! Root store and [`rustls::ClientConfig`] construction.
//!
//! Copy of `bdai-platform/libs/pg-tls/src/tls.rs`; the two must stay
//! behaviourally identical. See `super`'s header for why this is a copy and for
//! the one intentional divergence: the crypto provider here is `ring`, not
//! `aws-lc-rs`, because this binary is built statically against musl in a
//! `FROM scratch` image and `aws-lc-rs` needs cmake/nasm in the builder.

use std::fs::File;
use std::io::BufReader;
use std::iter::FromIterator;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};

use crate::pg_tls::verifier::{AcceptAnyVerifier, ChainOnlyVerifier};
use crate::pg_tls::{Resolved, Verification};

/// The crypto provider is named explicitly rather than resolved from crate
/// features.
///
/// `CryptoProvider::from_crate_features()` returns `None` — and the bare
/// `ClientConfig::builder()` then panics inside its `.expect()` — as soon as
/// two provider features are unified into a build. Naming the provider means
/// that can never happen here, whatever else lands in the dependency graph. Do
/// not reintroduce `ClientConfig::builder()` or
/// `WebPkiServerVerifier::builder()` in this file.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// The public webpki roots, **augmented** with every certificate in
/// `ca_bundle_path` when one is configured.
///
/// An unreadable bundle, or a bundle containing no certificates, is a hard
/// error: silently falling back to public roots only would turn an operator's
/// private-CA configuration into an unverifiable connection.
pub(crate) fn root_store(ca_bundle_path: Option<&Path>) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = ca_bundle_path {
        let file = File::open(path)
            .with_context(|| format!("failed to read CA bundle {}", path.display()))?;
        let mut reader = BufReader::new(file);

        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert =
                cert.with_context(|| format!("failed to read CA bundle {}", path.display()))?;
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
    }

    Ok(roots)
}

/// Build a [`ClientConfig`] for the tier `resolved` asked for.
///
/// The root store — and therefore the CA bundle — is only read for the tiers
/// that consult it. Note that an `sslrootcert` alongside `sslmode=require` is
/// *not* one of the tiers that skips it: [`crate::pg_tls::dsn::resolve`]
/// escalates that combination to [`Verification::ChainOnly`], so the bundle is
/// read and an unreadable one is a hard error.
pub fn client_config(resolved: &Resolved) -> anyhow::Result<ClientConfig> {
    let ca_bundle_path = resolved.ca_bundle_path.as_deref();
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to build TLS client configuration")?;

    let config = match resolved.verification {
        Verification::Full => builder
            .with_webpki_verifier(webpki_verifier(&provider, ca_bundle_path)?)
            .with_no_client_auth(),
        Verification::ChainOnly => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ChainOnlyVerifier::new(webpki_verifier(
                &provider,
                ca_bundle_path,
            )?)))
            .with_no_client_auth(),
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
    ca_bundle_path: Option<&Path>,
) -> anyhow::Result<Arc<WebPkiServerVerifier>> {
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_store(ca_bundle_path)?),
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

    /// A self-signed CA, PEM-encoded — the same fixture as the sibling
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

    fn resolved(verification: Verification, ca_bundle_path: Option<&Path>) -> Resolved {
        Resolved {
            dsn: "postgresql://user@db.example.com/app".to_string(),
            requested: None,
            effective: "require",
            verification,
            ca_bundle_path: ca_bundle_path.map(|p| p.to_path_buf()),
            current_schema: None,
        }
    }

    /// A `ClientConfig` actually builds for every tier. This is the regression
    /// test for the crypto-provider panic — no assertion about mode mapping can
    /// catch it, because the panic happens at construction.
    #[test]
    fn client_config_builds_for_every_tier() {
        let tiers = [
            Verification::None,
            Verification::ChainOnly,
            Verification::Full,
        ];
        for verification in tiers.iter() {
            let config = client_config(&resolved(*verification, None))
                .unwrap_or_else(|err| panic!("{:?} config must build: {}", verification, err));
            assert!(
                !config.crypto_provider().cipher_suites.is_empty(),
                "{:?} config must carry the ring provider's cipher suites",
                verification
            );
        }
    }

    #[test]
    fn missing_bundle_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.pem");

        let err = root_store(Some(&path)).expect_err("a missing bundle must be a hard error");
        assert!(
            err.to_string().contains("failed to read CA bundle"),
            "got {}",
            err
        );

        // And it must fail through the tiers that consult the root store, not
        // only through `root_store` directly.
        for verification in [Verification::ChainOnly, Verification::Full].iter() {
            assert!(
                client_config(&resolved(*verification, Some(&path))).is_err(),
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

        let err = root_store(Some(file.path()))
            .expect_err("a bundle with no certificates must be a hard error");
        assert!(
            err.to_string().contains("contained no certificates"),
            "got {}",
            err
        );

        for verification in [Verification::ChainOnly, Verification::Full].iter() {
            assert!(
                client_config(&resolved(*verification, Some(file.path()))).is_err(),
                "{:?} must refuse to build with a certificate-less CA bundle",
                verification
            );
        }
    }

    /// A bundle configured alongside a **genuinely** unverified tier is not
    /// read, so it cannot fail the run.
    ///
    /// The tiers that qualify are the ones `dsn::resolve` still resolves to
    /// [`Verification::None`] with a bundle in play: `prefer` (and `allow`,
    /// and `disable`), plus `require` with **no** bundle. `require` *with* a
    /// bundle is deliberately absent — it escalates to
    /// [`Verification::ChainOnly`] and the second half of this test pins that,
    /// so this test can never again be satisfied by the fail-open it used to
    /// encode.
    #[test]
    fn unverified_tier_ignores_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.pem");

        client_config(&resolved(Verification::None, Some(&path)))
            .expect("Verification::None must not read the CA bundle");

        // Driven through the real `resolve`, so the set of modes that reach
        // `Verification::None` with a bundle present is asserted, not assumed.
        const BASE: &str = "postgresql://user@db.example.com:5432/app";
        for mode in ["disable", "allow", "prefer"].iter() {
            let unverified = dsn::resolve(&format!(
                "{}?sslmode={}&sslrootcert={}",
                BASE,
                mode,
                path.display()
            ))
            .unwrap();
            assert_eq!(
                unverified.verification,
                Verification::None,
                "sslmode={} must stay unverified",
                mode
            );
            client_config(&unverified).unwrap_or_else(|err| {
                panic!("sslmode={} must not read the CA bundle, got: {}", mode, err)
            });
        }

        // `require` with no bundle at all is the other unverified tier.
        let require_no_bundle = dsn::resolve(&format!("{}?sslmode=require", BASE)).unwrap();
        assert_eq!(require_no_bundle.verification, Verification::None);
        client_config(&require_no_bundle).expect("require with no bundle must build");

        // And the case this test used to (wrongly) cover: `require` + a bundle
        // is a verifying tier, so the unreadable bundle IS a hard error.
        let require_with_bundle = dsn::resolve(&format!(
            "{}?sslmode=require&sslrootcert={}",
            BASE,
            path.display()
        ))
        .unwrap();
        assert_eq!(
            require_with_bundle.verification,
            Verification::ChainOnly,
            "require + sslrootcert must not be an unverified tier"
        );
        assert!(
            client_config(&require_with_bundle).is_err(),
            "require + an unreadable sslrootcert must fail rather than fail open"
        );
    }

    /// The `verify-ca` relaxation is narrow: `ChainOnlyVerifier` tolerates a
    /// hostname mismatch and nothing else, so a real certificate that does not
    /// chain to a trust anchor is still rejected.
    ///
    /// Red if `ChainOnlyVerifier::verify_server_cert` were replaced with a bare
    /// `Ok(ServerCertVerified::assertion())` — i.e. if `verify-ca` silently
    /// degraded to accept-any. Every other test in this crate would stay green.
    ///
    /// The assertion is deliberately only `is_err()`: the fixture CA's validity
    /// window is not the point, so its eventual expiry (or a not-yet-valid
    /// clock) cannot turn this into a false *pass* — it stays an error either
    /// way, just for a different reason.
    #[test]
    fn chain_only_verifier_rejects_untrusted_chain() {
        let verifier = ChainOnlyVerifier::new(webpki_verifier(&provider(), None).unwrap());
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
