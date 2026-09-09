//! Custom [`rustls::client::danger::ServerCertVerifier`] implementations for
//! the [`Verification::ChainOnly`] and [`Verification::None`] tiers.
//!
//! Copy of `bdai-platform/libs/pg-tls/src/verifier.rs`; the two must stay
//! behaviourally identical. See `super`'s header for why this is a copy.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};

/// Map a hostname-mismatch rejection to success, leaving every other outcome
/// alone.
///
/// This is the whole of the `verify-ca` relaxation: `WebPkiServerVerifier`
/// validates the chain (and expiry, and revocation when configured) *before*
/// it checks the name, so a `NotValidForName*` error means everything else
/// already passed. Chain, expiry, purpose and revocation errors propagate
/// untouched.
pub(crate) fn allow_hostname_mismatch(
    result: Result<ServerCertVerified, rustls::Error>,
) -> Result<ServerCertVerified, rustls::Error> {
    match result {
        Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        )) => Ok(ServerCertVerified::assertion()),
        other => other,
    }
}

/// Verifies the chain but tolerates a hostname mismatch — libpq `verify-ca`.
#[derive(Debug)]
pub(crate) struct ChainOnlyVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ChainOnlyVerifier {
    pub(crate) fn new(inner: Arc<WebPkiServerVerifier>) -> ChainOnlyVerifier {
        ChainOnlyVerifier { inner }
    }
}

impl ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        allow_hostname_mismatch(self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Accepts any server certificate — encryption without authentication, which
/// is what libpq's `require` (and `prefer`, and `allow`) do.
#[derive(Debug)]
pub(crate) struct AcceptAnyVerifier {
    provider: Arc<CryptoProvider>,
}

impl AcceptAnyVerifier {
    pub(crate) fn new(provider: Arc<CryptoProvider>) -> AcceptAnyVerifier {
        AcceptAnyVerifier { provider }
    }
}

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;

    /// A hostname mismatch is tolerated, everything else is not.
    ///
    /// Exercised through `allow_hostname_mismatch`, which is the exact function
    /// `ChainOnlyVerifier::verify_server_cert` calls — not a copy of its logic.
    #[test]
    fn hostname_mismatch_maps_to_ok() {
        allow_hostname_mismatch(Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName,
        )))
        .expect("NotValidForName must map to Ok");

        allow_hostname_mismatch(Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForNameContext {
                expected: ServerName::try_from("db.example.com").unwrap().to_owned(),
                presented: vec!["CN=other".to_string()],
            },
        )))
        .expect("NotValidForNameContext must map to Ok");
    }

    #[test]
    fn chain_and_expiry_errors_still_propagate() {
        let errors = vec![
            rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
            rustls::Error::InvalidCertificate(CertificateError::Expired),
            rustls::Error::InvalidCertificate(CertificateError::Revoked),
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding),
            rustls::Error::InvalidCertificate(CertificateError::InvalidPurpose),
            rustls::Error::NoCertificatesPresented,
        ];
        for err in errors {
            let mapped = allow_hostname_mismatch(Err(err.clone()));
            assert!(
                mapped.is_err(),
                "{:?} must still be rejected under verify-ca",
                err
            );
        }
    }

    #[test]
    fn success_passes_through() {
        allow_hostname_mismatch(Ok(ServerCertVerified::assertion()))
            .expect("a successful verification must stay successful");
    }
}
