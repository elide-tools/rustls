//! External Pre-Shared Key (PSK) support for TLS 1.3.
//!
//! This module provides traits for resolving external PSKs on both the
//! client and server sides of a TLS 1.3 handshake, as specified in
//! [RFC 8446 Section 4.2.11].
//!
//! External PSKs are provisioned out-of-band (not via TLS NewSessionTicket)
//! and use the `"ext binder"` label for binder key derivation, as opposed
//! to the `"res binder"` label used for resumption PSKs.
//!
//! When a PSK resolver is configured and returns a match, external PSK
//! authentication takes priority over ticket-based resumption.
//!
//! [RFC 8446 Section 4.2.11]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11

use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

use crate::enums::CipherSuite;

/// Server-side external PSK resolver.
///
/// Called during TLS 1.3 ClientHello processing when the client offers
/// PSK identities. The server iterates the offered identities and calls
/// [`resolve`](ResolvesServerPsk::resolve) for each one; the first identity
/// that returns `Some` is selected.
///
/// If no identity matches (all return `None`), the server falls back to
/// ticket-based resumption and then to a full handshake.
///
/// # Example
///
/// ```rust,no_run
/// use rustls::psk::ResolvesServerPsk;
///
/// #[derive(Debug)]
/// struct MyPskResolver;
///
/// impl ResolvesServerPsk for MyPskResolver {
///     fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
///         if identity == b"my-client-id" {
///             Some(b"shared-secret-key-bytes".to_vec())
///         } else {
///             None
///         }
///     }
/// }
/// ```
pub trait ResolvesServerPsk: fmt::Debug + Send + Sync {
    /// Given a PSK identity offered by the client, return the corresponding
    /// pre-shared key bytes.
    ///
    /// Return `None` to reject this identity. The server will try the next
    /// offered identity, and if none match, fall back to ticket-based
    /// resumption or a full certificate handshake.
    fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>>;
}

/// Client-side external PSK resolver.
///
/// Called during TLS 1.3 ClientHello construction. If it returns an
/// [`ExternalPsk`], the identity is included in the `pre_shared_key`
/// extension with a binder computed using the `"ext binder"` key.
///
/// If it returns `None`, no external PSK is offered and the client
/// proceeds with normal certificate authentication (or ticket-based
/// resumption if available).
///
/// # Example
///
/// ```rust,no_run
/// use rustls::CipherSuite;
/// use rustls::psk::{ResolvesClientPsk, ExternalPsk};
///
/// #[derive(Debug)]
/// struct MyClientPsk;
///
/// impl ResolvesClientPsk for MyClientPsk {
///     fn resolve(&self, server_name: Option<&str>) -> Option<ExternalPsk> {
///         if server_name == Some("my-server.example.com") {
///             Some(ExternalPsk::new(
///                 b"my-client-id".to_vec(),
///                 b"shared-secret-key-bytes".to_vec(),
///             ))
///         } else {
///             None
///         }
///     }
/// }
/// ```
pub trait ResolvesClientPsk: fmt::Debug + Send + Sync {
    /// Return a PSK identity and secret to offer in the ClientHello.
    ///
    /// `server_name` is the SNI value, if one is being sent.
    ///
    /// Return `None` to skip external PSK and use normal certificate
    /// authentication or ticket-based resumption.
    fn resolve(&self, server_name: Option<&str>) -> Option<ExternalPsk>;
}

/// An external pre-shared key for use with TLS 1.3.
///
/// Each external PSK is associated with a hash algorithm via its
/// [`cipher_suite`](ExternalPsk::cipher_suite) field. The hash algorithm
/// of the cipher suite determines which binder key derivation is used.
/// Any TLS 1.3 cipher suite that shares the same hash algorithm will be
/// compatible with this PSK.
///
/// Per [RFC 8446 Section 4.2.11], the default hash algorithm for externally
/// established PSKs is SHA-256, which corresponds to suites like
/// [`TLS13_AES_128_GCM_SHA256`](CipherSuite::TLS13_AES_128_GCM_SHA256) and
/// [`TLS13_CHACHA20_POLY1305_SHA256`](CipherSuite::TLS13_CHACHA20_POLY1305_SHA256).
///
/// The secret is zeroized on drop.
///
/// [RFC 8446 Section 4.2.11]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
#[non_exhaustive]
pub struct ExternalPsk {
    /// The identity bytes sent to the server. This is opaque to TLS;
    /// the server's [`ResolvesServerPsk`] implementation must understand
    /// the format.
    pub identity: Vec<u8>,

    /// The pre-shared key bytes, zeroized on drop.
    pub(crate) secret: Zeroizing<Vec<u8>>,

    /// The TLS 1.3 cipher suite associated with this PSK, which determines
    /// the hash algorithm used for binder computation.
    ///
    /// Any TLS 1.3 cipher suite using the same hash algorithm will be
    /// compatible. For example, a PSK with
    /// [`TLS13_AES_128_GCM_SHA256`](CipherSuite::TLS13_AES_128_GCM_SHA256)
    /// also works with `TLS13_CHACHA20_POLY1305_SHA256` since both use SHA-256.
    ///
    /// Defaults to [`TLS13_AES_128_GCM_SHA256`](CipherSuite::TLS13_AES_128_GCM_SHA256)
    /// (SHA-256), per [RFC 8446 Section 4.2.11].
    ///
    /// [RFC 8446 Section 4.2.11]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
    pub cipher_suite: CipherSuite,
}

impl ExternalPsk {
    /// Create a new external PSK with the given identity and secret.
    ///
    /// The hash algorithm defaults to SHA-256 (via
    /// [`CipherSuite::TLS13_AES_128_GCM_SHA256`]).
    /// Use [`with_cipher_suite`](Self::with_cipher_suite) to specify a different hash.
    pub fn new(identity: Vec<u8>, secret: Vec<u8>) -> Self {
        Self {
            identity,
            secret: Zeroizing::new(secret),
            cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        }
    }

    /// Set the cipher suite (and thus hash algorithm) for this PSK.
    ///
    /// Use [`CipherSuite::TLS13_AES_256_GCM_SHA384`] for SHA-384.
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

    /// Access the pre-shared key bytes.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl fmt::Debug for ExternalPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalPsk")
            .field("identity", &self.identity)
            .field("secret", &"[redacted]")
            .field("cipher_suite", &self.cipher_suite)
            .finish()
    }
}

/// Return the expected hash output length for a TLS 1.3 cipher suite.
///
/// SHA-384 suites produce 48-byte hashes; all others (SHA-256) produce 32 bytes.
pub(crate) fn expected_hash_len(suite: CipherSuite) -> usize {
    match suite {
        CipherSuite::TLS13_AES_256_GCM_SHA384 => 48,
        _ => 32,
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};

    use super::*;

    #[derive(Debug)]
    struct TestServerPskResolver {
        known_identity: Vec<u8>,
        known_secret: Vec<u8>,
    }

    impl ResolvesServerPsk for TestServerPskResolver {
        fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
            if identity == self.known_identity {
                Some(self.known_secret.clone())
            } else {
                None
            }
        }
    }

    #[derive(Debug)]
    struct TestClientPskResolver {
        identity: Vec<u8>,
        secret: Vec<u8>,
        target_server: Option<String>,
    }

    impl ResolvesClientPsk for TestClientPskResolver {
        fn resolve(&self, server_name: Option<&str>) -> Option<ExternalPsk> {
            match (&self.target_server, server_name) {
                (Some(target), Some(name)) if target == name => Some(ExternalPsk::new(
                    self.identity.clone(),
                    self.secret.clone(),
                )),
                (None, _) => Some(ExternalPsk::new(
                    self.identity.clone(),
                    self.secret.clone(),
                )),
                _ => None,
            }
        }
    }

    #[test]
    fn server_psk_resolver_matches_known_identity() {
        let resolver = TestServerPskResolver {
            known_identity: b"client-id-1".to_vec(),
            known_secret: b"secret-key-1".to_vec(),
        };

        assert_eq!(
            resolver.resolve(b"client-id-1"),
            Some(b"secret-key-1".to_vec())
        );
    }

    #[test]
    fn server_psk_resolver_rejects_unknown_identity() {
        let resolver = TestServerPskResolver {
            known_identity: b"client-id-1".to_vec(),
            known_secret: b"secret-key-1".to_vec(),
        };

        assert_eq!(resolver.resolve(b"unknown-id"), None);
    }

    #[test]
    fn client_psk_resolver_returns_identity_for_matching_server() {
        let resolver = TestClientPskResolver {
            identity: b"my-id".to_vec(),
            secret: b"my-secret".to_vec(),
            target_server: Some("example.com".to_string()),
        };

        let result = resolver.resolve(Some("example.com"));
        assert!(result.is_some());
        let psk = result.unwrap();
        assert_eq!(psk.identity, b"my-id");
        assert_eq!(psk.secret(), b"my-secret");
    }

    #[test]
    fn client_psk_resolver_returns_none_for_wrong_server() {
        let resolver = TestClientPskResolver {
            identity: b"my-id".to_vec(),
            secret: b"my-secret".to_vec(),
            target_server: Some("example.com".to_string()),
        };

        assert!(resolver.resolve(Some("other.com")).is_none());
    }

    #[test]
    fn client_psk_resolver_returns_none_when_no_server_name() {
        let resolver = TestClientPskResolver {
            identity: b"my-id".to_vec(),
            secret: b"my-secret".to_vec(),
            target_server: Some("example.com".to_string()),
        };

        assert!(resolver.resolve(None).is_none());
    }

    #[test]
    fn client_psk_resolver_returns_identity_regardless_of_server() {
        let resolver = TestClientPskResolver {
            identity: b"universal-id".to_vec(),
            secret: b"universal-secret".to_vec(),
            target_server: None,
        };

        assert!(resolver.resolve(Some("any.com")).is_some());
        assert!(resolver.resolve(None).is_some());
    }

    #[test]
    fn external_psk_default_cipher_suite() {
        let psk = ExternalPsk::new(b"id".to_vec(), b"secret".to_vec());
        assert_eq!(psk.cipher_suite, CipherSuite::TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn external_psk_with_cipher_suite() {
        let psk = ExternalPsk::new(b"id".to_vec(), b"secret".to_vec())
            .with_cipher_suite(CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(psk.cipher_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn external_psk_debug_redacts_secret() {
        use alloc::format;
        let psk = ExternalPsk::new(b"id".to_vec(), b"top-secret".to_vec());
        let debug = format!("{:?}", psk);
        assert!(!debug.contains("top-secret"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn expected_hash_len_sha256() {
        assert_eq!(
            expected_hash_len(CipherSuite::TLS13_AES_128_GCM_SHA256),
            32
        );
        assert_eq!(
            expected_hash_len(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
            32
        );
    }

    #[test]
    fn expected_hash_len_sha384() {
        assert_eq!(
            expected_hash_len(CipherSuite::TLS13_AES_256_GCM_SHA384),
            48
        );
    }
}

/// Integration tests for external PSK handshakes.
/// These require `std`, `rcgen`, and a crypto provider.
#[cfg(all(test, feature = "std", any(feature = "ring", feature = "aws_lc_rs")))]
#[macro_rules_attribute::apply(test_for_each_provider)]
mod integration_tests {
    use std::prelude::v1::*;
    use std::vec;

    use pki_types::ServerName;

    use super::*;
    use crate::client::ClientConnection;
    use crate::common_state::HandshakeKind;
    use crate::crypto::CryptoProvider;
    use crate::server::{ServerConfig, ServerConnection};
    use crate::sync::Arc;
    use crate::{ClientConfig, RootCertStore, version};

    #[derive(Debug)]
    struct FixedClientPsk {
        identity: Vec<u8>,
        secret: Vec<u8>,
    }

    impl ResolvesClientPsk for FixedClientPsk {
        fn resolve(&self, _server_name: Option<&str>) -> Option<ExternalPsk> {
            Some(ExternalPsk::new(
                self.identity.clone(),
                self.secret.clone(),
            ))
        }
    }

    #[derive(Debug)]
    struct FixedServerPsk {
        identity: Vec<u8>,
        secret: Vec<u8>,
    }

    impl ResolvesServerPsk for FixedServerPsk {
        fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
            if identity == self.identity {
                Some(self.secret.clone())
            } else {
                None
            }
        }
    }

    fn generate_test_certs() -> (
        Vec<pki_types::CertificateDer<'static>>,
        pki_types::PrivateKeyDer<'static>,
        RootCertStore,
    ) {
        // Create a self-signed CA.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .unwrap();
        let ca_der = pki_types::CertificateDer::from(ca_cert.der().to_vec());

        // Issue an end-entity cert signed by the CA.
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let ee_key = rcgen::KeyPair::generate().unwrap();
        let mut ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        ee_params.is_ca = rcgen::IsCa::NoCa;
        let ee_cert = ee_params
            .signed_by(&ee_key, &issuer)
            .unwrap();

        let ee_cert_der = pki_types::CertificateDer::from(ee_cert.der().to_vec());
        let ee_key_der =
            pki_types::PrivateKeyDer::try_from(ee_key.serialize_der()).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();

        (vec![ee_cert_der], ee_key_der, roots)
    }

    fn do_handshake(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) {
        let mut buf = Vec::new();
        loop {
            // Client -> Server
            if client.wants_write() {
                buf.clear();
                client.write_tls(&mut buf).unwrap();
                server
                    .read_tls(&mut &buf[..])
                    .unwrap();
                server.process_new_packets().unwrap();
            }

            // Server -> Client
            if server.wants_write() {
                buf.clear();
                server.write_tls(&mut buf).unwrap();
                client
                    .read_tls(&mut &buf[..])
                    .unwrap();
                client.process_new_packets().unwrap();
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
    }

    /// Build a CryptoProvider that only has SHA-256-based TLS 1.3 suites.
    /// This ensures the negotiated suite is compatible with the default
    /// PSK hash algorithm (SHA-256).
    fn sha256_provider() -> CryptoProvider {
        let mut provider = provider::default_provider();
        provider.cipher_suites.retain(|cs| {
            cs.tls13()
                .map_or(false, |s| s.common.hash_provider.output_len() == 32)
        });
        provider
    }

    fn make_psk_pair(
        psk_identity: &[u8],
        psk_secret: &[u8],
    ) -> (ClientConnection, ServerConnection) {
        let (certs, key, roots) = generate_test_certs();

        let mut client_config = ClientConfig::builder_with_provider(
            CryptoProvider::from(sha256_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_config.psk_resolver = Some(Arc::new(FixedClientPsk {
            identity: psk_identity.to_vec(),
            secret: psk_secret.to_vec(),
        }));

        let mut server_config = ServerConfig::builder_with_provider(
            CryptoProvider::from(sha256_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        server_config.psk_resolver = Some(Arc::new(FixedServerPsk {
            identity: psk_identity.to_vec(),
            secret: psk_secret.to_vec(),
        }));

        let client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        let server = ServerConnection::new(Arc::new(server_config)).unwrap();

        (client, server)
    }

    /// Test that a full external PSK handshake completes successfully.
    /// This is the critical test: the client must transition to ExpectFinished
    /// (not ExpectCertificate) when the server accepts the external PSK.
    #[test]
    fn external_psk_handshake_completes() {
        let (mut client, mut server) = make_psk_pair(b"test-id", b"test-secret-32-bytes-long-xxxxx");
        do_handshake(&mut client, &mut server);

        // Both sides should report a full handshake (not Resumed).
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));

        // No peer certificates in external PSK mode (no cert exchange).
        assert!(client.peer_certificates().is_none());
    }

    /// Test that mismatched PSK secrets cause the server to abort with
    /// IncorrectBinder (the identity matches but the binder doesn't verify).
    #[test]
    fn mismatched_psk_secret_causes_binder_error() {
        let (certs, key, roots) = generate_test_certs();

        let mut client_config = ClientConfig::builder_with_provider(
            CryptoProvider::from(sha256_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_config.psk_resolver = Some(Arc::new(FixedClientPsk {
            identity: b"test-id".to_vec(),
            secret: b"client-secret-does-not-match!!".to_vec(),
        }));

        let mut server_config = ServerConfig::builder_with_provider(
            CryptoProvider::from(sha256_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        server_config.psk_resolver = Some(Arc::new(FixedServerPsk {
            identity: b"test-id".to_vec(),
            secret: b"server-secret-does-not-match!!".to_vec(),
        }));

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        // The handshake should fail because the binder doesn't verify,
        // and the server sends a DecryptError alert.
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        let result = server.process_new_packets();
        assert!(result.is_err(), "Expected handshake failure due to binder mismatch");
    }

    /// Test that unknown PSK identity causes fallback to full handshake.
    #[test]
    fn unknown_psk_identity_falls_back_to_cert_handshake() {
        let (certs, key, roots) = generate_test_certs();

        let mut client_config = ClientConfig::builder_with_provider(
            CryptoProvider::from(provider::default_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_config.psk_resolver = Some(Arc::new(FixedClientPsk {
            identity: b"unknown-id".to_vec(),
            secret: b"some-secret-32-bytes-long-xxxxx".to_vec(),
        }));

        let mut server_config = ServerConfig::builder_with_provider(
            CryptoProvider::from(provider::default_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        server_config.psk_resolver = Some(Arc::new(FixedServerPsk {
            identity: b"known-id".to_vec(),
            secret: b"some-secret-32-bytes-long-xxxxx".to_vec(),
        }));

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        // Server doesn't recognize the PSK identity, falls back to full cert handshake.
        do_handshake(&mut client, &mut server);

        // Should be a full handshake with certificates.
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        assert!(client.peer_certificates().is_some());
    }

    /// Test that server with no PSK resolver does a normal handshake
    /// even when client offers PSK.
    #[test]
    fn client_psk_ignored_when_server_has_no_resolver() {
        let (certs, key, roots) = generate_test_certs();

        let mut client_config = ClientConfig::builder_with_provider(
            CryptoProvider::from(provider::default_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_config.psk_resolver = Some(Arc::new(FixedClientPsk {
            identity: b"test-id".to_vec(),
            secret: b"test-secret-32-bytes-long-xxxxx".to_vec(),
        }));

        // Server has NO psk_resolver — should ignore PSK and do full handshake.
        let server_config = ServerConfig::builder_with_provider(
            CryptoProvider::from(provider::default_provider()).into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        do_handshake(&mut client, &mut server);

        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        assert!(client.peer_certificates().is_some());
    }
}
