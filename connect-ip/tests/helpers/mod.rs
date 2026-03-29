use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Ensure the ring crypto provider is installed (required by rustls 0.23+).
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed certificate for testing.
pub fn generate_test_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    ensure_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    (vec![cert_der], key.into())
}

/// Create a quinn server endpoint on localhost with datagrams enabled.
pub fn make_server_endpoint(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> (quinn::Endpoint, SocketAddr) {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport);

    let endpoint = quinn::Endpoint::server(
        server_config,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();

    let addr = endpoint.local_addr().unwrap();
    (endpoint, addr)
}

/// Create a quinn client endpoint that trusts the given server cert.
pub fn make_client_endpoint(
    server_certs: &[CertificateDer<'static>],
) -> quinn::Endpoint {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let mut roots = rustls::RootCertStore::empty();
    for cert in server_certs {
        roots.add(cert.clone()).unwrap();
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport);

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}
