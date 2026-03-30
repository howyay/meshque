//! Integration tests for the meshque connection flow.
//! Tests the protocol handshake (QUIC → H3 → CONNECT-IP → capsule exchange)
//! without requiring root or TUN devices.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use connect_ip_rs::capsule::address::{AddressAssign, AssignedAddress};
use connect_ip_rs::capsule::route::{IpAddressRange, RouteAdvertisement};
use connect_ip_rs::client::ConnectIpClient;
use connect_ip_rs::proxy::ConnectIpProxy;
use connect_ip_rs::session::Capsule;
use connect_ip_rs::types::IpVersion;

fn setup_crypto() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

fn generate_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["meshque-peer".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    (vec![cert_der], key.into())
}

fn make_server_endpoint(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> (quinn::Endpoint, SocketAddr) {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport);

    let endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    (endpoint, addr)
}

fn make_client_endpoint() -> quinn::Endpoint {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    // Accept any cert (MVP)
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport);

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Full connection flow: responder assigns address + routes, initiator receives them,
/// then both exchange IP packets via datagrams (no TUN involved).
#[tokio::test]
async fn full_handshake_and_packet_exchange() {
    setup_crypto();
    let (certs, key) = generate_cert();
    let (server_ep, server_addr) = make_server_endpoint(certs, key);
    let client_ep = make_client_endpoint();

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    // Responder side
    let responder = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let max_dg = quic_conn.max_datagram_size();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let mut session = request.accept(&conn, max_dg).await.unwrap();

        // Send ADDRESS_ASSIGN
        let assign = AddressAssign {
            addresses: vec![AssignedAddress {
                request_id: 0,
                ip_version: IpVersion::V4,
                address: Ipv4Addr::new(100, 64, 0, 2).into(),
                prefix_length: 32,
            }],
        };
        session.send_address_assign(&assign).await.unwrap();

        // Send ROUTE_ADVERTISEMENT
        let routes = RouteAdvertisement {
            ranges: vec![IpAddressRange {
                ip_version: IpVersion::V4,
                start: Ipv4Addr::new(100, 64, 0, 0).into(),
                end: Ipv4Addr::new(100, 64, 0, 255).into(),
                ip_protocol: 0,
            }],
        };
        session.send_route_advertisement(&routes).await.unwrap();

        // Echo 5 packets
        for _ in 0..5 {
            let pkt = session.recv_ip_packet().await.unwrap();
            session.send_ip_packet(&pkt).unwrap();
        }

        let _ = done_rx.await;
    });

    // Initiator side
    let quic_conn = client_ep
        .connect(server_addr, "meshque-peer")
        .unwrap()
        .await
        .unwrap();
    let max_dg = quic_conn.max_datagram_size();
    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let client_session =
        ConnectIpClient::connect(h3_conn, "*", "*", max_dg).await.unwrap();

    let driver = tokio::spawn(async move {
        let mut d = client_session.driver;
        d.wait_idle().await;
    });

    let mut session = client_session.session;

    // Receive ADDRESS_ASSIGN
    let capsule = session.recv_capsule().await.unwrap().unwrap();
    match &capsule {
        Capsule::AddressAssign(a) => {
            assert_eq!(a.addresses.len(), 1);
            assert_eq!(a.addresses[0].address, std::net::IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)));
        }
        other => panic!("expected AddressAssign, got {:?}", other),
    }

    // Receive ROUTE_ADVERTISEMENT
    let capsule = session.recv_capsule().await.unwrap().unwrap();
    match &capsule {
        Capsule::RouteAdvertisement(r) => {
            assert_eq!(r.ranges.len(), 1);
        }
        other => panic!("expected RouteAdvertisement, got {:?}", other),
    }

    // Send 5 packets, verify echoes
    for i in 0u8..5 {
        let mut pkt = vec![0x45u8; 20]; // minimal IPv4 header
        pkt[3] = 20; // total length
        pkt[8] = 64; // TTL
        pkt[1] = i; // vary payload
        session.send_ip_packet(&pkt).unwrap();

        let echo = session.recv_ip_packet().await.unwrap();
        assert_eq!(echo.as_ref(), pkt.as_slice());
    }

    let _ = done_tx.send(());
    responder.await.unwrap();
    driver.abort();
}

/// Test that tunnel_mtu() returns a reasonable value.
#[tokio::test]
async fn mtu_is_reasonable() {
    setup_crypto();
    let (certs, key) = generate_cert();
    let (server_ep, server_addr) = make_server_endpoint(certs, key);
    let client_ep = make_client_endpoint();

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let responder = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let max_dg = quic_conn.max_datagram_size();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let session = request.accept(&conn, max_dg).await.unwrap();

        let mtu = session.tunnel_mtu();
        assert!(mtu.is_some(), "MTU should be available");
        let mtu = mtu.unwrap();
        // QUIC datagrams on localhost are typically ~1200 bytes
        // After H3 + context ID overhead, tunnel MTU should be > 1000
        assert!(mtu > 1000, "MTU {} is too low", mtu);
        assert!(mtu < 65535, "MTU {} is too high", mtu);

        let _ = done_rx.await;
    });

    let quic_conn = client_ep
        .connect(server_addr, "meshque-peer")
        .unwrap()
        .await
        .unwrap();
    let max_dg = quic_conn.max_datagram_size();
    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let client_session =
        ConnectIpClient::connect(h3_conn, "*", "*", max_dg).await.unwrap();

    let mtu = client_session.session.tunnel_mtu();
    assert!(mtu.is_some());
    let mtu = mtu.unwrap();
    assert!(mtu > 1000, "client MTU {} is too low", mtu);

    let _ = done_tx.send(());
    responder.await.unwrap();
}

/// Test concurrent capsule + datagram I/O via into_parts().
/// Responder sends capsule AND packet, initiator receives both via select!.
#[tokio::test]
async fn concurrent_capsule_and_datagram() {
    setup_crypto();
    let (certs, key) = generate_cert();
    let (server_ep, server_addr) = make_server_endpoint(certs, key);
    let client_ep = make_client_endpoint();

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let responder = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let session = request.accept(&conn, None).await.unwrap();
        let mut parts = session.into_parts();

        // Send capsule and packet "simultaneously"
        let routes = RouteAdvertisement {
            ranges: vec![IpAddressRange {
                ip_version: IpVersion::V4,
                start: Ipv4Addr::new(10, 0, 0, 0).into(),
                end: Ipv4Addr::new(10, 0, 0, 255).into(),
                ip_protocol: 0,
            }],
        };
        parts.capsule_send.send_route_advertisement(&routes).await.unwrap();
        parts.datagram_send.send_ip_packet(&[0x45u8; 20]).unwrap();

        let _ = done_rx.await;
    });

    let quic_conn = client_ep
        .connect(server_addr, "meshque-peer")
        .unwrap()
        .await
        .unwrap();
    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let client_session =
        ConnectIpClient::connect(h3_conn, "*", "*", None).await.unwrap();

    let driver = tokio::spawn(async move {
        let mut d = client_session.driver;
        d.wait_idle().await;
    });

    let mut parts = client_session.session.into_parts();

    let mut got_capsule = false;
    let mut got_packet = false;

    for _ in 0..2 {
        tokio::select! {
            result = parts.datagram_recv.recv_ip_packet() => {
                let pkt = result.unwrap();
                assert_eq!(pkt.len(), 20);
                got_packet = true;
            }
            result = parts.capsule_recv.recv_capsule() => {
                let cap = result.unwrap().unwrap();
                assert!(matches!(cap, Capsule::RouteAdvertisement(_)));
                got_capsule = true;
            }
        }
    }

    assert!(got_capsule && got_packet, "should receive both capsule and packet");

    let _ = done_tx.send(());
    responder.await.unwrap();
    driver.abort();
}

/// Verify session.close() sends FIN gracefully.
#[tokio::test]
async fn session_close_is_graceful() {
    setup_crypto();
    let (certs, key) = generate_cert();
    let (server_ep, server_addr) = make_server_endpoint(certs, key);
    let client_ep = make_client_endpoint();

    let responder = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let mut session = request.accept(&conn, None).await.unwrap();

        // Try to receive capsule — should get None when client closes
        let result = session.recv_capsule().await;
        match result {
            Ok(None) => {} // expected: stream finished
            Ok(Some(_)) => panic!("unexpected capsule"),
            Err(_) => {} // also acceptable: stream error on close
        }
    });

    let quic_conn = client_ep
        .connect(server_addr, "meshque-peer")
        .unwrap()
        .await
        .unwrap();
    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let client_session =
        ConnectIpClient::connect(h3_conn, "*", "*", None).await.unwrap();

    let driver = tokio::spawn(async move {
        let mut d = client_session.driver;
        d.wait_idle().await;
    });

    // Close session explicitly
    client_session.session.close().await.unwrap();

    responder.await.unwrap();
    driver.abort();
}

// ─── Helper: accept-any-cert verifier ───────────────────────────────

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>, _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
