//! Minimal CONNECT-IP proxy that accepts one connection and echoes IP packets.
//!
//! Usage: cargo run --example simple_proxy

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use connect_ip::proxy::ConnectIpProxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let bind_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // Generate self-signed cert
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);

    // Save cert for client to use
    std::fs::write("cert.der", cert_der.as_ref())?;
    println!("Certificate written to cert.der");

    // Configure QUIC with datagrams
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key.into())?;
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_config.transport_config(transport);

    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    println!("CONNECT-IP proxy listening on {bind_addr}");

    // Accept one connection
    let incoming = endpoint.accept().await.unwrap();
    let quic_conn = incoming.await?;
    println!("QUIC connection established");

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let mut conn = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_conn)
        .await?;

    // Accept CONNECT-IP request
    if let Some(request) = ConnectIpProxy::accept(&mut conn).await? {
        println!(
            "CONNECT-IP request: target={}, ipproto={}",
            request.target, request.ip_protocol
        );

        let mut session = request.accept(&conn, None).await?;
        println!("Session established — echoing IP packets");

        // Echo loop
        loop {
            match session.recv_ip_packet().await {
                Ok(packet) => {
                    println!("Received {} byte IP packet, echoing back", packet.len());
                    session.send_ip_packet(&packet)?;
                }
                Err(e) => {
                    println!("Session ended: {e}");
                    break;
                }
            }
        }
    }

    Ok(())
}
