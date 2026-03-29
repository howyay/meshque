//! Minimal CONNECT-IP client that connects to the proxy and sends a test packet.
//!
//! Usage: cargo run --example simple_client
//!
//! Requires simple_proxy to be running and cert.der to exist.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;

use connect_ip::client::ConnectIpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let proxy_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // Load proxy certificate
    let cert_data = std::fs::read("cert.der")?;
    let cert = CertificateDer::from(cert_data);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;

    // Configure QUIC with datagrams
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config.transport_config(transport);

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to proxy
    println!("Connecting to proxy at {proxy_addr}...");
    let quic_conn = endpoint.connect(proxy_addr, "localhost")?.await?;
    println!("QUIC connection established");

    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let mut client_session = ConnectIpClient::connect(h3_conn, "*", "*", None).await?;
    println!("CONNECT-IP session established");

    // Drive h3 connection in background
    tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
    });

    // Send a fake IPv4 packet (20-byte header, all 0x45)
    let test_packet = vec![0x45u8; 20];
    client_session.session.send_ip_packet(&test_packet)?;
    println!("Sent {} byte test packet", test_packet.len());

    // Receive echo
    let echoed = client_session.session.recv_ip_packet().await?;
    println!("Received {} byte echo", echoed.len());
    assert_eq!(echoed.as_ref(), test_packet.as_slice());
    println!("Echo matches — tunnel working!");

    Ok(())
}
