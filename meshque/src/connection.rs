use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::info;

use connect_ip::capsule::address::{AddressAssign, AssignedAddress};
use connect_ip::capsule::route::{IpAddressRange, RouteAdvertisement};
use connect_ip::client::ConnectIpClient;
use connect_ip::proxy::ConnectIpProxy;
use connect_ip::types::IpVersion;

use crate::config::{Config, Role};
use crate::tun_device;
use crate::tunnel;

/// Main entry point — run the connection based on config.
pub async fn run(cfg: Config) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install crypto provider"))?;

    // Generate self-signed cert for QUIC/TLS
    let (cert_der, key_der) = generate_cert()?;
    info!("Generated ephemeral TLS certificate");

    match (&cfg.direct_addr, cfg.role) {
        (Some(_), Role::Responder) => {
            let listen_addr = cfg.listen_addr;
            info!(listen = %listen_addr, "Starting as responder (proxy)");
            run_responder(cfg, cert_der, key_der, listen_addr).await
        }
        (Some(addr), Role::Initiator) => {
            let peer_addr: SocketAddr = addr
                .parse()
                .with_context(|| format!("invalid peer address: {addr}"))?;
            info!(peer = %peer_addr, "Starting as initiator (client)");
            run_initiator(cfg, cert_der, key_der, peer_addr).await
        }
        (None, _) => {
            bail!("Signaling server mode not yet implemented. Use --direct <addr> for now.")
        }
    }
}

fn generate_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["meshque-peer".into()])?;
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    Ok((vec![cert_der], key.into()))
}

/// Responder (proxy) mode: listen for incoming QUIC connection, accept CONNECT-IP session.
async fn run_responder(
    cfg: Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    listen_addr: SocketAddr,
) -> Result<()> {
    // Configure QUIC server
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_config.transport_config(transport);

    let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;
    info!(addr = %endpoint.local_addr()?, "QUIC server listening");

    // Accept one connection
    let incoming = endpoint
        .accept()
        .await
        .context("no incoming connection")?;
    let quic_conn = incoming.await?;
    let max_dg = quic_conn.max_datagram_size();
    info!("QUIC connection established");

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let mut conn = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_conn)
        .await?;

    // Accept CONNECT-IP request
    let request = ConnectIpProxy::accept(&mut conn)
        .await?
        .context("connection closed before CONNECT-IP request")?;
    info!(
        target = request.target,
        ip_protocol = request.ip_protocol,
        "CONNECT-IP request received"
    );

    let mut session = request.accept(&conn, max_dg).await?;
    info!("CONNECT-IP session established");

    // Responder is 100.64.0.1, assigns 100.64.0.2 to client
    let local_addr = Ipv4Addr::new(100, 64, 0, 1);
    let peer_addr = Ipv4Addr::new(100, 64, 0, 2);

    // Send ADDRESS_ASSIGN to client
    let assign = AddressAssign {
        addresses: vec![AssignedAddress {
            request_id: 0,
            ip_version: IpVersion::V4,
            address: peer_addr.into(),
            prefix_length: 32,
        }],
    };
    session.send_address_assign(&assign).await?;
    info!(assigned = %peer_addr, "Sent ADDRESS_ASSIGN to peer");

    // Send ROUTE_ADVERTISEMENT — all traffic via tunnel
    let routes = RouteAdvertisement {
        ranges: vec![IpAddressRange {
            ip_version: IpVersion::V4,
            start: Ipv4Addr::new(100, 64, 0, 0).into(),
            end: Ipv4Addr::new(100, 64, 0, 255).into(),
            ip_protocol: 0,
        }],
    };
    session.send_route_advertisement(&routes).await?;
    info!("Sent ROUTE_ADVERTISEMENT");

    // Create TUN device
    let mtu = session.tunnel_mtu().unwrap_or(1400) as u16;
    let tun = tun_device::create_tun(&cfg.tun_name, local_addr, peer_addr, mtu)?;

    // Run tunnel
    tunnel::run_tunnel(session, &tun).await
}

/// Initiator (client) mode: connect to peer's QUIC server, establish CONNECT-IP session.
async fn run_initiator(
    cfg: Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Configure QUIC client — trust any cert for now (MVP)
    // In production, we'd pin to the cert fingerprint from signaling
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_client_auth_cert(certs, key)?;
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(transport);

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    info!(peer = %peer_addr, "Connecting to peer");
    let quic_conn = endpoint.connect(peer_addr, "meshque-peer")?.await?;
    let max_dg = quic_conn.max_datagram_size();
    info!("QUIC connection established");

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let client_session =
        ConnectIpClient::connect(h3_conn, "*", "*", max_dg).await?;
    info!("CONNECT-IP session established");

    // Drive h3 connection in background
    let driver_handle = tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
    });

    let mut session = client_session.session;

    // Receive ADDRESS_ASSIGN from responder
    let capsule = session
        .recv_capsule()
        .await?
        .context("expected ADDRESS_ASSIGN capsule")?;
    let local_addr = match capsule {
        connect_ip::Capsule::AddressAssign(assign) => {
            let addr = assign
                .addresses
                .first()
                .context("empty ADDRESS_ASSIGN")?;
            match addr.address {
                std::net::IpAddr::V4(v4) => v4,
                _ => bail!("expected IPv4 address in ADDRESS_ASSIGN"),
            }
        }
        other => bail!("expected ADDRESS_ASSIGN, got {:?}", other),
    };
    info!(address = %local_addr, "Received ADDRESS_ASSIGN");

    // Receive ROUTE_ADVERTISEMENT
    let capsule = session
        .recv_capsule()
        .await?
        .context("expected ROUTE_ADVERTISEMENT capsule")?;
    match capsule {
        connect_ip::Capsule::RouteAdvertisement(routes) => {
            info!(
                ranges = routes.ranges.len(),
                "Received ROUTE_ADVERTISEMENT"
            );
        }
        other => bail!("expected ROUTE_ADVERTISEMENT, got {:?}", other),
    }

    // Peer (responder) is 100.64.0.1
    let peer_tun_addr = Ipv4Addr::new(100, 64, 0, 1);

    // Create TUN device
    let mtu = session.tunnel_mtu().unwrap_or(1400) as u16;
    let tun = tun_device::create_tun(&cfg.tun_name, local_addr, peer_tun_addr, mtu)?;

    // Run tunnel
    let result = tunnel::run_tunnel(session, &tun).await;

    driver_handle.abort();
    result
}

/// Accept any TLS certificate (MVP — in production, pin to fingerprint from signaling).
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
