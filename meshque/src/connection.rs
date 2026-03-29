use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{info, warn};

use connect_ip::capsule::address::{AddressAssign, AssignedAddress};
use connect_ip::capsule::route::{IpAddressRange, RouteAdvertisement};
use connect_ip::client::ConnectIpClient;
use connect_ip::proxy::ConnectIpProxy;
use connect_ip::types::IpVersion;

use crate::config::{Config, Role};
use crate::nat;
use crate::signaling;
use crate::tun_device;
use crate::tunnel;

/// Main entry point — run the connection based on config.
pub async fn run(cfg: Config) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install crypto provider"))?;

    // Generate self-signed cert for QUIC/TLS
    let (cert_der, key_der) = generate_cert()?;
    let fingerprint = cert_fingerprint(&cert_der[0]);
    info!(fingerprint = %fingerprint, "Generated ephemeral TLS certificate");

    match &cfg.direct_addr {
        Some(_) => run_direct(cfg, cert_der, key_der).await,
        None => run_signaled(cfg, cert_der, key_der, fingerprint).await,
    }
}

/// Direct connection mode (--direct flag) — no signaling server.
async fn run_direct(
    cfg: Config,
    cert_der: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
) -> Result<()> {
    let listen_addr = cfg.listen_addr;
    match cfg.role {
        Role::Responder => {
            info!(listen = %listen_addr, "Starting as responder (proxy)");
            run_responder(cfg, cert_der, key_der, listen_addr, None).await
        }
        Role::Initiator => {
            let addr: SocketAddr = cfg
                .direct_addr
                .as_ref()
                .unwrap()
                .parse()
                .context("invalid peer address")?;
            info!(peer = %addr, "Starting as initiator (client)");
            run_initiator(cfg, cert_der, key_der, addr, None).await
        }
    }
}

/// Signaling server mode — discover peer via signaling + STUN + hole punch.
async fn run_signaled(
    cfg: Config,
    cert_der: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
    fingerprint: String,
) -> Result<()> {
    let room_code = cfg
        .room_code
        .as_deref()
        .context("room_code required for signaling mode")?;

    // Bind a UDP socket we'll use for both STUN and QUIC
    let socket = tokio::net::UdpSocket::bind(cfg.listen_addr).await?;
    let local_addr = socket.local_addr()?;
    info!(bind = %local_addr, "Bound UDP socket");

    // STUN discovery
    let stun_result = nat::stun_discover(&socket).await?;

    if stun_result.nat_type == nat::NatType::Symmetric {
        warn!("Symmetric NAT detected — hole-punching may fail");
    }

    // Signaling exchange
    let peer_id = uuid_simple();
    let local_peer = signaling::LocalPeer {
        peer_id,
        cert_fingerprint: fingerprint,
    };

    let sig_result = signaling::run_signaling(
        &cfg.signal_server,
        room_code,
        &local_peer,
        stun_result.reflexive_addr,
        stun_result.nat_type.as_str(),
    )
    .await?;

    info!(
        role = ?sig_result.role,
        peer_endpoint = %sig_result.remote.endpoint,
        peer_fingerprint = sig_result.remote.cert_fingerprint,
        "Signaling complete"
    );

    // Hole punch
    nat::hole_punch(&socket, sig_result.remote.endpoint).await?;

    // Convert tokio socket to std for quinn
    let std_socket = socket.into_std()?;

    let expected_fingerprint = Some(sig_result.remote.cert_fingerprint.clone());

    match sig_result.role {
        Role::Responder => {
            run_responder_with_socket(cfg, cert_der, key_der, std_socket, expected_fingerprint)
                .await
        }
        Role::Initiator => {
            run_initiator_with_socket(
                cfg,
                cert_der,
                key_der,
                std_socket,
                sig_result.remote.endpoint,
                expected_fingerprint,
            )
            .await
        }
    }
}

fn generate_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["meshque-peer".into()])?;
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    Ok((vec![cert_der], key.into()))
}

/// Compute SHA-256 fingerprint of a DER-encoded certificate.
fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    let hash = digest::digest(&digest::SHA256, cert.as_ref());
    let hex = hash
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("sha256:{hex}")
}

/// Generate a simple UUID-like ID (no dependency needed).
fn uuid_simple() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("{now:x}-{pid:x}")
}

// --- Responder (proxy) ---

/// Responder with a new endpoint (direct mode).
async fn run_responder(
    cfg: Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    listen_addr: SocketAddr,
    expected_fingerprint: Option<String>,
) -> Result<()> {
    let std_socket = std::net::UdpSocket::bind(listen_addr)?;
    run_responder_with_socket(cfg, certs, key, std_socket, expected_fingerprint).await
}

/// Responder with a pre-bound socket (signaling mode, after hole punch).
async fn run_responder_with_socket(
    cfg: Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    socket: std::net::UdpSocket,
    _expected_fingerprint: Option<String>,
) -> Result<()> {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_config.transport_config(transport);

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        quinn::default_runtime().context("no async runtime")?,
    )?;
    info!(addr = %endpoint.local_addr()?, "QUIC server listening");

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

    let local_addr = Ipv4Addr::new(100, 64, 0, 1);
    let peer_addr = Ipv4Addr::new(100, 64, 0, 2);

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

    let mtu = session.tunnel_mtu().unwrap_or(1400) as u16;
    let tun = tun_device::create_tun(&cfg.tun_name, local_addr, peer_addr, mtu)?;

    tunnel::run_tunnel(session, &tun).await
}

// --- Initiator (client) ---

/// Initiator with a new endpoint (direct mode).
async fn run_initiator(
    cfg: Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    peer_addr: SocketAddr,
    expected_fingerprint: Option<String>,
) -> Result<()> {
    let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    run_initiator_with_socket(cfg, certs, key, std_socket, peer_addr, expected_fingerprint).await
}

/// Initiator with a pre-bound socket (signaling mode, after hole punch).
async fn run_initiator_with_socket(
    cfg: Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    socket: std::net::UdpSocket,
    peer_addr: SocketAddr,
    expected_fingerprint: Option<String>,
) -> Result<()> {
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        if let Some(ref fp) = expected_fingerprint {
            Arc::new(FingerprintVerifier(fp.clone()))
        } else {
            Arc::new(AcceptAnyCert)
        };

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)?;
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(transport);

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        quinn::default_runtime().context("no async runtime")?,
    )?;

    info!(peer = %peer_addr, "Connecting to peer");
    let quic_conn = endpoint.connect_with(client_config, peer_addr, "meshque-peer")?.await?;
    let max_dg = quic_conn.max_datagram_size();
    info!("QUIC connection established");

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let client_session = ConnectIpClient::connect(h3_conn, "*", "*", max_dg).await?;
    info!("CONNECT-IP session established");

    let driver_handle = tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
    });

    let mut session = client_session.session;

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

    let peer_tun_addr = Ipv4Addr::new(100, 64, 0, 1);
    let mtu = session.tunnel_mtu().unwrap_or(1400) as u16;
    let tun = tun_device::create_tun(&cfg.tun_name, local_addr, peer_tun_addr, mtu)?;

    let result = tunnel::run_tunnel(session, &tun).await;
    driver_handle.abort();
    result
}

// --- Certificate Verifiers ---

/// Accept any TLS certificate (direct mode without fingerprint).
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

/// Verify the server's certificate fingerprint matches the expected value from signaling.
#[derive(Debug)]
struct FingerprintVerifier(String);

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual = cert_fingerprint(end_entity);
        if actual == self.0 {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected {}, got {actual}",
                self.0
            )))
        }
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
