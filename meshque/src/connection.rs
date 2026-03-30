use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{error, info, warn};

use connect_ip_rs::capsule::address::{AddressAssign, AssignedAddress};
use connect_ip_rs::capsule::route::{IpAddressRange, RouteAdvertisement};
use connect_ip_rs::client::ConnectIpClient;
use connect_ip_rs::proxy::ConnectIpProxy;
use connect_ip_rs::session::ConnectIpSession;
use connect_ip_rs::types::IpVersion;

use crate::config::{Config, Role};
use crate::nat;
use crate::signaling;
use crate::tun_device;
use crate::tunnel;

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Main entry point — run the connection with reconnection logic.
pub async fn run(cfg: Config) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install crypto provider"))?;

    let mut backoff = INITIAL_BACKOFF;
    let mut attempt = 0u32;

    loop {
        attempt += 1;

        // Generate fresh cert each attempt (ephemeral identity)
        let (cert_der, key_der) = generate_cert()?;
        let fingerprint = cert_fingerprint(&cert_der[0]);
        if attempt == 1 {
            info!(fingerprint = %fingerprint, "Generated ephemeral TLS certificate");
        } else {
            info!(attempt, fingerprint = %fingerprint, "Reconnecting with fresh certificate");
        }

        let result = match &cfg.direct_addr {
            Some(_) => run_direct(&cfg, cert_der, key_der).await,
            None => run_signaled(&cfg, cert_der, key_der, fingerprint).await,
        };

        match result {
            Ok(()) => {
                info!("Connection closed cleanly");
                return Ok(());
            }
            Err(e) => {
                error!(error = %e, attempt, "Connection failed");

                // Check if this is a non-retryable error
                let msg = format!("{e:#}");
                if msg.contains("are you root")
                    || msg.contains("Operation not permitted")
                    || msg.contains("invalid peer address")
                    || msg.contains("room_code required")
                {
                    return Err(e);
                }

                info!(
                    backoff_secs = backoff.as_secs_f32(),
                    "Retrying in {:.0}s...",
                    backoff.as_secs_f32()
                );
                tokio::time::sleep(backoff).await;

                // Exponential backoff: 1, 2, 4, 8, 16, 30, 30, 30...
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Direct connection mode (--direct flag).
async fn run_direct(
    cfg: &Config,
    cert_der: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
) -> Result<()> {
    let listen_addr = cfg.listen_addr;
    match cfg.role {
        Role::Responder => {
            info!(listen = %listen_addr, "Starting as responder (proxy)");
            let socket = std::net::UdpSocket::bind(listen_addr)?;
            run_responder(cfg, cert_der, key_der, socket, None).await
        }
        Role::Initiator => {
            let addr: SocketAddr = cfg
                .direct_addr
                .as_ref()
                .unwrap()
                .parse()
                .context("invalid peer address")?;
            info!(peer = %addr, "Starting as initiator (client)");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
            run_initiator(cfg, cert_der, key_der, socket, addr, None).await
        }
    }
}

/// Signaling server mode — discover peer via signaling + STUN + hole punch.
async fn run_signaled(
    cfg: &Config,
    cert_der: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
    fingerprint: String,
) -> Result<()> {
    let room_code = cfg
        .room_code
        .as_deref()
        .context("room_code required for signaling mode")?;

    // Bind a UDP socket for STUN + QUIC
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
            run_responder(cfg, cert_der, key_der, std_socket, expected_fingerprint).await
        }
        Role::Initiator => {
            run_initiator(
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

fn uuid_simple() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("{now:x}-{pid:x}")
}

// --- Responder (proxy) ---

async fn run_responder(
    cfg: &Config,
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

    // Send ADDRESS_ASSIGN
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

    // Send ROUTE_ADVERTISEMENT
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

    // Create TUN and run tunnel
    run_with_tun(cfg, session, local_addr, peer_addr).await
}

// --- Initiator (client) ---

async fn run_initiator(
    cfg: &Config,
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
    let quic_conn = endpoint
        .connect_with(client_config, peer_addr, "meshque-peer")?
        .await?;
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

    // Receive ADDRESS_ASSIGN
    let capsule = session
        .recv_capsule()
        .await?
        .context("expected ADDRESS_ASSIGN capsule")?;
    let local_addr = match capsule {
        connect_ip_rs::Capsule::AddressAssign(assign) => {
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
        connect_ip_rs::Capsule::RouteAdvertisement(routes) => {
            info!(ranges = routes.ranges.len(), "Received ROUTE_ADVERTISEMENT");
        }
        other => bail!("expected ROUTE_ADVERTISEMENT, got {:?}", other),
    }

    let peer_tun_addr = Ipv4Addr::new(100, 64, 0, 1);

    let result = run_with_tun(cfg, session, local_addr, peer_tun_addr).await;
    driver_handle.abort();
    result
}

/// Create TUN device and run the tunnel loop.
async fn run_with_tun<C>(
    cfg: &Config,
    session: ConnectIpSession<C>,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Result<()>
where
    C: h3::quic::Connection<bytes::Bytes>
        + h3_datagram::quic_traits::DatagramConnectionExt<bytes::Bytes>,
    C::BidiStream: h3::quic::BidiStream<bytes::Bytes>,
    <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer:
        Into<bytes::Bytes>,
{
    let mtu = session.tunnel_mtu().unwrap_or(1400) as u16;
    let tun = tun_device::create_tun(&cfg.tun_name, local_addr, peer_addr, mtu)?;
    tunnel::run_tunnel(session, &tun).await
}

// --- Certificate Verifiers ---

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

#[derive(Debug)]
pub(crate) struct FingerprintVerifier(pub(crate) String);

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
