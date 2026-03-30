use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{error, info, warn};

use connect_ip_rs::client::ConnectIpClient;
use connect_ip_rs::proxy::ConnectIpProxy;

use crate::config::MeshConfig;
use crate::nat;
use crate::peer_table::PeerTable;
use crate::signaling::{self, NetworkPeerInfo};
use crate::tun_device;

/// Run the mesh network daemon.
pub async fn run(cfg: MeshConfig) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install crypto provider"))?;

    // Generate ephemeral certificate
    let cert = rcgen::generate_simple_self_signed(vec!["meshque-peer".into()])?;
    let key_bytes = cert.key_pair.serialize_der();
    let cert_der_raw = cert.cert;
    let cert_der = CertificateDer::from(cert_der_raw);
    let fingerprint = cert_fingerprint(&cert_der);
    let peer_id = uuid_simple();

    let certs = vec![cert_der];

    info!(peer_id = %peer_id, fingerprint = %fingerprint, "Generated identity");

    // Join the network
    let (assigned_ip, initial_peers) = signaling::join_network(
        &cfg.signal_server,
        &cfg.network,
        &cfg.token,
        &peer_id,
        &fingerprint,
    )
    .await?;

    let local_ip: Ipv4Addr = assigned_ip.parse().context("invalid assigned IP")?;
    info!(ip = %local_ip, peers = initial_peers.len(), "Joined network '{}'", cfg.network);

    // STUN discovery
    let socket = tokio::net::UdpSocket::bind(&cfg.listen_addr).await?;
    let stun_result = nat::stun_discover(&socket).await?;
    let local_endpoint = stun_result.reflexive_addr;

    // Submit our endpoint
    let peers = signaling::exchange_endpoint(
        &cfg.signal_server,
        &cfg.network,
        &cfg.token,
        &peer_id,
        &local_endpoint.to_string(),
        stun_result.nat_type.as_str(),
    )
    .await?;

    info!(endpoint = %local_endpoint, "Submitted endpoint to signaling");

    // Create TUN device
    let mtu = 1400u16;
    let tun = tun_device::create_tun(&cfg.tun_name, local_ip, Ipv4Addr::new(100, 64, 0, 0), mtu)?;
    let tun = Arc::new(tun);
    info!(tun = cfg.tun_name, ip = %local_ip, "TUN device created");

    // Initialize peer table
    let peer_table = PeerTable::new();

    // Convert the tokio socket to std for quinn
    let std_socket = socket.into_std()?;

    // Set up quinn endpoint that can both listen and connect
    let key_for_server: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_bytes).into();
    let (endpoint, _server_config) = create_dual_endpoint(
        certs.clone(),
        key_for_server,
        std_socket,
    )?;

    // Spawn the TUN read loop — routes outbound packets through peer table
    let pt_for_tun = peer_table.clone();
    let tun_for_read = tun.clone();
    let tun_read_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            match tun_device::read_packet(&tun_for_read, &mut buf).await {
                Ok(n) if n > 0 => {
                    pt_for_tun.route_packet(&buf[..n]).await;
                }
                Ok(_) => {}
                Err(e) => {
                    error!("TUN read error: {e}");
                    break;
                }
            }
        }
    });

    // Spawn acceptor for incoming connections (we are a proxy for higher-IP peers)
    let pt_for_accept = peer_table.clone();
    let tun_for_accept = tun.clone();
    let endpoint_for_accept = endpoint.clone();
    let accept_handle = tokio::spawn(async move {
        loop {
            let incoming = match endpoint_for_accept.accept().await {
                Some(inc) => inc,
                None => break,
            };
            let pt = pt_for_accept.clone();
            let tun = tun_for_accept.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming(incoming, pt, tun).await {
                    warn!("Incoming connection failed: {e}");
                }
            });
        }
    });

    // Connect to all existing peers that have endpoints
    let mut connected_peers: HashSet<String> = HashSet::new();

    // Merge initial_peers and post-exchange peers
    let all_peers = merge_peers(initial_peers, peers);

    for peer_info in &all_peers {
        if should_initiate(local_ip, &peer_info.assigned_ip) {
            if let Some(ref ep) = peer_info.endpoint {
                if let Ok(addr) = ep.parse::<SocketAddr>() {
                    let pip: Ipv4Addr = peer_info.assigned_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let pid = peer_info.peer_id.clone();

                    info!(peer = %pip, endpoint = %addr, "Connecting to peer");
                    let connected = connect_to_peer(
                        endpoint.clone(),
                        addr,
                        &peer_info.cert_fingerprint,
                        pip,
                        &pid,
                        peer_table.clone(),
                        tun.clone(),
                    )
                    .await;
                    if connected {
                        connected_peers.insert(peer_info.peer_id.clone());
                    }
                }
            }
        }
    }

    // Signaling poller — discover new peers every 30s
    let pt_for_poll = peer_table.clone();
    let tun_for_poll = tun.clone();
    let endpoint_for_poll = endpoint.clone();
    let cfg_server = cfg.signal_server.clone();
    let cfg_network = cfg.network.clone();
    let cfg_token = cfg.token.clone();
    let peer_id_for_poll = peer_id.clone();

    let poll_handle = tokio::spawn(async move {
        let mut known_peers = connected_peers;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            match signaling::get_network_peers(
                &cfg_server,
                &cfg_network,
                &cfg_token,
                &peer_id_for_poll,
            )
            .await
            {
                Ok(peers) => {
                    for peer_info in &peers {
                        if known_peers.contains(&peer_info.peer_id) {
                            continue;
                        }
                        if !should_initiate(local_ip, &peer_info.assigned_ip) {
                            continue;
                        }
                        if let Some(ref ep) = peer_info.endpoint {
                            if let Ok(addr) = ep.parse::<SocketAddr>() {
                                let pip: Ipv4Addr = peer_info.assigned_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
                                let pid = peer_info.peer_id.clone();
                                info!(peer = %pip, "New peer discovered, connecting");

                                let connected = connect_to_peer(
                                    endpoint_for_poll.clone(),
                                    addr,
                                    &peer_info.cert_fingerprint,
                                    pip,
                                    &pid,
                                    pt_for_poll.clone(),
                                    tun_for_poll.clone(),
                                )
                                .await;
                                if connected {
                                    known_peers.insert(peer_info.peer_id.clone());
                                }
                            }
                        }
                    }
                }
                Err(e) => warn!("Failed to poll peers: {e}"),
            }
        }
    });

    // Print status
    let connected = peer_table.connected_peers().await;
    info!(
        local_ip = %local_ip,
        connected_peers = connected.len(),
        "Mesh active. Press Ctrl-C to stop."
    );

    // Wait for shutdown
    tokio::select! {
        _ = tun_read_handle => {},
        _ = accept_handle => {},
        _ = poll_handle => {},
    }

    // Cleanup: leave the network
    let _ = signaling::leave_network(&cfg.signal_server, &cfg.network, &cfg.token, &peer_id).await;
    info!("Left network");

    Ok(())
}

/// Determine if we should initiate the connection to a peer.
/// Lower virtual IP = initiator (deterministic, no coordination needed).
fn should_initiate(local_ip: Ipv4Addr, peer_ip_str: &str) -> bool {
    if let Ok(peer_ip) = peer_ip_str.parse::<Ipv4Addr>() {
        local_ip < peer_ip
    } else {
        false
    }
}

/// Connect to a peer as QUIC client, establish CONNECT-IP session, wire into peer table.
async fn connect_to_peer(
    endpoint: quinn::Endpoint,
    peer_addr: SocketAddr,
    expected_fingerprint: &str,
    peer_ip: Ipv4Addr,
    peer_id: &str,
    peer_table: PeerTable,
    tun: Arc<tun_rs::AsyncDevice>,
) -> bool {
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        Arc::new(crate::connection::FingerprintVerifier(expected_fingerprint.to_string()));

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let client_config = match QuicClientConfig::try_from(client_crypto) {
        Ok(c) => {
            let mut cc = quinn::ClientConfig::new(Arc::new(c));
            cc.transport_config(transport);
            cc
        }
        Err(e) => {
            error!(peer = %peer_ip, error = %e, "TLS config failed");
            return false;
        }
    };

    let quic_conn = match endpoint.connect_with(client_config, peer_addr, "meshque-peer") {
        Ok(connecting) => match connecting.await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(peer = %peer_ip, error = %e, "QUIC connection failed");
                return false;
            }
        },
        Err(e) => {
            warn!(peer = %peer_ip, error = %e, "QUIC connect failed");
            return false;
        }
    };

    let max_dg = quic_conn.max_datagram_size();
    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let client_session = match ConnectIpClient::connect(h3_conn, "*", "*", max_dg).await {
        Ok(s) => s,
        Err(e) => {
            warn!(peer = %peer_ip, error = %e, "CONNECT-IP handshake failed");
            return false;
        }
    };

    // Split session into parts for concurrent I/O
    let parts = client_session.session.into_parts();

    // Register sender in peer table
    let sender = PeerTable::make_sender(parts.datagram_send);
    peer_table.insert(peer_ip, peer_id.to_string(), sender).await;

    // Spawn receiver task — incoming packets from this peer go to TUN
    let pt = peer_table.clone();
    tokio::spawn(async move {
        let mut recv = parts.datagram_recv;
        loop {
            match recv.recv_ip_packet().await {
                Ok(packet) => {
                    if let Err(e) = tun_device::write_packet(&tun, &packet).await {
                        error!(peer = %peer_ip, error = %e, "TUN write error");
                    }
                }
                Err(e) => {
                    warn!(peer = %peer_ip, error = %e, "Peer tunnel recv error");
                    pt.remove(&peer_ip).await;
                    break;
                }
            }
        }
    });

    // Drive h3 in background
    tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
    });

    info!(peer = %peer_ip, "Connected to peer");
    true
}

/// Handle an incoming QUIC connection (we are the proxy/responder).
async fn handle_incoming(
    incoming: quinn::Incoming,
    peer_table: PeerTable,
    tun: Arc<tun_rs::AsyncDevice>,
) -> Result<()> {
    let quic_conn = incoming.await?;
    let max_dg = quic_conn.max_datagram_size();
    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let mut conn = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_conn)
        .await?;

    let request = ConnectIpProxy::accept(&mut conn)
        .await?
        .context("connection closed before CONNECT-IP request")?;

    let session = request.accept(&conn, max_dg).await?;
    let parts = session.into_parts();

    // For incoming connections, we learn the peer IP from the first packet's source address.
    // We hold the sender in an Option so we can move it into the peer table once we know the IP.
    let sender = Some(parts.datagram_send);
    let sender = Arc::new(tokio::sync::Mutex::new(sender));

    let pt = peer_table.clone();
    let sender_for_task = sender.clone();
    tokio::spawn(async move {
        let mut recv = parts.datagram_recv;
        let mut peer_ip: Option<Ipv4Addr> = None;

        loop {
            match recv.recv_ip_packet().await {
                Ok(packet) => {
                    if packet.len() >= 20 {
                        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

                        if peer_ip.is_none() {
                            peer_ip = Some(src_ip);
                            // Register the sender now that we know the peer's IP
                            let mut guard = sender_for_task.lock().await;
                            if let Some(s) = guard.take() {
                                pt.insert(src_ip, format!("incoming-{src_ip}"), s).await;
                                info!(peer = %src_ip, "Incoming peer registered");
                            }
                        }

                        if let Err(e) = tun_device::write_packet(&tun, &packet).await {
                            error!(peer = %src_ip, error = %e, "TUN write error");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Incoming peer tunnel recv error");
                    if let Some(ip) = peer_ip {
                        pt.remove(&ip).await;
                    }
                    break;
                }
            }
        }
    });

    Ok(())
}

fn create_dual_endpoint(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    socket: std::net::UdpSocket,
) -> Result<(quinn::Endpoint, quinn::ServerConfig)> {
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
        Some(server_config.clone()),
        socket,
        quinn::default_runtime().context("no async runtime")?,
    )?;

    Ok((endpoint, server_config))
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

/// Merge two peer lists, deduplicating by peer_id and preferring the entry with an endpoint.
fn merge_peers(a: Vec<NetworkPeerInfo>, b: Vec<NetworkPeerInfo>) -> Vec<NetworkPeerInfo> {
    let mut map = std::collections::HashMap::new();
    for p in a {
        map.insert(p.peer_id.clone(), p);
    }
    for p in b {
        let entry = map.entry(p.peer_id.clone()).or_insert(p.clone());
        if entry.endpoint.is_none() && p.endpoint.is_some() {
            *entry = p;
        }
    }
    map.into_values().collect()
}
