use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{error, info, warn};

use connect_ip_rs::client::ConnectIpClient;
use connect_ip_rs::proxy::ConnectIpProxy;

use crate::config::MeshConfig;
use crate::identity;
use crate::nat;
use crate::peer_table::PeerTable;
use crate::signaling::{self, NetworkPeerInfo};
use crate::tun_device;

type ConnectedPeers = Arc<tokio::sync::RwLock<HashSet<String>>>;

struct BackoffTracker {
    attempts: HashMap<String, (u32, Instant)>,
}

impl BackoffTracker {
    fn new() -> Self {
        Self { attempts: HashMap::new() }
    }

    fn should_retry(&self, peer_id: &str) -> bool {
        match self.attempts.get(peer_id) {
            None => true,
            Some((count, last_attempt)) => {
                let delay = Duration::from_secs(2u64.pow((*count).min(6)));
                last_attempt.elapsed() >= delay
            }
        }
    }

    fn record_failure(&mut self, peer_id: &str) {
        let entry = self.attempts.entry(peer_id.to_string()).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    fn record_success(&mut self, peer_id: &str) {
        self.attempts.remove(peer_id);
    }
}

/// Run the mesh network daemon.
pub async fn run(cfg: MeshConfig) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install crypto provider"))?;

    let identity = identity::load_or_create_identity(cfg.identity_file.as_deref())?;
    let fingerprint = identity.fingerprint.clone();
    let peer_id = identity.peer_id.clone();

    let certs = vec![identity.certificate()];

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

    // Endpoint discovery: use override if provided, otherwise STUN
    let socket = tokio::net::UdpSocket::bind(&cfg.listen_addr).await?;
    let (local_endpoint, nat_type_str) = if let Some(override_ep) = cfg.advertise_endpoint {
        info!(endpoint = %override_ep, "Using advertised endpoint override");
        (override_ep, "unknown")
    } else {
        let stun_result = nat::stun_discover(&socket).await?;
        (stun_result.reflexive_addr, stun_result.nat_type.as_str())
    };

    // Submit our endpoint
    let peers = signaling::exchange_endpoint(
        &cfg.signal_server,
        &cfg.network,
        &cfg.token,
        &peer_id,
        &local_endpoint.to_string(),
        nat_type_str,
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
    let key_for_server: PrivateKeyDer<'static> = identity.private_key();
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

    let connected_peers: ConnectedPeers = Arc::new(tokio::sync::RwLock::new(HashSet::new()));

    // Connect to all existing peers that have endpoints
    let all_peers = merge_peers(initial_peers, peers);

    for peer_info in &all_peers {
        if should_initiate(local_ip, &peer_info.assigned_ip) {
            if let Some(ref ep) = peer_info.endpoint {
                if let Ok(addr) = ep.parse::<SocketAddr>() {
                    let pip: Ipv4Addr = peer_info.assigned_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
                    info!(peer = %pip, endpoint = %addr, "Connecting to peer");
                    let connected = connect_to_peer(
                        endpoint.clone(),
                        addr,
                        &peer_info.cert_fingerprint,
                        pip,
                        &peer_info.peer_id,
                        peer_table.clone(),
                        tun.clone(),
                        connected_peers.clone(),
                    )
                    .await;
                    if connected {
                        connected_peers.write().await.insert(peer_info.peer_id.clone());
                    }
                }
            }
        }
    }

    // Signaling poller — discovers new peers, reconnects dropped peers
    let pt_for_poll = peer_table.clone();
    let tun_for_poll = tun.clone();
    let endpoint_for_poll = endpoint.clone();
    let cfg_server = cfg.signal_server.clone();
    let cfg_network = cfg.network.clone();
    let cfg_token = cfg.token.clone();
    let peer_id_for_poll = peer_id.clone();
    let cp_for_poll = connected_peers.clone();

    let poll_handle = tokio::spawn(async move {
        let start = Instant::now();
        let mut backoff = BackoffTracker::new();

        loop {
            let interval = if start.elapsed() < Duration::from_secs(60) {
                Duration::from_secs(2)
            } else {
                Duration::from_secs(30)
            };
            tokio::time::sleep(interval).await;

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
                        if cp_for_poll.read().await.contains(&peer_info.peer_id) {
                            continue;
                        }
                        if !should_initiate(local_ip, &peer_info.assigned_ip) {
                            continue;
                        }
                        if !backoff.should_retry(&peer_info.peer_id) {
                            continue;
                        }
                        if let Some(ref ep) = peer_info.endpoint {
                            if let Ok(addr) = ep.parse::<SocketAddr>() {
                                let pip: Ipv4Addr = peer_info.assigned_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
                                info!(peer = %pip, "Connecting to peer");

                                let connected = connect_to_peer(
                                    endpoint_for_poll.clone(),
                                    addr,
                                    &peer_info.cert_fingerprint,
                                    pip,
                                    &peer_info.peer_id,
                                    pt_for_poll.clone(),
                                    tun_for_poll.clone(),
                                    cp_for_poll.clone(),
                                )
                                .await;
                                if connected {
                                    cp_for_poll.write().await.insert(peer_info.peer_id.clone());
                                    backoff.record_success(&peer_info.peer_id);
                                } else {
                                    backoff.record_failure(&peer_info.peer_id);
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
    connected_peers: ConnectedPeers,
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
    let generation = peer_table.insert(peer_ip, peer_id.to_string(), sender).await;

    let pt = peer_table.clone();
    let cp = connected_peers;
    let pid = peer_id.to_string();
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
                    if pt.remove_if_generation(&peer_ip, generation).await {
                        warn!(peer = %peer_ip, error = %e, "Peer disconnected, will reconnect");
                        cp.write().await.remove(&pid);
                    } else {
                        tracing::debug!(peer = %peer_ip, error = %e, "Stale peer tunnel closed");
                    }
                    break;
                }
            }
        }
    });

    // Drive h3 in background.
    // IMPORTANT: send_request must be kept alive — dropping it closes the h3 connection.
    let send_request_handle = client_session.send_request;
    tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
        drop(send_request_handle);
    });

    info!(peer = %peer_ip, "Connected to peer");
    true
}

/// Handle an incoming QUIC connection (we are the proxy/responder).
/// IMPORTANT: This function must keep the h3 server connection alive for the
/// lifetime of the session. Dropping `conn` sends H3_NO_ERROR and kills the tunnel.
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
    info!("Accepted incoming CONNECT-IP session");

    let parts = session.into_parts();

    // Hold the sender in an Arc<Mutex<Option>> so the recv task can register it
    // once we learn the peer's IP from the first packet.
    let sender = Arc::new(tokio::sync::Mutex::new(Some(parts.datagram_send)));

    let pt = peer_table.clone();
    let sender_for_task = sender.clone();

    // Spawn the recv + TUN write loop. This task runs until the tunnel closes.
    let recv_handle = tokio::spawn(async move {
        let mut recv = parts.datagram_recv;
        let mut registered_peer: Option<(Ipv4Addr, u64)> = None;

        loop {
            match recv.recv_ip_packet().await {
                Ok(packet) => {
                    if packet.len() >= 20 {
                        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

                        if registered_peer.is_none() {
                            let mut guard = sender_for_task.lock().await;
                            if let Some(s) = guard.take() {
                                let generation = pt.insert(src_ip, format!("incoming-{src_ip}"), s).await;
                                registered_peer = Some((src_ip, generation));
                                info!(peer = %src_ip, "Incoming peer registered in routing table");
                            }
                        }

                        if let Err(e) = tun_device::write_packet(&tun, &packet).await {
                            error!(peer = %src_ip, error = %e, "TUN write error");
                        }
                    }
                }
                Err(e) => {
                    if let Some((ip, generation)) = registered_peer {
                        if pt.remove_if_generation(&ip, generation).await {
                            warn!(peer = %ip, error = %e, "Incoming peer tunnel recv error");
                        } else {
                            tracing::debug!(peer = %ip, error = %e, "Stale incoming peer tunnel closed");
                        }
                    } else {
                        warn!(error = %e, "Incoming peer tunnel recv error");
                    }
                    break;
                }
            }
        }
    });

    // Keep the h3 server connection alive by waiting for the recv task to finish.
    // If we return early, `conn` is dropped → H3_NO_ERROR → tunnel dies.
    recv_handle.await.ok();

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
