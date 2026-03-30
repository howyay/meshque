use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

// ═══════════════════════════════════════════════════════════════════════
// Phase 2: Mesh network signaling
// ═══════════════════════════════════════════════════════════════════════

/// Peer info from the network signaling API.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPeerInfo {
    pub peer_id: String,
    pub assigned_ip: String,
    pub cert_fingerprint: String,
    pub endpoint: Option<String>,
    pub nat_type: Option<String>,
}

#[derive(Deserialize)]
struct NetworkJoinResponse {
    status: String,
    assigned_ip: Option<String>,
    peers: Option<Vec<NetworkPeerInfo>>,
    message: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct NetworkExchangeResponse {
    status: String,
    peers: Option<Vec<NetworkPeerInfo>>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct NetworkPeersResponse {
    status: String,
    assigned_ip: Option<String>,
    peers: Option<Vec<NetworkPeerInfo>>,
    message: Option<String>,
}

/// Join a mesh network. Returns (assigned_ip, list of existing peers).
pub async fn join_network(
    server_url: &str,
    network: &str,
    token: &str,
    peer_id: &str,
    cert_fingerprint: &str,
) -> Result<(String, Vec<NetworkPeerInfo>)> {
    let client = reqwest::Client::new();
    let base = server_url.trim_end_matches('/');

    let res: NetworkJoinResponse = client
        .post(format!("{base}/api/networks/join"))
        .json(&serde_json::json!({
            "network": network,
            "token": token,
            "peer_id": peer_id,
            "cert_fingerprint": cert_fingerprint,
        }))
        .send()
        .await
        .context("failed to reach signaling server")?
        .json()
        .await?;

    if res.status != "joined" {
        bail!(
            "failed to join network: {}",
            res.message.unwrap_or_else(|| res.status)
        );
    }

    let ip = res.assigned_ip.context("no assigned_ip in join response")?;
    let peers = res.peers.unwrap_or_default();
    Ok((ip, peers))
}

/// Submit our STUN-discovered endpoint to the network.
pub async fn exchange_endpoint(
    server_url: &str,
    network: &str,
    token: &str,
    peer_id: &str,
    endpoint: &str,
    nat_type: &str,
) -> Result<Vec<NetworkPeerInfo>> {
    let client = reqwest::Client::new();
    let base = server_url.trim_end_matches('/');

    let res: NetworkExchangeResponse = client
        .post(format!("{base}/api/networks/exchange"))
        .json(&serde_json::json!({
            "network": network,
            "token": token,
            "peer_id": peer_id,
            "endpoint": endpoint,
            "nat_type": nat_type,
        }))
        .send()
        .await?
        .json()
        .await?;

    Ok(res.peers.unwrap_or_default())
}

/// Poll for updated peer list (also serves as heartbeat).
pub async fn get_network_peers(
    server_url: &str,
    network: &str,
    token: &str,
    peer_id: &str,
) -> Result<Vec<NetworkPeerInfo>> {
    let client = reqwest::Client::new();
    let base = server_url.trim_end_matches('/');

    let res: NetworkPeersResponse = client
        .get(format!(
            "{base}/api/networks/peers?network={network}&token={token}&peer_id={peer_id}"
        ))
        .send()
        .await?
        .json()
        .await?;

    if res.status != "ok" {
        bail!(
            "failed to get peers: {}",
            res.message.unwrap_or_else(|| res.status)
        );
    }

    Ok(res.peers.unwrap_or_default())
}

/// Leave the network.
pub async fn leave_network(
    server_url: &str,
    network: &str,
    token: &str,
    peer_id: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let base = server_url.trim_end_matches('/');

    let _ = client
        .post(format!("{base}/api/networks/leave"))
        .json(&serde_json::json!({
            "network": network,
            "token": token,
            "peer_id": peer_id,
        }))
        .send()
        .await;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 1: Point-to-point room signaling (unchanged)
// ═══════════════════════════════════════════════════════════════════════

/// Information about the local peer to send to the signaling server.
pub struct LocalPeer {
    pub peer_id: String,
    pub cert_fingerprint: String,
}

/// Information about the remote peer received from the signaling server.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RemotePeer {
    pub peer_id: String,
    pub cert_fingerprint: String,
    pub endpoint: SocketAddr,
    pub nat_type: String,
}

/// Result of the signaling exchange — the local role and remote peer info.
pub struct SignalingResult {
    pub role: crate::config::Role,
    pub remote: RemotePeer,
}

#[derive(Serialize)]
struct JoinRequest<'a> {
    room_code: &'a str,
    peer_id: &'a str,
    cert_fingerprint: &'a str,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct JoinResponse {
    status: String,
    role: Option<String>,
    peer_id: Option<String>,
    peer: Option<PeerInfo>,
}

#[derive(Serialize)]
struct ExchangeRequest<'a> {
    room_code: &'a str,
    peer_id: &'a str,
    endpoint: &'a str,
    nat_type: &'a str,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ExchangeResponse {
    status: String,
    peer_endpoint: Option<String>,
    #[allow(dead_code)]
    peer_nat_type: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct PollResponse {
    status: String,
    #[allow(dead_code)]
    role: Option<String>,
    peer: Option<PollPeerInfo>,
}

#[derive(Deserialize, Clone)]
struct PeerInfo {
    peer_id: String,
    cert_fingerprint: String,
}

#[derive(Deserialize)]
struct PollPeerInfo {
    peer_id: String,
    cert_fingerprint: String,
    endpoint: Option<String>,
    nat_type: Option<String>,
}

/// Run the signaling protocol: join room, exchange endpoints, return peer info.
pub async fn run_signaling(
    server_url: &str,
    room_code: &str,
    local: &LocalPeer,
    local_endpoint: SocketAddr,
    nat_type: &str,
) -> Result<SignalingResult> {
    let client = reqwest::Client::new();
    let base = server_url.trim_end_matches('/');

    // Step 1: Join the room
    info!(room = room_code, "Joining signaling room");
    let join_res: JoinResponse = client
        .post(format!("{base}/api/rooms/join"))
        .json(&JoinRequest {
            room_code,
            peer_id: &local.peer_id,
            cert_fingerprint: &local.cert_fingerprint,
        })
        .send()
        .await
        .context("failed to reach signaling server")?
        .error_for_status()
        .context("signaling server returned error on join")?
        .json()
        .await?;

    let role_str = join_res.role.as_deref().unwrap_or("unknown");
    let role = match role_str {
        "responder" => crate::config::Role::Responder,
        "initiator" => crate::config::Role::Initiator,
        other => bail!("unexpected role from signaling: {other}"),
    };
    info!(role = role_str, "Joined room");

    // If we got paired immediately (second peer), we still have peer info from join
    let peer_info: PeerInfo = if let Some(peer) = join_res.peer {
        peer
    } else {
        // Step 2: Poll until peer arrives
        info!("Waiting for peer to join...");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let poll_res: PollResponse = client
                .get(format!(
                    "{base}/api/rooms/poll?room_code={room_code}&peer_id={}",
                    local.peer_id
                ))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            match poll_res.status.as_str() {
                "paired" | "ready" => {
                    if let Some(peer) = poll_res.peer {
                        // If already ready (both exchanged), return immediately
                        if poll_res.status == "ready" {
                            if let (Some(ep), Some(nt)) = (peer.endpoint, peer.nat_type) {
                                let endpoint: SocketAddr = ep
                                    .parse()
                                    .context("invalid peer endpoint from signaling")?;
                                return Ok(SignalingResult {
                                    role,
                                    remote: RemotePeer {
                                        peer_id: peer.peer_id,
                                        cert_fingerprint: peer.cert_fingerprint,
                                        endpoint,
                                        nat_type: nt,
                                    },
                                });
                            }
                        }
                        break PeerInfo {
                            peer_id: peer.peer_id,
                            cert_fingerprint: peer.cert_fingerprint,
                        };
                    }
                }
                "waiting" => {
                    debug!("Still waiting for peer...");
                }
                other => bail!("unexpected poll status: {other}"),
            }
        }
    };

    info!(peer_id = peer_info.peer_id, "Peer found");

    // Step 3: Exchange endpoints
    info!(endpoint = %local_endpoint, "Exchanging endpoint");
    let ex_res: ExchangeResponse = client
        .post(format!("{base}/api/rooms/exchange"))
        .json(&ExchangeRequest {
            room_code,
            peer_id: &local.peer_id,
            endpoint: &local_endpoint.to_string(),
            nat_type,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let (peer_endpoint, peer_nat_type) = if ex_res.status == "ready" {
        let ep = ex_res
            .peer_endpoint
            .context("ready but no peer_endpoint")?;
        let nt = ex_res.peer_nat_type.unwrap_or_else(|| "unknown".into());
        (ep, nt)
    } else {
        // Step 4: Poll until peer exchanges
        info!("Waiting for peer to exchange endpoint...");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let poll_res: PollResponse = client
                .get(format!(
                    "{base}/api/rooms/poll?room_code={room_code}&peer_id={}",
                    local.peer_id
                ))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            if poll_res.status == "ready" {
                if let Some(peer) = poll_res.peer {
                    if let (Some(ep), Some(nt)) = (peer.endpoint, peer.nat_type) {
                        break (ep, nt);
                    }
                }
            }
            debug!("Still waiting for peer endpoint...");
        }
    };

    let endpoint: SocketAddr = peer_endpoint
        .parse()
        .context("invalid peer endpoint from signaling")?;

    info!(
        peer_endpoint = %endpoint,
        peer_nat_type = peer_nat_type,
        "Exchange complete"
    );

    Ok(SignalingResult {
        role,
        remote: RemotePeer {
            peer_id: peer_info.peer_id,
            cert_fingerprint: peer_info.cert_fingerprint,
            endpoint,
            nat_type: peer_nat_type,
        },
    })
}
