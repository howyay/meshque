use anyhow::Result;
use bytes::Bytes;
use connect_ip_rs::session::ConnectIpSession;
use h3::quic;
use h3_datagram::quic_traits::DatagramConnectionExt;
use tracing::{debug, error, info};
use tun_rs::AsyncDevice;

use crate::tun_device;

/// Run the tunnel: forward IP packets between TUN device and CONNECT-IP session.
///
/// This splits the session into independent parts and runs two concurrent loops:
/// 1. TUN → tunnel: read packets from TUN, send via CONNECT-IP datagrams
/// 2. tunnel → TUN: receive CONNECT-IP datagrams, write to TUN
pub async fn run_tunnel<C>(session: ConnectIpSession<C>, tun: &AsyncDevice) -> Result<()>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    C::BidiStream: quic::BidiStream<Bytes>,
    <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer: Into<Bytes>,
{
    let mut parts = session.into_parts();

    info!("Tunnel active — forwarding packets");

    let tun_to_tunnel = async {
        let mut buf = vec![0u8; 1500];
        loop {
            let n = tun_device::read_packet(tun, &mut buf).await?;
            if n == 0 {
                continue;
            }
            debug!(bytes = n, "TUN → tunnel");
            if let Err(e) = parts.datagram_send.send_ip_packet(&buf[..n]) {
                error!("Failed to send packet to tunnel: {e}");
                return Err(anyhow::anyhow!("tunnel send error: {e}"));
            }
        }
    };

    let tunnel_to_tun = async {
        loop {
            let packet = parts.datagram_recv.recv_ip_packet().await.map_err(|e| {
                anyhow::anyhow!("tunnel recv error: {e}")
            })?;
            debug!(bytes = packet.len(), "tunnel → TUN");
            tun_device::write_packet(tun, &packet).await?;
        }
    };

    // Run both directions concurrently — first error stops everything
    tokio::select! {
        result = tun_to_tunnel => result,
        result = tunnel_to_tun => result,
    }
}
