use std::future::poll_fn;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use tun_rs::{AsyncDevice, DeviceBuilder};
use tracing::info;

/// Create and configure a TUN device.
pub fn create_tun(
    name: &str,
    address: Ipv4Addr,
    peer_address: Ipv4Addr,
    mtu: u16,
) -> Result<AsyncDevice> {
    let device = DeviceBuilder::new()
        .name(name)
        .ipv4(address, "255.255.255.255", None)
        .mtu(mtu)
        .build_async()
        .with_context(|| format!("failed to create TUN device '{name}' (are you root?)"))?;

    info!(
        name,
        address = %address,
        peer = %peer_address,
        mtu,
        "TUN device created"
    );

    Ok(device)
}

/// Read a single IP packet from the TUN device.
pub async fn read_packet(tun: &AsyncDevice, buf: &mut [u8]) -> Result<usize> {
    let n = poll_fn(|cx| tun.poll_recv(cx, buf)).await?;
    Ok(n)
}

/// Write a single IP packet to the TUN device.
pub async fn write_packet(tun: &AsyncDevice, packet: &[u8]) -> Result<()> {
    poll_fn(|cx| tun.poll_send(cx, packet)).await?;
    Ok(())
}
