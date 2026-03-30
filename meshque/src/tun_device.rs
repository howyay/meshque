use std::future::poll_fn;
use std::net::Ipv4Addr;
use std::process::Command;

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
        .ipv4(address, 32u8, None)
        .mtu(mtu)
        .build_async()
        .with_context(|| format!("failed to create TUN device '{name}'"))?;

    #[cfg(target_os = "linux")]
    configure_linux_routes(name, address)?;

    info!(
        name,
        address = %address,
        peer = %peer_address,
        mtu,
        "TUN device created"
    );

    Ok(device)
}

#[cfg(target_os = "linux")]
fn configure_linux_routes(name: &str, address: Ipv4Addr) -> Result<()> {
    // Linux TUN devices are point-to-point — the kernel ignores SIOCSIFNETMASK,
    // so no subnet route is created automatically. Use source-based policy
    // routing so that each peer's outbound mesh traffic goes through its own TUN
    // (required when multiple peers share the same host, e.g. in testing).
    let table = format!("{}", 100 + u32::from(address.octets()[3]));
    let addr_str = address.to_string();
    run_ip(&["rule", "add", "from", &addr_str, "table", &table])?;
    run_ip(&["route", "add", "100.64.0.0/10", "dev", name, "table", &table])?;
    // Fallback route in main table satisfies rp_filter (loose mode) without
    // interfering with policy routing (which has higher priority).
    run_ip(&["route", "add", "100.64.0.0/10", "dev", name, "metric", "9999"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("failed to run: ip {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            anyhow::bail!("ip {} failed: {stderr}", args.join(" "));
        }
    }
    Ok(())
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
