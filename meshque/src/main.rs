mod config;
mod connection;
mod mesh;
mod nat;
mod peer_table;
mod signaling;
mod tun_device;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// meshque — mesh VPN over MASQUE CONNECT-IP
#[derive(Parser)]
#[command(name = "meshque", about = "Mesh VPN over MASQUE CONNECT-IP (RFC 9484)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Join a mesh network
    Up {
        /// Network name
        #[arg(long)]
        network: String,

        /// Shared network token
        #[arg(long)]
        token: String,

        /// Signaling server URL
        #[arg(long, default_value = "https://meshque-signaling.haoye.workers.dev")]
        signal_server: String,

        /// Local listen address
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: String,

        /// TUN device name
        #[arg(long, default_value = "meshque0")]
        tun_name: String,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show network status
    Status {
        /// Network name
        #[arg(long)]
        network: String,

        /// Shared network token
        #[arg(long)]
        token: String,

        /// Signaling server URL
        #[arg(long, default_value = "https://meshque-signaling.haoye.workers.dev")]
        signal_server: String,

        /// Local peer ID
        #[arg(long)]
        peer_id: String,
    },

    /// List peers in the network
    Peers {
        /// Network name
        #[arg(long)]
        network: String,

        /// Shared network token
        #[arg(long)]
        token: String,

        /// Signaling server URL
        #[arg(long, default_value = "https://meshque-signaling.haoye.workers.dev")]
        signal_server: String,

        /// Local peer ID
        #[arg(long)]
        peer_id: String,
    },

    /// Point-to-point connection (Phase 1 compat)
    Connect {
        /// Room code for signaling server, or use --direct for direct connection
        #[arg(required_unless_present = "direct")]
        room_code: Option<String>,

        /// Direct connection to peer address (skip signaling server)
        #[arg(long, value_name = "HOST:PORT")]
        direct: Option<String>,

        /// Role when using --direct: "initiator" connects to peer, "responder" listens
        #[arg(long, default_value = "initiator", requires = "direct")]
        role: String,

        /// Signaling server URL
        #[arg(long, default_value = "https://meshque-signaling.haoye.workers.dev")]
        signal_server: String,

        /// Local listen address for proxy mode
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: String,

        /// TUN device name
        #[arg(long, default_value = "meshque0")]
        tun_name: String,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Up {
            network,
            token,
            signal_server,
            listen,
            tun_name,
            verbose,
        } => {
            let filter = if verbose {
                EnvFilter::new("meshque=debug,connect_ip_rs=debug,quinn=info,h3=info")
            } else {
                EnvFilter::new("meshque=info")
            };
            tracing_subscriber::fmt().with_env_filter(filter).init();

            let cfg = config::MeshConfig {
                network,
                token,
                signal_server,
                listen_addr: listen.parse()?,
                tun_name,
            };

            tokio::select! {
                result = mesh::run(cfg) => result,
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received shutdown signal, cleaning up...");
                    Ok(())
                }
            }
        }

        Commands::Status {
            network,
            token,
            signal_server,
            peer_id,
        } => {
            let peers = signaling::get_network_peers(&signal_server, &network, &token, &peer_id).await?;
            println!("Network: {network}");
            println!("Peers: {}", peers.len());
            for p in &peers {
                println!("  {} ({})", p.assigned_ip, if p.endpoint.is_some() { "connected" } else { "no endpoint" });
            }
            Ok(())
        }

        Commands::Peers {
            network,
            token,
            signal_server,
            peer_id,
        } => {
            let peers = signaling::get_network_peers(&signal_server, &network, &token, &peer_id).await?;
            if peers.is_empty() {
                println!("No other peers in the network.");
            } else {
                println!("{:<16} {:<24} {:<10}", "IP", "ENDPOINT", "NAT");
                println!("{}", "-".repeat(50));
                for p in &peers {
                    println!(
                        "{:<16} {:<24} {:<10}",
                        p.assigned_ip,
                        p.endpoint.as_deref().unwrap_or("-"),
                        p.nat_type.as_deref().unwrap_or("unknown"),
                    );
                }
            }
            Ok(())
        }

        Commands::Connect {
            room_code,
            direct,
            role,
            signal_server,
            listen,
            tun_name,
            verbose,
        } => {
            let filter = if verbose {
                EnvFilter::new("meshque=debug,connect_ip_rs=debug,quinn=info,h3=info")
            } else {
                EnvFilter::new("meshque=info")
            };
            tracing_subscriber::fmt().with_env_filter(filter).init();

            let cfg = config::Config {
                room_code,
                direct_addr: direct,
                role: role.parse()?,
                signal_server,
                listen_addr: listen.parse()?,
                tun_name,
            };

            tokio::select! {
                result = connection::run(cfg) => result,
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received shutdown signal, cleaning up...");
                    Ok(())
                }
            }
        }
    }
}
