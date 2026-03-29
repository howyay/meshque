mod config;
mod connection;
mod nat;
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
    /// Connect to a peer
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
        #[arg(long, default_value = "https://signal.meshque.dev")]
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
        Commands::Connect {
            room_code,
            direct,
            role,
            signal_server,
            listen,
            tun_name,
            verbose,
        } => {
            // Initialize logging
            let filter = if verbose {
                EnvFilter::new("meshque=debug,connect_ip=debug,quinn=info,h3=info")
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

            // Run with graceful shutdown on SIGTERM/SIGINT
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
