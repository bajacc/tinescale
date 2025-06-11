use std::{fs, net::SocketAddr};
use anyhow::{Ok, Result};
use serde::Deserialize;
use clap::Parser;

mod server;
mod client;

#[derive(Parser, Debug)]
#[command(name = "tinescale", about = "Tinescale VPN peer")]
struct Cli {
    /// Path to the configuration file
    #[arg(long)]
    config: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    server: Option<ServerConfig>,
    client: Option<ClientConfig>,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    listen_addr: String,
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    interface: String,
    wg_port: u16,
    private_key: String,
    server_addr: Option<String>,
    peers: Option<Vec<PeerConfig>>,
}

#[derive(Debug, Deserialize)]
struct PeerConfig {
    pubkey: String,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<String>,
    persistent_keepalive: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();


    let config_str = fs::read_to_string(&cli.config)?;
    let config: Config = toml::from_str(&config_str)?;

    if let Some(server_cfg) = config.server {
        tokio::spawn(async move {
            if let Err(e) = server::run_server_with_config(server_cfg).await {
                eprintln!("Server error: {}", e);
            }
        });
    }

    if let Some(client_cfg) = config.client {
        tokio::spawn(async move {
            if let Err(e) = client::register_and_configure(&client_cfg).await {
                eprintln!("client error: {}", e);
            }
        });
    }
    Ok(())
}
