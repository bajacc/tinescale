use coordination::coordination_client::CoordinationClient;
use coordination::{RegisterRequest, PeerRequest};
use boringtun::device::{Device, DeviceConfig};
use boringtun::x25519::{PublicKey, StaticSecret};
use base64::{prelude::BASE64_STANDARD, Engine};
use std::net::SocketAddr;
use anyhow::{anyhow, Result};
use crate::{ClientConfig};
use boringtun::device::peer::AllowedIP;
use boringtun::serialization::KeyBytes;

pub mod coordination {
    tonic::include_proto!("coordination");
}

pub async fn register_and_configure(
    config: &ClientConfig
) -> Result<()> {

    let key_bytes: KeyBytes = config.private_key.parse().map_err(|e: &'static str| anyhow!(e))?;
    let sk = StaticSecret::from(key_bytes.0);

    let public_key = PublicKey::from(&sk);
    let pubkey_base64 = BASE64_STANDARD.encode(public_key.as_bytes());

    let mut client_opt = None;
    if let Some(server_addr) = &config.server_addr {
        let mut client = CoordinationClient::connect(server_addr.clone()).await?;

        let reg = RegisterRequest {
            pubkey: pubkey_base64.clone(),
            wg_port: config.wg_port as u32,
        };

        let response = client.register(reg).await?.into_inner();
        println!("[{}] Public address: {}:{}", pubkey_base64, response.external_ip, response.external_port);
        client_opt = Some(client);
    }

    let mut device = Device::new(config.interface.as_str(), DeviceConfig::default())?;
    device.open_listen_socket(config.wg_port)?;
    device.set_key(sk);

    if let Some(peers) = &config.peers {
        for peer in peers {
            // Query the coordination server to get peer endpoint info by public key
            let peer_pubkey: KeyBytes = peer.pubkey.parse().map_err(|e: &'static str| anyhow!(e))?;
            let peer_addr: SocketAddr = match peer.endpoint {
                Some(endpoint) => endpoint,
                None => {
                    let peer_info = client_opt.as_mut().unwrap()
                        .get_peer(PeerRequest {
                            requester_pubkey: pubkey_base64.clone(),
                            target_pubkey: peer.pubkey.clone(),
                        })
                        .await?
                        .into_inner();
                    format!("{}:{}", peer_info.external_ip, peer_info.external_port).parse()?
                }
            };
            let mut allowed_ips: Vec<AllowedIP> = vec![];
            for allowed_ip in &peer.allowed_ips {
                let ip: AllowedIP = allowed_ip.parse().map_err(|e: String| anyhow!(e))?;
                allowed_ips.push(ip);
            }

            device.update_peer(
                PublicKey::from(peer_pubkey.0), 
                false, 
                true,
                Some(peer_addr), 
                allowed_ips.as_slice(),
                peer.persistent_keepalive,
                None,
            );
        }
    }

    println!("WireGuard peers configured with endpoints from server.");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
