use crate::serialization::KeyBytes;
use crate::wghandle::WGHandle;
use crate::ClientConfig;
use anyhow::{anyhow, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use boringtun::x25519::{PublicKey, StaticSecret};
use coordination::coordination_client::CoordinationClient;
use coordination::{PeerRequest, RegisterRequest};
use std::net::SocketAddr;

pub mod coordination {
    tonic::include_proto!("coordination");
}

pub async fn register_and_configure(config: &ClientConfig) -> Result<()> {
    let wg = WGHandle::init(config.interface.as_str());

    let key_bytes: KeyBytes = config
        .private_key
        .parse()
        .map_err(|e: &'static str| anyhow!(e))?;
    let private_key = StaticSecret::from(key_bytes.0);

    let public_key = PublicKey::from(&private_key);
    let pubkey_base64 = BASE64_STANDARD.encode(public_key.as_bytes());

    let mut client_opt = None;
    if let Some(server_addr) = &config.server_addr {
        let mut client = CoordinationClient::connect(server_addr.clone()).await?;

        let reg = RegisterRequest {
            pubkey: pubkey_base64.clone(),
            wg_port: config.wg_port as u32,
        };

        let response = client.register(reg).await?.into_inner();
        println!(
            "[{}] Public address: {}:{}",
            pubkey_base64, response.external_ip, response.external_port
        );
        client_opt = Some(client);
    }

    wg.wg_set_port(config.wg_port);
    wg.wg_set_key(private_key);

    if let Some(peers) = &config.peers {
        for peer in peers {
            // Query the coordination server to get peer endpoint info by public key
            let peer_addr: SocketAddr = match peer.endpoint {
                Some(endpoint) => endpoint,
                None => {
                    let peer_info = client_opt
                        .as_mut()
                        .unwrap()
                        .get_peer(PeerRequest {
                            requester_pubkey: pubkey_base64.clone(),
                            target_pubkey: peer.pubkey.clone(),
                        })
                        .await?
                        .into_inner();
                    format!("{}:{}", peer_info.external_ip, peer_info.external_port).parse()?
                }
            };

            let key_bytes: KeyBytes = peer.pubkey.parse().map_err(|e: &'static str| anyhow!(e))?;
            let public_key = PublicKey::from(key_bytes.0);
            wg.wg_set_peer(
                &public_key,
                &peer_addr,
                &peer.allowed_ips,
                peer.persistent_keepalive,
            );
        }
    }

    println!("WireGuard peers configured with endpoints from server.");
    println!("{}", wg.wg_get());

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
