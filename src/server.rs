use anyhow::Result;
use coordination::coordination_server::{Coordination, CoordinationServer};
use coordination::{PeerRequest, PeerResponse, RegisterRequest, RegisterResponse};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{transport::Server, Request, Response, Status};

pub mod coordination {
    tonic::include_proto!("coordination");
}

#[derive(Default)]
pub struct CoordService {
    pub peers: Arc<Mutex<HashMap<String, (String, String, u16)>>>, // pubkey => (pubkey, ip, port)
}

#[tonic::async_trait]
impl Coordination for CoordService {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let addr = req
            .remote_addr()
            .ok_or(Status::internal("Missing remote IP"))?;
        let reg = req.into_inner();
        let ip = addr.ip().to_string();

        self.peers.lock().unwrap().insert(
            reg.pubkey.clone(),
            (reg.pubkey, ip.clone(), reg.wg_port as u16),
        );

        Ok(Response::new(RegisterResponse {
            external_ip: ip,
            external_port: reg.wg_port,
        }))
    }

    async fn get_peer(&self, req: Request<PeerRequest>) -> Result<Response<PeerResponse>, Status> {
        let target_pubkey = req.into_inner().target_pubkey;

        let peers = self.peers.lock().unwrap();
        if let Some((pubkey, ip, port)) = peers.get(&target_pubkey) {
            Ok(Response::new(PeerResponse {
                pubkey: pubkey.clone(),
                external_ip: ip.clone(),
                external_port: *port as u32,
            }))
        } else {
            Err(Status::not_found("Peer not found"))
        }
    }
}

pub async fn run_server_with_config(cfg: crate::ServerConfig) -> Result<()> {
    let addr = cfg.listen_addr.parse()?;
    let svc = CoordService::default();

    println!("Coordination server listening on {}", addr);

    Server::builder()
        .add_service(CoordinationServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
