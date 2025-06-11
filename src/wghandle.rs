use std::fmt::Write as _;
use std::io::{Read, Write};
use std::{net::SocketAddr, os::unix::net::UnixStream};

use boringtun::device::{DeviceConfig, DeviceHandle};
use hex::encode;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct WGHandle {
    _device: DeviceHandle,
    name: String,
}

impl WGHandle {
    /// Create a new interface for the tunnel with the given address
    pub fn init(name: &str) -> WGHandle {
        WGHandle::init_with_config(
            name,
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: true,
                #[cfg(target_os = "linux")]
                use_multi_queue: true,
                #[cfg(target_os = "linux")]
                uapi_fd: -1,
            },
        )
    }

    /// Create a new interface for the tunnel with the given address
    fn init_with_config(name: &str, config: DeviceConfig) -> WGHandle {
        let _device = DeviceHandle::new(&name, config).unwrap();
        WGHandle {
            _device,
            name: name.into(),
        }
    }

    /// Issue a get command on the interface
    pub fn wg_get(&self) -> String {
        let path = format!("/var/run/wireguard/{}.sock", self.name);

        let mut socket = UnixStream::connect(path).unwrap();
        write!(socket, "get=1\n\n").unwrap();

        let mut ret = String::new();
        socket.read_to_string(&mut ret).unwrap();
        ret
    }

    /// Issue a set command on the interface
    fn wg_set(&self, setting: &str) -> String {
        let path = format!("/var/run/wireguard/{}.sock", self.name);
        let mut socket = UnixStream::connect(path).unwrap();
        write!(socket, "set=1\n{}\n\n", setting).unwrap();

        println!("set=1\n{}\n\n", setting);
        let mut ret = String::new();
        socket.read_to_string(&mut ret).unwrap();
        println!("ret={}\n\n", ret);
        ret
    }

    /// Assign a listen_port to the interface
    pub fn wg_set_port(&self, port: u16) -> String {
        self.wg_set(&format!("listen_port={}", port))
    }

    /// Assign a private_key to the interface
    pub fn wg_set_key(&self, key: StaticSecret) -> String {
        self.wg_set(&format!("private_key={}", encode(key.to_bytes())))
    }

    /// Assign a peer to the interface (with public_key, endpoint and a series of nallowed_ip)
    pub fn wg_set_peer(
        &self,
        key: &PublicKey,
        ep: &SocketAddr,
        allowed_ips: &[String],
        persistent_keepalive: Option<u16>,
    ) -> String {
        let mut req = format!("public_key={}\nendpoint={}", encode(key.as_bytes()), ep);
        for allowed_ip in allowed_ips {
            let _ = write!(req, "\nallowed_ip={}", allowed_ip);
        }

        if let Some(persistent_keepalive) = persistent_keepalive {
            let _ = write!(
                req,
                "\npersistent_keepalive_interval={}",
                persistent_keepalive
            );
        }

        self.wg_set(&req)
    }
}
