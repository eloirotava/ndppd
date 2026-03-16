use std::sync::Arc;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use dhcproto::v4::Message;
use dhcproto::{Decoder, Decodable}; // Adicionado Decodable para corrigir E0599
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

pub async fn start_server(config: Arc<BridgeConfig>, storage: Arc<LeaseManager>) {
    let socket = UdpSocket::bind("0.0.0.0:67").await.expect("Falha porta 67");
    socket.set_broadcast(true).expect("Falha broadcast");
    
    let mut buf = [0u8; 1500];
    loop {
        if let Ok((len, _peer)) = socket.recv_from(&mut buf).await {
            let mut decoder = Decoder::new(&buf[..len]);
            
            // Correção E0599 e E0282: Especificando o tipo Message explicitamente
            if let Ok(msg) = Message::decode(&mut decoder) {
                let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                    msg.chaddr()[0], msg.chaddr()[1], msg.chaddr()[2], 
                    msg.chaddr()[3], msg.chaddr()[4], msg.chaddr()[5]);

                let lease = storage.get_lease(&mac).unwrap_or_else(|| {
                    let ip = config.ipv4_range_start.clone();
                    storage.set_lease(&mac, ip, "".to_string());
                    storage.get_lease(&mac).expect("Falha ao criar lease")
                });

                let offered_ip: Ipv4Addr = lease.ipv4.parse().unwrap_or(Ipv4Addr::new(10,0,0,2));
                log::info!("🔍 DHCPv4 em {}: MAC {} -> IP {}", config.name, mac, offered_ip);
            }
        }
    }
}