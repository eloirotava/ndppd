use std::sync::Arc;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use dhcproto::v4::{Message, MessageType, Opcode, DhcpOption};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

pub async fn start_server(config: Arc<BridgeConfig>, storage: Arc<LeaseManager>) {
    let socket = UdpSocket::bind("0.0.0.0:67").await.unwrap();
    socket.set_broadcast(true).unwrap();
    
    let mut buf = [0u8; 1500];
    loop {
        if let Ok((len, _)) = socket.recv_from(&mut buf).await {
            let mut decoder = Decoder::new(&buf[..len]);
            if let Ok(msg) = Message::decode(&mut decoder) {
                let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                    msg.chaddr()[0], msg.chaddr()[1], msg.chaddr()[2], 
                    msg.chaddr()[3], msg.chaddr()[4], msg.chaddr()[5]);

                // Lógica de Persistência: Checar JSON
                let lease = storage.get_lease(&mac).unwrap_or_else(|| {
                    // Se não existe, cria um novo (aqui poderíamos ter um pool, mas vamos usar o start do range)
                    let ip = config.ipv4_range_start.clone();
                    storage.set_lease(&mac, ip.clone(), "".to_string());
                    storage.get_lease(&mac).unwrap()
                });

                let offered_ip: Ipv4Addr = lease.ipv4.parse().unwrap();

                // ... Restante da lógica de envio do DHCPOFFER/ACK (mesma da v1) ...
                log::info!("   🎯 IP {} persistido para o MAC {}", offered_ip, mac);
            }
        }
    }
}