use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::process::Command;
use tokio::net::UdpSocket;
use socket2::{Socket, Domain, Type, Protocol};
use rand::Rng; // Requer rand = "0.8" no Cargo.toml
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

/// Verifica se o IP responde na rede usando ping6
fn is_ip6_on_network(ip: &str, iface: &str) -> bool {
    // Tenta enviar 1 pacote com timeout de 1 segundo
    let status = Command::new("ping")
        .args(&["-6", "-c", "1", "-W", "1", "-I", iface, ip])
        .status();
    status.map(|s| s.success()).unwrap_or(false)
}

fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string())
        .trim()
        .parse()
        .unwrap_or(0)
}

fn get_mac_address(iface: &str) -> Vec<u8> {
    std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))
        .unwrap_or_else(|_| "00:00:00:00:00:00".to_string())
        .trim()
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).unwrap_or(0))
        .collect()
}

pub async fn start_server(cfg: Arc<BridgeConfig>, storage: Arc<LeaseManager>) {
    let ifindex = get_ifindex(&cfg.name);
    log::info!("📡 [DHCPv6] Iniciando em {} (Index: {}) na porta 547", cfg.name, ifindex);

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).expect("Erro socket v6");
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_reuse_port(true);
    
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0);
    if let Err(e) = sock.bind(&addr.into()) {
        log::error!("❌ [DHCPv6] Erro bind porta 547: {}", e);
        return;
    }

    sock.set_nonblocking(true).unwrap();
    let socket = UdpSocket::from_std(sock.into()).unwrap();
    
    let multicast_addr: Ipv6Addr = "ff02::1:2".parse().unwrap();
    if let Err(e) = socket.join_multicast_v6(&multicast_addr, ifindex) {
        log::warn!("⚠️  Aviso Multicast em {}: {}", cfg.name, e);
    }

    let mut buf = [0u8; 1500];
    let server_mac = get_mac_address(&cfg.name);

    loop {
        if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if len < 4 { continue; }
            let msg_type = buf[0];
            if msg_type != 1 && msg_type != 3 { continue; }

            let mut client_id = Vec::new();
            let mut iaid = vec![0u8; 4];
            let mut offset = 4;
            while offset + 4 <= len {
                let o_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let o_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
                offset += 4;
                if offset + o_len > len { break; }
                if o_type == 1 { client_id.extend_from_slice(&buf[offset - 4 .. offset + o_len]); }
                else if o_type == 3 && o_len >= 4 { iaid.copy_from_slice(&buf[offset .. offset + 4]); }
                offset += o_len;
            }

            let peer_ip = peer.ip().to_string();
            // Tenta recuperar o IP salvo para este cliente
            let lease = storage.get_lease(&peer_ip).unwrap_or_else(|| {
                let mut rng = rand::thread_rng();
                let prefix_addr = cfg.ipv6_prefix.split('/').next().unwrap_or("::").parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED);
                let mut octets = prefix_addr.octets();
                
                // Calcula quantos bytes são fixos (ex: /80 -> 10 bytes)
                let fixed_bytes = (cfg.ipv6_prefix_len / 8) as usize;
                
                let mut ip_str;
                loop {
                    // Randomiza os bytes restantes (o host)
                    for i in fixed_bytes..16 {
                        octets[i] = rng.gen();
                    }
                    
                    let candidate = Ipv6Addr::from(octets);
                    ip_str = candidate.to_string();
                    
                    // TESTE DE EXISTÊNCIA NA REDE: Gera de novo se o IP responder ao ping
                    if !is_ip6_on_network(&ip_str, &cfg.name) {
                        break; 
                    }
                }
                
                // Atribui e salva no storage como é hoje
                storage.set_lease(&peer_ip, "10.0.0.x".to_string(), ip_str);
                storage.get_lease(&peer_ip).unwrap()
            });

            let offered_ipv6: Ipv6Addr = lease.ipv6.parse().unwrap_or(Ipv6Addr::UNSPECIFIED);
            
            let mut out = vec![if msg_type == 1 { 2 } else { 7 }]; 
            out.extend_from_slice(&buf[1..4]); 
            out.extend_from_slice(&client_id); 
            
            out.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1]);
            if server_mac.len() == 6 { out.extend_from_slice(&server_mac); } 
            else { out.extend_from_slice(&[0x02, 0x42, 0, 0, 0, 0x01]); }
            
            out.extend_from_slice(&[0, 3, 0, 40]); 
            out.extend_from_slice(&iaid);
            out.extend_from_slice(&[0, 0, 0x0e, 0x10, 0, 0, 0x15, 0x18]);
            
            out.extend_from_slice(&[0, 5, 0, 24]); 
            out.extend_from_slice(&offered_ipv6.octets());
            out.extend_from_slice(&[0, 0, 0x1c, 0x20, 0, 0, 0x2a, 0x30]);
            
            out.extend_from_slice(&[0, 23, 0, 16]);
            out.extend_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());

            let _ = socket.send_to(&out, peer).await;
            log::info!("   🎉 [DHCPv6] {} enviado para {}: {}", 
                if msg_type == 1 {"ADVERTISE"} else {"REPLY"}, peer_ip, offered_ipv6);
        }
    }
}