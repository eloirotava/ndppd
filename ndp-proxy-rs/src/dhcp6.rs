use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::net::UdpSocket;
use socket2::{Socket, Domain, Type, Protocol};
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

/// Captura o índice real da interface no Linux (Ex: br1 -> 4)
fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string())
        .trim()
        .parse()
        .unwrap_or(0)
}

/// Captura o MAC para o DUID
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
    
    // Bind global na porta 547 para capturar multicast
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0);
    if let Err(e) = sock.bind(&addr.into()) {
        log::error!("❌ [DHCPv6] Erro bind porta 547: {}", e);
        return;
    }

    sock.set_nonblocking(true).unwrap();
    let socket = UdpSocket::from_std(sock.into()).unwrap();
    
    // IMPORTANTE: Inscreve no grupo multicast DHCPv6 USANDO o índice da interface
    let multicast_addr: Ipv6Addr = "ff02::1:2".parse().unwrap();
    if let Err(e) = socket.join_multicast_v6(&multicast_addr, ifindex) {
        log::warn!("⚠️  Aviso Multicast em {}: {}", cfg.name, e);
    }

    let mut buf = [0u8; 1500];
    let server_mac = get_mac_address(&cfg.name);

    loop {
        if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            // Log de depuração para ver se qualquer pacote chega
            log::debug!("   📥 [DHCPv6] Pacote de {} recebido em {}", peer, cfg.name);

            if len < 4 { continue; }
            let msg_type = buf[0];
            if msg_type != 1 && msg_type != 3 { continue; }

            // Parsing binário das opções
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
            let lease = storage.get_lease(&peer_ip).unwrap_or_else(|| {
                // Geração robusta do IP: Pega o prefixo (ex: 2804:14d:7e89:41a0:1234::) e força o final ::2
                let clean_prefix = cfg.ipv6_prefix.split('/').next().unwrap_or("::").trim_end_matches(':');
                let ip_str = format!("{}::2", clean_prefix.trim_end_matches(':'));
                
                storage.set_lease(&peer_ip, "10.0.0.x".to_string(), ip_str);
                storage.get_lease(&peer_ip).unwrap()
            });

            let offered_ipv6: Ipv6Addr = lease.ipv6.parse().unwrap_or(Ipv6Addr::UNSPECIFIED);
            
            // Construção da resposta binária (Baseada no seu dnsmasq-rs original)
            let mut out = vec![if msg_type == 1 { 2 } else { 7 }]; // Advertise (2) ou Reply (7)
            out.extend_from_slice(&buf[1..4]); // Transaction ID
            out.extend_from_slice(&client_id); // Client ID (Opção 1)
            
            // Server ID (Opção 2) - DUID-LL (Tipo 3) + Hardware (1) + MAC
            out.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1]);
            if server_mac.len() == 6 { out.extend_from_slice(&server_mac); } 
            else { out.extend_from_slice(&[0x02, 0x42, 0, 0, 0, 0x01]); }
            
            // IA_NA (Opção 3)
            out.extend_from_slice(&[0, 3, 0, 40]); 
            out.extend_from_slice(&iaid);
            out.extend_from_slice(&[0, 0, 0x0e, 0x10, 0, 0, 0x15, 0x18]); // T1, T2
            
            // IA_ADDR (Opção 5 - Dentro da IA_NA)
            out.extend_from_slice(&[0, 5, 0, 24]); 
            out.extend_from_slice(&offered_ipv6.octets());
            out.extend_from_slice(&[0, 0, 0x1c, 0x20, 0, 0, 0x2a, 0x30]); // Lifetimes
            
            // DNS (Opção 23)
            out.extend_from_slice(&[0, 23, 0, 16]);
            out.extend_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());

            if let Err(e) = socket.send_to(&out, peer).await {
                log::error!("❌ [DHCPv6] Falha ao responder {}: {}", peer, e);
            } else {
                log::info!("   🎉 [DHCPv6] {} enviado para {}: {}", 
                    if msg_type == 1 {"ADVERTISE"} else {"REPLY"}, peer_ip, offered_ipv6);
            }
        }
    }
}