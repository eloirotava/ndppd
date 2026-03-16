use std::sync::Arc;
use std::net::Ipv6Addr;
use tokio::net::UdpSocket;
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string()).trim().parse().unwrap_or(0)
}

pub async fn start_server(cfg: Arc<BridgeConfig>, storage: Arc<LeaseManager>) {
    log::info!("📡 Motor DHCPv6 iniciado na interface {}", cfg.name);

    let socket = UdpSocket::bind("[::]:547").await.expect("Erro bind DHCPv6");
    let multicast_addr: Ipv6Addr = "ff02::1:2".parse().unwrap();
    let _ = socket.join_multicast_v6(&multicast_addr, get_ifindex(&cfg.name));

    let mut buf = [0u8; 1500];
    loop {
        if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if len < 4 { continue; }
            let msg_type = buf[0];
            if msg_type != 1 && msg_type != 3 { continue; }

            // Extração manual de ClientID e IAID para garantir compatibilidade
            let mut client_id_bytes = Vec::new();
            let mut iaid_bytes = vec![0, 0, 0, 0];
            let mut offset = 4;
            while offset + 4 <= len {
                let opt_type = u16::from_be_bytes([buf[offset], buf[offset+1]]);
                let opt_len = u16::from_be_bytes([buf[offset+2], buf[offset+3]]) as usize;
                offset += 4;
                if offset + opt_len > len { break; }
                if opt_type == 1 { client_id_bytes.extend_from_slice(&buf[offset-4..offset+opt_len]); }
                else if opt_type == 3 && opt_len >= 4 { iaid_bytes.copy_from_slice(&buf[offset..offset+4]); }
                offset += opt_len;
            }

            // Identificamos o cliente pelo MAC (vinda do DUID no ClientID se necessário, ou Link-Local)
            let peer_str = peer.to_string();
            let lease = storage.get_lease(&peer_str).unwrap_or_else(|| {
                let ip = cfg.ipv6_prefix.replace("::/80", ":2"); // Lógica simples de oferta
                storage.set_lease(&peer_str, "10.0.0.x".to_string(), ip);
                storage.get_lease(&peer_str).unwrap()
            });

            let offered_ipv6: Ipv6Addr = lease.ipv6.parse().unwrap();

            // Montagem da resposta (Advertise ou Reply)
            let mut out = Vec::new();
            out.push(if msg_type == 1 { 2 } else { 7 }); // 2=Advertise, 7=Reply
            out.extend_from_slice(&buf[1..4]); // Transaction ID
            out.extend_from_slice(&client_id_bytes);
            
            // Server ID
            out.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1, 0x02, 0x42, 0, 0, 0, 0x01]);
            // IA_NA
            out.extend_from_slice(&[0, 3, 0, 40]);
            out.extend_from_slice(&iaid_bytes);
            out.extend_from_slice(&[0, 0, 0x0e, 0x10, 0, 0, 0x15, 0x18]);
            // IA_ADDR
            out.extend_from_slice(&[0, 5, 0, 24]);
            out.extend_from_slice(&offered_ipv6.octets());
            out.extend_from_slice(&[0, 0, 0x1c, 0x20, 0, 0, 0x2a, 0x30]);

            let _ = socket.send_to(&out, peer).await;
            log::info!("   🚀 Resposta DHCPv6 enviada para {}", peer_str);
        }
    }
}