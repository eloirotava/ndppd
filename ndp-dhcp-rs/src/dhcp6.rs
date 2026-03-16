use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::net::UdpSocket;
use socket2::{Socket, Domain, Type, Protocol};
use rand::Rng;
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

// Imports pnet para teste NDP nativo
use pnet::datalink::{self, Channel};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::{Icmpv6Types, Icmpv6Packet};

/// Verifica se um IPv6 está em uso (Rust puro via inspeção de vizinhança)
fn is_ipv6_in_use(iface_name: &str, target_ip: Ipv6Addr) -> bool {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| iface.name == iface_name).expect("Interface erro");
    
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return false,
    };

    // Em vez de enviar (complexo construir ICMPv6 NS bruto), escutamos por 200ms
    // para ver se alguém já está anunciando esse IP.
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(200) {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Ipv6 {
                    // Se virmos qualquer tráfego ICMPv6 vindo desse IP, ele está ocupado
                    if let Some(ipv6) = pnet::packet::ipv6::Ipv6Packet::new(eth.payload()) {
                        if ipv6.get_source() == target_ip {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string()).trim().parse().unwrap_or(0)
}

fn get_mac_address(iface: &str) -> Vec<u8> {
    std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))
        .unwrap_or_else(|_| "00:00:00:00:00:00".to_string()).trim()
        .split(':').map(|s| u8::from_str_radix(s, 16).unwrap_or(0)).collect()
}

pub async fn start_server(cfg: Arc<BridgeConfig>, storage: Arc<LeaseManager>) {
    let ifindex = get_ifindex(&cfg.name);
    log::info!("📡 [DHCPv6] Iniciando em {} (Index: {}) na porta 547", cfg.name, ifindex);

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).expect("Erro socket v6");
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_reuse_port(true);
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0);
    let _ = sock.bind(&addr.into());

    sock.set_nonblocking(true).unwrap();
    let socket = UdpSocket::from_std(sock.into()).unwrap();
    let _ = socket.join_multicast_v6(&"ff02::1:2".parse().unwrap(), ifindex);

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
            let lease = storage.get_lease(&peer_ip).unwrap_or_else(|| {
                let mut rng = rand::thread_rng();
                let prefix_addr = cfg.ipv6_prefix.split('/').next().unwrap_or("::").parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED);
                let mut octets = prefix_addr.octets();
                let fixed_bytes = (cfg.ipv6_prefix_len / 8) as usize;
                
                let mut ip_str;
                loop {
                    for i in fixed_bytes..16 { octets[i] = rng.gen(); }
                    let candidate = Ipv6Addr::from(octets);
                    ip_str = candidate.to_string();
                    if !is_ipv6_in_use(&cfg.name, candidate) { break; }
                }
                storage.set_lease(&peer_ip, "".to_string(), ip_str);
                storage.get_lease(&peer_ip).unwrap()
            });

            let offered_ipv6: Ipv6Addr = lease.ipv6.parse().unwrap_or(Ipv6Addr::UNSPECIFIED);
            let mut out = vec![if msg_type == 1 { 2 } else { 7 }]; 
            out.extend_from_slice(&buf[1..4]); 
            out.extend_from_slice(&client_id); 
            out.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1]);
            out.extend_from_slice(if server_mac.len() == 6 { &server_mac } else { &[0x02, 0x42, 0, 0, 0, 0x01] });
            out.extend_from_slice(&[0, 3, 0, 40]); out.extend_from_slice(&iaid);
            out.extend_from_slice(&[0, 0, 0x0e, 0x10, 0, 0, 0x15, 0x18]);
            out.extend_from_slice(&[0, 5, 0, 24]); out.extend_from_slice(&offered_ipv6.octets());
            out.extend_from_slice(&[0, 0, 0x1c, 0x20, 0, 0, 0x2a, 0x30]);
            out.extend_from_slice(&[0, 23, 0, 16]);
            out.extend_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());

            let _ = socket.send_to(&out, peer).await;
            log::info!("   🎉 [DHCPv6] {} para {}: {}", if msg_type == 1 {"ADVERTISE"} else {"REPLY"}, peer_ip, offered_ipv6);
        }
    }
}