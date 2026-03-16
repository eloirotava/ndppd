use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::time::{sleep, Duration};
use socket2::{Socket, Domain, Type, Protocol};
use crate::config::BridgeConfig;

fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string())
        .trim()
        .parse()
        .unwrap_or(0)
}

pub async fn start_server(cfg: Arc<BridgeConfig>) {
    log::info!("📢 Motor RADVD iniciado na interface {}", cfg.name);

    let prefix_ip: Ipv6Addr = cfg.ipv6_prefix.parse().unwrap_or(Ipv6Addr::UNSPECIFIED);
    let socket_type = Type::from(libc::SOCK_RAW);
    
    let socket = Socket::new(Domain::IPV6, socket_type, Some(Protocol::ICMPV6))
        .expect("Falha ao criar Raw Socket IPv6");

    let _ = socket.set_multicast_hops_v6(255);
    let _ = socket.bind_device(Some(cfg.name.as_bytes()));

    let ifindex = get_ifindex(&cfg.name);
    let dest_addr = SocketAddrV6::new("ff02::1".parse().unwrap(), 0, 0, ifindex);

    // Forjando o pacote RA (Router Advertisement)
    let mut ra = vec![
        134, 0, 0, 0, // Tipo 134, Código 0, Checksum 0
        64,           // Hop Limit
        0xC0,         // M=1 (Managed), O=1 (Other)
        0x07, 0x08,   // Lifetime 1800s
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Opção de Prefixo
    ra.extend_from_slice(&[
        3, 4,         // Opção 3, Tamanho 4
        cfg.ipv6_prefix_len, 
        0x80,         // L=1 (On-Link), A=0 (SLAAC OFF)
        0, 0, 0x0e, 0x10, 0, 0, 0x0e, 0x10,
        0, 0, 0, 0,
    ]);
    ra.extend_from_slice(&prefix_ip.octets());

    loop {
        if let Err(e) = socket.send_to(&ra, &dest_addr.into()) {
            log::error!("Erro ao enviar RA em {}: {}", cfg.name, e);
        }
        sleep(Duration::from_secs(10)).await;
    }
}