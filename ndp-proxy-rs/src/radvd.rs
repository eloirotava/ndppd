use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::time::{sleep, Duration};
use socket2::{Socket, Domain, Type, Protocol};
use crate::config::BridgeConfig;

pub async fn start_server(cfg: Arc<BridgeConfig>) {
    log::info!("📢 [RADVD] Iniciando anúncios em {}", cfg.name);

    let prefix_ip: Ipv6Addr = cfg.ipv6_prefix.split('/').next().unwrap_or("::").parse().unwrap_or(Ipv6Addr::UNSPECIFIED);
    
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).expect("Erro socket RA");
    let _ = socket.set_multicast_hops_v6(255);
    let _ = socket.bind_device(Some(cfg.name.as_bytes()));

    // Multicast para todos os hosts
    let dest_addr = SocketAddrV6::new("ff02::1".parse().unwrap(), 0, 0, 0);

    loop {
        // Estrutura do Router Advertisement
        let mut ra = vec![
            134, 0,           // Tipo RA, Código 0
            0, 0,             // Checksum (Kernel preenche)
            64,               // Hop Limit
            0xC0,             // Flags: Managed (M=1), Other (O=1) para forçar o DHCPv6
            0x07, 0x08,       // Router Lifetime: 1800s
            0, 0, 0, 0,       // Reachable Time
            0, 0, 0, 0,       // Retrans Timer
        ];

        // Opção 3: Prefix Information
        ra.extend_from_slice(&[
            3, 4,               // Tipo 3, Len 4 (32 bytes)
            cfg.ipv6_prefix_len, // Comprimento (ex: 80)
            0x80,               // L=1 (On-link), A=0 (Auto/SLAAC OFF)
            0, 0, 0x0e, 0x10,   // Valid Lifetime: 3600s
            0, 0, 0x0e, 0x10,   // Preferred Lifetime: 3600s
            0, 0, 0, 0,         // Reservado
        ]);
        ra.extend_from_slice(&prefix_ip.octets());

        if let Err(e) = socket.send_to(&ra, &dest_addr.into()) {
            log::error!("❌ [RADVD] Erro ao anunciar em {}: {}", cfg.name, e);
        }

        sleep(Duration::from_secs(10)).await;
    }
}