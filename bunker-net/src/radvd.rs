use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::time::{sleep, Duration};
use socket2::{Socket, Domain, Type, Protocol};
use crate::config::NetConfig;

// Pequeno truque para pegar o ID da interface direto do Linux
fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string())
        .trim()
        .parse()
        .unwrap_or(0)
}

pub async fn start_server(config: Arc<NetConfig>) {
    if !config.enable_ra {
        log::info!("Motor RADVD desativado na configuração.");
        return;
    }
    
    log::info!("Motor RADVD [ICMPv6 Tipo 134] inicializado. Preparando anúncios...");

    let prefix_ip: Ipv6Addr = match config.ipv6_range_start.parse() {
        Ok(ip) => ip,
        Err(_) => {
            log::error!("Erro: Prefixo IPv6 inválido no ficheiro de configuração!");
            return;
        }
    };

    // CORREÇÃO: Usamos libc::SOCK_RAW para dizer ao Kernel Linux exatamente o que queremos
    let socket_type = Type::from(libc::SOCK_RAW);

    // Cria o Raw Socket IPv6
    let socket = match Socket::new(Domain::IPV6, socket_type, Some(Protocol::ICMPV6)) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Falha ao criar Raw Socket IPv6 (Está a executar como root?). Erro: {}", e);
            return;
        }
    };

    if let Err(e) = socket.set_multicast_hops_v6(255) {
        log::warn!("Não foi possível definir o Hop Limit para 255: {}", e);
    }

    // O bind_device agora funciona porque ativamos a feature "all" no Cargo.toml
    if let Err(e) = socket.bind_device(Some(config.interface.as_bytes())) {
        log::warn!("Aviso: Falha ao fixar o socket na interface {}: {}", config.interface, e);
    }

    let ifindex = get_ifindex(&config.interface);
    let dest_addr = SocketAddrV6::new("ff02::1".parse().unwrap(), 0, 0, ifindex);

    // =========================================================
    // FORJANDO O PACOTE ICMPv6 ROUTER ADVERTISEMENT (Tipo 134)
    // =========================================================
    
    let mut ra = vec![
        134, 0,       // Tipo 134, Código 0
        0, 0,         // Checksum 
        64,           // Hop Limit sugerido
        0xC0,         // MAGIA AQUI: M=1 (DHCPv6) e O=1 
        0x07, 0x08,   // Router lifetime (1800s)
        0, 0, 0, 0,   // Reachable Time 
        0, 0, 0, 0,   // Retrans Timer 
    ];

    ra.extend_from_slice(&[
        3,            // Tipo: Prefix Information
        4,            // Length: 32 bytes
        config.ipv6_prefix_len, // Sub-rede: /80
        0x80,         // MAGIA AQUI: L=1 (On-Link) e A=0 (SLAAC DESATIVADO)
        0, 0, 0x0e, 0x10, // Tempo de vida válido (3600s)
        0, 0, 0x0e, 0x10, // Tempo de vida preferido (3600s)
        0, 0, 0, 0,   // Reservado
    ]);
    
    ra.extend_from_slice(&prefix_ip.octets());

    log::info!("📢 A enviar Router Advertisements (SLAAC Desativado, DHCPv6 Ativo) na interface {} a cada 10s...", config.interface);

    loop {
        if let Err(e) = socket.send_to(&ra, &dest_addr.into()) {
            log::error!("Erro ao enviar pacote RA: {}", e);
        } else {
            // Log comentado para não "sujar" o terminal a cada 10 segundos
            // log::debug!("RA Multicast enviado!");
        }
        
        sleep(Duration::from_secs(10)).await;
    }
}