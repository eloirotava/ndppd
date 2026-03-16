use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::net::UdpSocket;
use socket2::{Socket, Domain, Type, Protocol};
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

/// Obtém o índice da interface para o join do multicast
fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string())
        .trim()
        .parse()
        .unwrap_or(0)
}

pub async fn start_server(cfg: Arc<BridgeConfig>, storage: Arc<LeaseManager>) {
    log::info!("📡 Motor DHCPv6 iniciado na interface {}", cfg.name);

    // Criação do socket com as permissões de reuso para evitar AddrInUse
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).expect("Erro ao criar socket v6");
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_reuse_port(true);
    let _ = sock.bind_device(Some(cfg.name.as_bytes()));

    // Bind na porta padrão DHCPv6 (547)
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0);
    if let Err(e) = sock.bind(&addr.into()) {
        log::error!("❌ [DHCPv6] Falha fatal no bind da porta 547 em {}: {}", cfg.name, e);
        return;
    }

    sock.set_nonblocking(true).expect("Erro ao definir modo não-bloqueante");
    let socket = UdpSocket::from_std(sock.into()).expect("Erro ao converter para UdpSocket");

    // Inscrição no grupo Multicast de Servidores DHCPv6
    let multicast_addr: Ipv6Addr = "ff02::1:2".parse().unwrap();
    let ifindex = get_ifindex(&cfg.name);
    if let Err(e) = socket.join_multicast_v6(&multicast_addr, ifindex) {
        log::warn!("⚠️  Não foi possível entrar no grupo multicast DHCPv6 em {}: {}", cfg.name, e);
    }

    let mut buf = [0u8; 1500];
    loop {
        if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if len < 4 { continue; }

            let msg_type = buf[0];
            // 1 = Solicit, 3 = Request
            if msg_type != 1 && msg_type != 3 { continue; }

            // --- Parsing Manual de Opções (ClientID e IAID) ---
            let mut client_id = Vec::new();
            let mut iaid = vec![0u8; 4];
            let mut offset = 4;

            while offset + 4 <= len {
                let opt_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let opt_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
                offset += 4;

                if offset + opt_len > len { break; }

                if opt_type == 1 {
                    // Copia o Client ID completo (incluindo cabeçalho da opção)
                    client_id.extend_from_slice(&buf[offset - 4 .. offset + opt_len]);
                } else if opt_type == 3 {
                    // IA_NA: Extrai os primeiros 4 bytes que são o IAID
                    if opt_len >= 4 {
                        iaid.copy_from_slice(&buf[offset .. offset + 4]);
                    }
                }
                offset += opt_len;
            }

            // --- Lógica de Persistência (Lease) ---
            let peer_str = peer.to_string();
            let lease = storage.get_lease(&peer_str).unwrap_or_else(|| {
                // Gera um IP sugerido a partir do prefixo (ex: ...::2)
                let ip_sugerido = cfg.ipv6_prefix.split('/').next().unwrap_or("::").replace("::", ":2");
                storage.set_lease(&peer_str, "10.0.0.x".to_string(), ip_sugerido);
                storage.get_lease(&peer_str).unwrap()
            });

            let offered_ipv6: Ipv6Addr = lease.ipv6.parse().unwrap_or(Ipv6Addr::UNSPECIFIED);

            // --- Forja da Resposta Binária ---
            let mut out = Vec::new();
            
            // 1. Tipo: Solicit -> Advertise (2), Request -> Reply (7)
            out.push(if msg_type == 1 { 2 } else { 7 });
            
            // 2. Transaction ID (Copiado do cliente)
            out.extend_from_slice(&buf[1..4]);

            // 3. Option: Client ID (Devolvido)
            out.extend_from_slice(&client_id);

            // 4. Option: Server ID (Fixo: 02:42:00:00:00:01)
            out.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1, 0x02, 0x42, 0x00, 0x00, 0x00, 0x01]);

            // 5. Option: IA_NA (Identidade da Interface)
            out.extend_from_slice(&[0, 3, 0, 40]); // Tipo 3, Len 40
            out.extend_from_slice(&iaid);
            out.extend_from_slice(&[0, 0, 0x0e, 0x10, 0, 0, 0x15, 0x18]); // T1, T2

            // 5.1 Sub-Option: IA_ADDR (O IP real)
            out.extend_from_slice(&[0, 5, 0, 24]); // Tipo 5, Len 24
            out.extend_from_slice(&offered_ipv6.octets());
            out.extend_from_slice(&[0, 0, 0x1c, 0x20, 0, 0, 0x2a, 0x30]); // Lifetimes

            // 6. Option: DNS (Cloudflare como fallback)
            out.extend_from_slice(&[0, 23, 0, 16]);
            out.extend_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());

            if let Err(e) = socket.send_to(&out, peer).await {
                log::error!("Erro ao enviar resposta DHCPv6 em {}: {}", cfg.name, e);
            } else {
                let res_type = if msg_type == 1 { "ADVERTISE" } else { "REPLY" };
                log::info!("   🎉 [DHCPv6] {} enviado para {} (IP: {})", res_type, peer_str, offered_ipv6);
            }
        }
    }
}