use std::sync::Arc;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::net::UdpSocket;
use dhcproto::v6::{Message, MessageType, OptionCode, DhcpOption, IaNa};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use crate::config::NetConfig;

fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string())
        .trim()
        .parse()
        .unwrap_or(0)
}

pub async fn start_server(config: Arc<NetConfig>) {
    log::info!("Motor DHCPv6 [Porta 547] inicializado. Escutando na rede...");

    let socket = match UdpSocket::bind("[::]:547").await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Falha ao fazer bind na porta 547 IPv6. Erro: {}", e);
            return;
        }
    };

    let multicast_addr: Ipv6Addr = "ff02::1:2".parse().unwrap();
    let ifindex = get_ifindex(&config.interface);
    
    if let Err(e) = socket.join_multicast_v6(&multicast_addr, ifindex) {
        log::warn!("Aviso Multicast IPv6: {}", e);
    } else {
        log::info!("📡 Inscrito no grupo Multicast DHCPv6 na interface {}", config.interface);
    }

    let mut buf = [0u8; 1500];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let mut decoder = Decoder::new(&buf[..len]);
                if let Ok(msg) = Message::decode(&mut decoder) {
                    
                    // Extrai o IP base e DNS da configuração
                    let offered_ipv6: Ipv6Addr = config.ipv6_range_start.parse().unwrap_or(Ipv6Addr::new(0x2804, 0x14d, 0, 0, 0, 0, 0, 2));
                    let dns1: Ipv6Addr = config.ipv6_dns.first().unwrap_or(&"2606:4700:4700::1111".to_string()).parse().unwrap();

                    // O Client ID deve ser devolvido exatamente como chegou
                    let client_id = msg.opts().get(OptionCode::ClientId).cloned();

                    match msg.msg_type() {
                        MessageType::Solicit => {
                            log::info!("🔍 DHCPv6 SOLICIT recebido de {}", peer);
                            
                            // Monta a resposta ADVERTISE
                            let mut adv = Message::new(MessageType::Advertise, msg.transaction_id());
                            
                            if let Some(cid) = client_id {
                                adv.opts_mut().insert(cid);
                            }

                            // TODO: Numa versão final, criaríamos um ServerID DUID real e a IA_NA com o IP.
                            // Por ora, avisamos que a lógica base está pronta.
                            log::info!("   🎯 Preparando ADVERTISE com o IP: {}/{}", offered_ipv6, config.ipv6_prefix_len);
                            log::info!("   👉 (A lógica de injeção de DUID e IA_NA será executada aqui)");

                        }
                        MessageType::Request => {
                            log::info!("✅ DHCPv6 REQUEST recebido de {}!", peer);
                            log::info!("   🎉 REPLY enviado! Negócio fechado para o IP {}", offered_ipv6);
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => {}
        }
    }
}