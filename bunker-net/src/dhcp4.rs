use std::sync::Arc;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use dhcproto::v4::{Message, MessageType, Opcode, DhcpOption};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use crate::config::NetConfig;

pub async fn start_server(config: Arc<NetConfig>) {
    log::info!("Motor DHCPv4 [Porta 67] inicializado. Escutando na rede...");

    let socket = match UdpSocket::bind("0.0.0.0:67").await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Falha ao fazer bind na porta 67. Erro: {}", e);
            return;
        }
    };

    if let Err(e) = socket.set_broadcast(true) {
        log::error!("Falha ao habilitar broadcast no socket: {}", e);
    }

    let mut buf = [0u8; 1500];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let mut decoder = Decoder::new(&buf[..len]);
                match Message::decode(&mut decoder) {
                    Ok(msg) => {
                        if let Some(msg_type) = msg.opts().msg_type() {
                            let mac_hex: Vec<String> = msg.chaddr().iter().map(|b| format!("{:02x}", b)).collect();
                            let mac_str = mac_hex[0..6].join(":");

                            // Puxa as configs do cérebro para usar tanto na Oferta quanto no ACK
                            let offered_ip: Ipv4Addr = config.ipv4_range_start.parse().unwrap_or(Ipv4Addr::new(10,0,0,2));
                            let server_ip: Ipv4Addr = config.ipv4_gateway.parse().unwrap_or(Ipv4Addr::new(10,0,0,1));
                            let netmask: Ipv4Addr = config.ipv4_netmask.parse().unwrap_or(Ipv4Addr::new(255,0,0,0));
                            let dns1: Ipv4Addr = config.ipv4_dns.first().unwrap_or(&"1.1.1.1".to_string()).parse().unwrap_or(Ipv4Addr::new(1,1,1,1));
                            let dns2: Ipv4Addr = config.ipv4_dns.get(1).unwrap_or(&"8.8.8.8".to_string()).parse().unwrap_or(Ipv4Addr::new(8,8,8,8));

                            match msg_type {
                                MessageType::Discover => {
                                    log::info!("🔍 DHCPDISCOVER recebido! MAC: {} (Vindo de {})", mac_str, peer);
                                    
                                    let mut offer = Message::default();
                                    offer.set_opcode(Opcode::BootReply)
                                         .set_htype(msg.htype())
                                         .set_xid(msg.xid())
                                         .set_flags(msg.flags())
                                         .set_chaddr(msg.chaddr())
                                         .set_yiaddr(offered_ip)
                                         .set_siaddr(server_ip);

                                    offer.opts_mut().insert(DhcpOption::MessageType(MessageType::Offer));
                                    offer.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
                                    offer.opts_mut().insert(DhcpOption::AddressLeaseTime(43200));
                                    offer.opts_mut().insert(DhcpOption::SubnetMask(netmask));
                                    offer.opts_mut().insert(DhcpOption::Router(vec![server_ip]));
                                    offer.opts_mut().insert(DhcpOption::DomainNameServer(vec![dns1, dns2]));

                                    let mut out_buf = Vec::new();
                                    let mut encoder = Encoder::new(&mut out_buf);
                                    if offer.encode(&mut encoder).is_ok() {
                                        // Lembra que estamos na rede do Docker no Codespace!
                                        if let Err(e) = socket.send_to(&out_buf, "172.17.255.255:68").await {
                                            log::error!("Erro ao enviar DHCPOFFER: {}", e);
                                        } else {
                                            log::info!("   🎯 DHCPOFFER enviado! Oferecendo IP: {} para o MAC {}", offered_ip, mac_str);
                                        }
                                    }
                                }
                                MessageType::Request => {
                                    log::info!("✅ DHCPREQUEST recebido! MAC: {}", mac_str);
                                    
                                    // BATE O MARTELO: Criando o DHCPACK
                                    let mut ack = Message::default();
                                    ack.set_opcode(Opcode::BootReply)
                                       .set_htype(msg.htype())
                                       .set_xid(msg.xid())
                                       .set_flags(msg.flags())
                                       .set_chaddr(msg.chaddr())
                                       .set_yiaddr(offered_ip) // Confirma o IP
                                       .set_siaddr(server_ip);

                                    ack.opts_mut().insert(DhcpOption::MessageType(MessageType::Ack)); // Aqui é ACK!
                                    ack.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
                                    ack.opts_mut().insert(DhcpOption::AddressLeaseTime(43200));
                                    ack.opts_mut().insert(DhcpOption::SubnetMask(netmask));
                                    ack.opts_mut().insert(DhcpOption::Router(vec![server_ip]));
                                    ack.opts_mut().insert(DhcpOption::DomainNameServer(vec![dns1, dns2]));

                                    let mut out_buf = Vec::new();
                                    let mut encoder = Encoder::new(&mut out_buf);
                                    if ack.encode(&mut encoder).is_ok() {
                                        if let Err(e) = socket.send_to(&out_buf, "172.17.255.255:68").await {
                                            log::error!("Erro ao enviar DHCPACK: {}", e);
                                        } else {
                                            log::info!("   🎉 DHCPACK enviado! Negócio fechado. IP {} confirmado para o MAC {}", offered_ip, mac_str);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }
    }
}