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

                            match msg_type {
                                MessageType::Discover => {
                                    log::info!("🔍 DHCPDISCOVER recebido! MAC: {} (Vindo de {})", mac_str, peer);
                                    
                                    // 1. Criar a mensagem de resposta (DHCPOFFER)
                                    let mut offer = Message::default();
                                    offer.set_op(Opcode::BootReply);  // 2 = Reply
                                    offer.set_htype(msg.htype());     // Ethernet
                                    offer.set_hlen(msg.hlen());       // 6 bytes MAC
                                    offer.set_xid(msg.xid());         // Transaction ID igual ao do request
                                    offer.set_flags(msg.flags());
                                    offer.set_chaddr(msg.chaddr());   // Mesmo MAC do destino
                                    
                                    // 2. Preencher os IPs usando o nosso cérebro (config.rs)
                                    let offered_ip: Ipv4Addr = config.ipv4_range_start.parse().unwrap_or(Ipv4Addr::new(10,0,0,2));
                                    let server_ip: Ipv4Addr = config.ipv4_gateway.parse().unwrap_or(Ipv4Addr::new(10,0,0,1));
                                    let netmask: Ipv4Addr = config.ipv4_netmask.parse().unwrap_or(Ipv4Addr::new(255,0,0,0));
                                    
                                    // Pega os DNS do conf ou usa fallback
                                    let dns1: Ipv4Addr = config.ipv4_dns.get(0).unwrap_or(&"1.1.1.1".to_string()).parse().unwrap_or(Ipv4Addr::new(1,1,1,1));
                                    let dns2: Ipv4Addr = config.ipv4_dns.get(1).unwrap_or(&"8.8.8.8".to_string()).parse().unwrap_or(Ipv4Addr::new(8,8,8,8));

                                    offer.set_yiaddr(offered_ip); // O IP que estamos oferecendo ("Your IP")
                                    offer.set_siaddr(server_ip);  // Quem somos nós ("Server IP")

                                    // 3. Adicionar as Opções (As famosas options do DHCP)
                                    offer.opts_mut().insert(DhcpOption::MessageType(MessageType::Offer));
                                    offer.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
                                    offer.opts_mut().insert(DhcpOption::AddressLeaseTime(43200)); // 12 horas
                                    offer.opts_mut().insert(DhcpOption::SubnetMask(netmask));
                                    offer.opts_mut().insert(DhcpOption::Router(vec![server_ip]));
                                    offer.opts_mut().insert(DhcpOption::DomainNameServer(vec![dns1, dns2]));

                                    // 4. Transformar em bytes e atirar de volta em Broadcast (Porta 68)
                                    let mut out_buf = Vec::new();
                                    let mut encoder = Encoder::new(&mut out_buf);
                                    if let Ok(_) = offer.encode(&mut encoder) {
                                        if let Err(e) = socket.send_to(&out_buf, "255.255.255.255:68").await {
                                            log::error!("Erro ao enviar DHCPOFFER: {}", e);
                                        } else {
                                            log::info!("   🎯 DHCPOFFER enviado! Oferecendo IP: {} para o MAC {}", offered_ip, mac_str);
                                        }
                                    }
                                }
                                MessageType::Request => {
                                    log::info!("✅ DHCPREQUEST recebido! MAC: {}", mac_str);
                                    // TODO: Próxima fase! Receber o Request e responder com um ACK!
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