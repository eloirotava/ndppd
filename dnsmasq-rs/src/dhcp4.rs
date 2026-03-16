use std::sync::Arc;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use dhcproto::v4::{Message, MessageType, Opcode, DhcpOption};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Socket, Domain, Type, Protocol};
use crate::config::NetConfig;

pub async fn start_server(config: Arc<NetConfig>) {
    log::info!("Motor DHCPv4 [Porta 67] inicializado. Escutando na rede...");

    // Cria o socket no nível do SO para podermos travar na interface (SO_BINDTODEVICE)
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("Falha ao criar socket IPv4");
    sock.set_broadcast(true).expect("Falha ao ativar broadcast");
    sock.set_reuse_address(true).expect("Falha ao ativar reuse_address");
    
    // Trava o socket na br1 (ou o que estiver no conf)
    if let Err(e) = sock.bind_device(Some(config.interface.as_bytes())) {
        log::warn!("Aviso: Falha ao prender DHCPv4 na interface {}: {}", config.interface, e);
    }

    let addr: SocketAddr = "0.0.0.0:67".parse().unwrap();
    sock.bind(&addr.into()).expect("Falha ao fazer bind na porta 67");
    sock.set_nonblocking(true).expect("Falha ao ativar modo assíncrono");

    // Transforma o socket do SO num socket Assíncrono do Tokio
    let socket = UdpSocket::from_std(sock.into()).unwrap();

    let mut buf = [0u8; 1500];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let mut decoder = Decoder::new(&buf[..len]);
                if let Ok(msg) = Message::decode(&mut decoder) {
                    if let Some(msg_type) = msg.opts().msg_type() {
                        let mac_hex: Vec<String> = msg.chaddr().iter().map(|b| format!("{:02x}", b)).collect();
                        let mac_str = mac_hex[0..6].join(":");

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
                                    // AGORA SIM: Broadcast global. O SO_BINDTODEVICE garante que saia pela br1!
                                    if let Err(e) = socket.send_to(&out_buf, "255.255.255.255:68").await {
                                        log::error!("Erro ao enviar DHCPOFFER: {}", e);
                                    } else {
                                        log::info!("   🎯 DHCPOFFER enviado em Broadcast para o MAC {}", mac_str);
                                    }
                                }
                            }
                            MessageType::Request => {
                                log::info!("✅ DHCPREQUEST recebido! MAC: {}", mac_str);
                                
                                let mut ack = Message::default();
                                ack.set_opcode(Opcode::BootReply)
                                   .set_htype(msg.htype())
                                   .set_xid(msg.xid())
                                   .set_flags(msg.flags())
                                   .set_chaddr(msg.chaddr())
                                   .set_yiaddr(offered_ip)
                                   .set_siaddr(server_ip);

                                ack.opts_mut().insert(DhcpOption::MessageType(MessageType::Ack));
                                ack.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
                                ack.opts_mut().insert(DhcpOption::AddressLeaseTime(43200));
                                ack.opts_mut().insert(DhcpOption::SubnetMask(netmask));
                                ack.opts_mut().insert(DhcpOption::Router(vec![server_ip]));
                                ack.opts_mut().insert(DhcpOption::DomainNameServer(vec![dns1, dns2]));

                                let mut out_buf = Vec::new();
                                let mut encoder = Encoder::new(&mut out_buf);
                                if ack.encode(&mut encoder).is_ok() {
                                    // ACK também em broadcast
                                    if let Err(e) = socket.send_to(&out_buf, "255.255.255.255:68").await {
                                        log::error!("Erro ao enviar DHCPACK: {}", e);
                                    } else {
                                        log::info!("   🎉 DHCPACK enviado! Negócio fechado para o MAC {}", mac_str);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
}