use std::sync::Arc;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use dhcproto::v4::{Message, MessageType, Opcode, DhcpOption, OptionCode};
use dhcproto::{Decoder, Decodable, Encoder, Encodable};
use socket2::{Socket, Domain, Type, Protocol};
use rand::Rng; // Importado para aleatoriedade
use crate::config::BridgeConfig;
use crate::storage::LeaseManager;

pub async fn start_server(config: Arc<BridgeConfig>, storage: Arc<LeaseManager>) {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("Erro socket");
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_reuse_port(true); 
    let _ = sock.set_broadcast(true);
    let _ = sock.bind_device(Some(config.name.as_bytes()));

    let addr: SocketAddr = "0.0.0.0:67".parse().unwrap();
    let _ = sock.bind(&addr.into());
    sock.set_nonblocking(true).unwrap();
    let socket = UdpSocket::from_std(sock.into()).unwrap();
    let mut buf = [0u8; 1500];

    loop {
        if let Ok((len, _)) = socket.recv_from(&mut buf).await {
            let mut decoder = Decoder::new(&buf[..len]);
            if let Ok(msg) = <Message as Decodable>::decode(&mut decoder) {
                let mtype = msg.opts().get(OptionCode::MessageType)
                    .and_then(|opt| if let DhcpOption::MessageType(t) = opt { Some(*t) } else { None })
                    .unwrap_or(MessageType::Discover);

                let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                    msg.chaddr()[0], msg.chaddr()[1], msg.chaddr()[2], 
                    msg.chaddr()[3], msg.chaddr()[4], msg.chaddr()[5]);

                // LÓGICA DE IP ALEATÓRIO NO INTERVALO
                let lease = storage.get_lease(&mac).unwrap_or_else(|| {
                    let mut rng = rand::thread_rng();
                    let net_u32 = u32::from(config.ipv4_network.parse::<Ipv4Addr>().unwrap());
                    let mask_u32 = u32::from(config.ipv4_mask.parse::<Ipv4Addr>().unwrap());
                    
                    let mut random_ip;
                    loop {
                        let rand_val: u32 = rng.gen();
                        // Aplica a máscara: mantém a parte da rede e randomiza a parte do host
                        random_ip = (net_u32 & mask_u32) | (rand_val & !mask_u32);
                        
                        // Validações: evita endereço de rede, broadcast e o gateway (.1)
                        if random_ip != (net_u32 & mask_u32) && 
                           random_ip != (net_u32 | !mask_u32) && 
                           random_ip != ((net_u32 & mask_u32) | 1) { 
                            break; 
                        }
                    }
                    
                    let ip_str = Ipv4Addr::from(random_ip).to_string();
                    storage.set_lease(&mac, ip_str, "".to_string());
                    storage.get_lease(&mac).unwrap()
                });

                let offered_ip: Ipv4Addr = lease.ipv4.parse().unwrap_or(Ipv4Addr::new(10,0,0,2));
                
                // Mantém a sua lógica de Gateway sendo o .1 da rede oferecida
                let mut gw_octets = offered_ip.octets();
                gw_octets[3] = 1;
                let server_ip = Ipv4Addr::from(gw_octets);
                let mask: Ipv4Addr = config.ipv4_mask.parse().unwrap_or(Ipv4Addr::new(255,0,0,0));

                let mut reply = Message::default();
                reply.set_opcode(Opcode::BootReply)
                     .set_htype(msg.htype())
                     .set_xid(msg.xid())
                     .set_flags(msg.flags())
                     .set_chaddr(msg.chaddr())
                     .set_yiaddr(offered_ip)
                     .set_siaddr(server_ip);

                let opts = reply.opts_mut();
                opts.insert(DhcpOption::MessageType(if mtype == MessageType::Discover { MessageType::Offer } else { MessageType::Ack }));
                opts.insert(DhcpOption::ServerIdentifier(server_ip));
                opts.insert(DhcpOption::SubnetMask(mask));
                opts.insert(DhcpOption::Router(vec![server_ip]));
                opts.insert(DhcpOption::DomainNameServer(vec![Ipv4Addr::new(1,1,1,1), Ipv4Addr::new(8,8,8,8)]));
                opts.insert(DhcpOption::AddressLeaseTime(86400));

                let mut out_buf = Vec::new();
                let mut encoder = Encoder::new(&mut out_buf);
                if reply.encode(&mut encoder).is_ok() {
                    let _ = socket.send_to(&out_buf, "255.255.255.255:68").await;
                    log::info!("   ✅ [DHCPv4] {} {} enviado para {}", if mtype == MessageType::Discover {"OFFER"} else {"ACK"}, offered_ip, mac);
                }
            }
        }
    }
}