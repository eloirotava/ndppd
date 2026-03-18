use std::sync::Arc;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use dhcproto::v4::{Message, MessageType, Opcode, DhcpOption, OptionCode};
use dhcproto::{Decoder, Decodable, Encoder, Encodable};
use socket2::{Socket, Domain, Type, Protocol};
use rand::Rng;

use pnet::datalink::{self, Channel};
use pnet::packet::Packet; 
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket, ArpHardwareTypes};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use crate::config::BridgeConfig;
use crate::storage::LeaseManager;
use crate::firewall::FirewallManager;

fn is_ipv4_in_use(iface_name: &str, target_ip: Ipv4Addr) -> bool {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| iface.name == iface_name).expect("Interface não encontrada");
    
    let source_mac = interface.mac.unwrap_or(MacAddr::zero());
    let source_ip = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => Ipv4Addr::UNSPECIFIED,
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return false,
    };

    let mut eth_buf = [0u8; 42]; 
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(source_mac);
    eth_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buf).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);
    
    eth_packet.set_payload(arp_packet.packet()); 

    let _ = tx.send_to(eth_packet.packet(), None);

    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(400) {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply && arp.get_sender_proto_addr() == target_ip {
                            return true; 
                        }
                    }
                }
            }
        }
    }
    false
}

pub async fn start_server(config: Arc<BridgeConfig>, storage: Arc<LeaseManager>, fw: Arc<FirewallManager>) {
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

                // CORREÇÃO: Lê o lease ou cria um vazio
                let mut lease = storage.get_lease(&mac).unwrap_or_else(|| crate::storage::Lease {
                    ipv4: String::new(), ipv6: String::new(),
                });

                // CORREÇÃO: Só gera IPv4 se estiver vazio
                if lease.ipv4.is_empty() {
                    let mut rng = rand::thread_rng();
                    let net_u32 = u32::from(config.ipv4_network.parse::<Ipv4Addr>().unwrap());
                    let mask_u32 = u32::from(config.ipv4_mask.parse::<Ipv4Addr>().unwrap());
                    let gw_u32 = u32::from(config.ipv4_gateway.parse::<Ipv4Addr>().expect("Gateway no conf é obrigatório"));
                    
                    let mut ip_str;
                    loop {
                        let rand_val: u32 = rng.gen();
                        let candidate = (net_u32 & mask_u32) | (rand_val & !mask_u32);
                        let cand_ip = Ipv4Addr::from(candidate);
                        ip_str = cand_ip.to_string();
                        
                        if candidate != (net_u32 & mask_u32) && 
                           candidate != (net_u32 | !mask_u32) && 
                           candidate != gw_u32 &&
                           !is_ipv4_in_use(&config.name, cand_ip) { 
                            break; 
                        }
                    }
                    lease.ipv4 = ip_str.clone();
                    storage.set_lease(&mac, ip_str, "".to_string());
                }

                if config.use_nftables && mtype == MessageType::Request && !lease.ipv4.is_empty() {
                    fw.bind_mac_to_ipv4(&mac, &lease.ipv4);
                }

                let offered_ip: Ipv4Addr = lease.ipv4.parse().unwrap_or(Ipv4Addr::new(10,0,0,2));
                let server_ip: Ipv4Addr = config.ipv4_gateway.parse().unwrap_or(Ipv4Addr::new(10,0,0,1));
                let mask: Ipv4Addr = config.ipv4_mask.parse().unwrap_or(Ipv4Addr::new(255,0,0,0));

                let mut reply = Message::default();
                reply.set_opcode(Opcode::BootReply).set_htype(msg.htype()).set_xid(msg.xid())
                     .set_flags(msg.flags()).set_chaddr(msg.chaddr()).set_yiaddr(offered_ip).set_siaddr(server_ip);

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
                    log::info!("   ✅ [DHCPv4] {} {} para {}", if mtype == MessageType::Discover {"OFFER"} else {"ACK"}, offered_ip, mac);
                }
            }
        }
    }
}