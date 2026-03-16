use std::net::Ipv6Addr;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, checksum};
use pnet::packet::icmpv6::ndp::{NeighborSolicitPacket};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use crate::config::BridgeConfig;

pub async fn start_proxy(proxy_cfg: BridgeConfig, all_configs: Vec<BridgeConfig>) {
    log::info!("🛡️ [NDP-Proxy] Escutando na interface externa: {}", proxy_cfg.name);

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == proxy_cfg.name)
        .expect("Interface externa não encontrada");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Erro ao abrir canal Ethernet na interface {}", proxy_cfg.name),
    };

    // Filtramos os prefixos das bridges que são do tipo "server"
    let target_prefixes: Vec<(Ipv6Addr, u8)> = all_configs.iter()
        .filter(|c| c.mode == "server")
        .filter_map(|c| {
            let ip = c.ipv6_prefix.split('/').next()?.parse::<Ipv6Addr>().ok()?;
            Some((ip, c.ipv6_prefix_len))
        })
        .collect();

    log::info!("   🔍 [NDP-Proxy] Monitorizando {} prefixos internos", target_prefixes.len());

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Ipv6 {
                        if let Some(reply) = process_packet(&eth, &interface, &target_prefixes) {
                            let _ = tx.send_to(&reply, None);
                        }
                    }
                }
            },
            Err(e) => log::error!("Erro NDP RX: {}", e),
        }
    }
}

fn process_packet(eth: &EthernetPacket, iface: &NetworkInterface, prefixes: &[(Ipv6Addr, u8)]) -> Option<Vec<u8>> {
    let ipv6 = Ipv6Packet::new(eth.payload())?;
    let icmp = Icmpv6Packet::new(ipv6.payload())?;

    if icmp.get_icmpv6_type() == Icmpv6Types::NeighborSolicit {
        let ns = NeighborSolicitPacket::new(ipv6.payload())?;
        let target_ip = ns.get_target_addr();

        for (prefix, len) in prefixes {
            if is_in_range(target_ip, *prefix, *len) {
                log::info!("   🎯 [NDP-Proxy] Alvo intercetado: {} -> Respondendo", target_ip);
                return Some(build_na(iface.mac.unwrap(), eth.get_source(), target_ip, ipv6.get_source()));
            }
        }
    }
    None
}

fn is_in_range(target: Ipv6Addr, prefix: Ipv6Addr, len: u8) -> bool {
    let bytes = (len / 8) as usize;
    target.octets()[..bytes] == prefix.octets()[..bytes]
}

fn build_na(my_mac: MacAddr, dst_mac: MacAddr, target_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Vec<u8> {
    let mut buffer = vec![0u8; 86];
    
    let mut eth = MutableEthernetPacket::new(&mut buffer[0..14]).unwrap();
    eth.set_source(my_mac); eth.set_destination(dst_mac); eth.set_ethertype(EtherTypes::Ipv6);
    
    let mut ipv6 = MutableIpv6Packet::new(&mut buffer[14..54]).unwrap();
    ipv6.set_version(6); ipv6.set_payload_length(32);
    ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6.set_hop_limit(255); ipv6.set_source(target_ip); ipv6.set_destination(dst_ip);
    
    buffer[54] = 136; // Tipo NA
    buffer[58] = 0x60; // Flags: Solicited (0x40) + Override (0x20)
    buffer[62..78].copy_from_slice(&target_ip.octets());
    
    buffer[78] = 2; // Option: Target Link-Layer Address
    buffer[79] = 1;
    buffer[80..86].copy_from_slice(&my_mac.octets());
    
    let cs = checksum(&Icmpv6Packet::new(&buffer[54..86]).unwrap(), &target_ip, &dst_ip);
    buffer[56] = (cs >> 8) as u8; buffer[57] = (cs & 0xff) as u8;
    
    buffer
}