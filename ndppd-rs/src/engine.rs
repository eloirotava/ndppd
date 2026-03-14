use crate::iface::Iface;
use crate::proxy::Proxy;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmpv6::ndp::NeighborSolicitPacket;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv6Addr;

use tokio::io::unix::AsyncFd;

/// O loop principal que escuta tráfego e responde
pub async fn run_loop(iface: Iface, mut proxy: Proxy) -> anyhow::Result<()> {
    tracing::info!("Motor NDP Proxy iniciado na interface '{}'!", iface.name);
    tracing::info!("O meu MAC Address é: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
        iface.mac[0], iface.mac[1], iface.mac[2], iface.mac[3], iface.mac[4], iface.mac[5]);

    let async_fd = AsyncFd::new(iface.as_raw_fd())?;
    let mut buf = [0u8; 1500];

    loop {
        let mut guard = async_fd.readable().await?;
        
        let res = unsafe { libc::read(iface.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(err.into());
        }

        let len = res as usize;
        if len > 0 {
            // Se a função retornar um pacote forjado, nós enviamos!
            if let Some(reply_packet) = process_packet(&buf[..len], &mut proxy, &iface) {
                unsafe {
                    libc::write(
                        iface.as_raw_fd(),
                        reply_packet.as_ptr() as *const libc::c_void,
                        reply_packet.len()
                    );
                }
                tracing::info!("[+] Neighbor Advert (NA) enviado para a rede com sucesso!");
            }
        }

        guard.clear_ready();
    }
}

/// Analisa o pacote recebido e decide se forja uma resposta
fn process_packet(buf: &[u8], proxy: &mut Proxy, iface: &Iface) -> Option<Vec<u8>> {
    let eth = EthernetPacket::new(buf)?;
    if eth.get_ethertype() != EtherTypes::Ipv6 { return None; }
    
    let ipv6 = Ipv6Packet::new(eth.payload())?;
    if ipv6.get_next_header() != pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 { return None; }
    
    let icmp = Icmpv6Packet::new(ipv6.payload())?;
    
    // Só respondemos a solicitações (NS)
    if icmp.get_icmpv6_type() == Icmpv6Types::NeighborSolicit {
        if let Some(ns) = NeighborSolicitPacket::new(ipv6.payload()) {
            
            let target_ip = ns.get_target_addr();
            let src_ip = ipv6.get_source();
            
            // LÓGICA DO PROXY: Este IP está nas nossas regras (/64, etc)?
            if let Some(rule) = proxy.find_rule(&target_ip).cloned() {
                tracing::info!("[<] NS recebido perguntando por: {}", target_ip);
                tracing::info!("[!] Match! A regra ({}) autoriza o proxy.", rule.addr);
                
                let _session = proxy.get_or_create_session(target_ip);
                
                // Se o IP de origem for "::" (unspecified), enviamos para Multicast
                let dst_ip = if src_ip.is_unspecified() {
                    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
                } else {
                    src_ip
                };

                let my_mac = MacAddr::new(iface.mac[0], iface.mac[1], iface.mac[2], iface.mac[3], iface.mac[4], iface.mac[5]);
                let dst_mac = eth.get_source(); // Respondemos ao MAC que nos perguntou
                
                return Some(build_na_packet(my_mac, dst_mac, target_ip, dst_ip, target_ip, proxy.router));
            }
        }
    }

    None
}

/// Constrói o pacote de Neighbor Advertisement a partir do zero
fn build_na_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv6Addr, // O IP que estamos a fazer proxy
    dst_ip: Ipv6Addr, // Quem perguntou
    target_ip: Ipv6Addr,
    router: bool,
) -> Vec<u8> {
    // 14 (Ethernet) + 40 (IPv6) + 32 (ICMPv6 NA + Option MAC) = 86 bytes
    let mut buffer = vec![0u8; 86]; 

    // 1. Camada Ethernet
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer[0..14]).unwrap();
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(EtherTypes::Ipv6);
    }

    // 2. Camada IPv6
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut buffer[14..54]).unwrap();
        ipv6.set_version(6);
        ipv6.set_payload_length(32); 
        ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
        ipv6.set_hop_limit(255); // Obrigatório ser 255 no NDP (RFC 4861)
        ipv6.set_source(src_ip);
        ipv6.set_destination(dst_ip);
    }

    // 3. Camada ICMPv6 (Payload)
    let mut icmp_buf = vec![0u8; 32];
    icmp_buf[0] = 136; // Tipo 136: Neighbor Advertisement
    
    // Flags: Router (R), Solicited (S), Override (O)
    let mut flags = 0u8;
    if router { flags |= 0x80; }
    flags |= 0x40; // Solicited
    flags |= 0x20; // Override
    icmp_buf[4] = flags;
    
    // O IP Alvo
    icmp_buf[8..24].copy_from_slice(&target_ip.octets());
    
    // Opção: Target Link-Layer Address (Tipo 2)
    icmp_buf[24] = 2; // Tipo
    icmp_buf[25] = 1; // Comprimento (1 unidade de 8 bytes)
    icmp_buf[26..32].copy_from_slice(&src_mac.octets());

    // 4. Injeta o Payload e Calcula o Checksum Matemático
    buffer[54..86].copy_from_slice(&icmp_buf);
    let checksum = pnet::packet::icmpv6::checksum(
        &pnet::packet::icmpv6::Icmpv6Packet::new(&buffer[54..86]).unwrap(),
        &src_ip,
        &dst_ip,
    );
    
    buffer[56] = (checksum >> 8) as u8;
    buffer[57] = (checksum & 0xff) as u8;

    buffer
}