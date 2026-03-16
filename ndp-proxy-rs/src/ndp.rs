use std::net::Ipv6Addr;
use std::os::unix::io::AsRawFd;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, checksum};
use pnet::packet::icmpv6::ndp::NeighborSolicitPacket;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio::io::unix::AsyncFd;
use crate::config::BridgeConfig;

pub async fn start_proxy(cfg: BridgeConfig) -> anyhow::Result<()> {
    log::info!("🛡️ Motor NDP Proxy iniciado em '{}'", cfg.name);
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::RAW, Some(socket2::Protocol::ICMPV6))?;
    socket.bind_device(Some(cfg.name.as_bytes()))?;
    socket.set_nonblocking(true)?;
    let async_fd = AsyncFd::new(socket)?;
    let mut buf = [0u8; 1500];

    loop {
        let mut guard = async_fd.readable().await?;
        match guard.try_io(|fd| {
            let res = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if res < 0 { return Err(std::io::Error::last_os_error()); }
            Ok(res as usize)
        }) {
            Ok(Ok(len)) => {
                if let Some(reply) = process_ndp(&buf[..len], &cfg) {
                    let _ = unsafe { libc::write(async_fd.as_raw_fd(), reply.as_ptr() as *const libc::c_void, reply.len()) };
                }
            },
            _ => continue,
        }
    }
}

fn process_ndp(buf: &[u8], cfg: &BridgeConfig) -> Option<Vec<u8>> {
    let eth = EthernetPacket::new(buf)?;
    let ipv6 = Ipv6Packet::new(eth.payload())?;
    let icmp = Icmpv6Packet::new(ipv6.payload())?;
    if icmp.get_icmpv6_type() == Icmpv6Types::NeighborSolicit {
        if let Some(ns) = NeighborSolicitPacket::new(ipv6.payload()) {
            let target = ns.get_target_addr();
            let prefix_ip: Ipv6Addr = cfg.ipv6_prefix.parse().ok()?;
            if target.octets().starts_with(&prefix_ip.octets()[..10]) {
                return Some(build_na(eth.get_destination(), eth.get_source(), target, ipv6.get_source()));
            }
        }
    }
    None
}

fn build_na(my_mac: MacAddr, dst_mac: MacAddr, target_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Vec<u8> {
    let mut buffer = vec![0u8; 86];
    let mut eth = MutableEthernetPacket::new(&mut buffer[0..14]).unwrap();
    eth.set_source(my_mac); eth.set_destination(dst_mac); eth.set_ethertype(EtherTypes::Ipv6);
    let mut ipv6 = MutableIpv6Packet::new(&mut buffer[14..54]).unwrap();
    ipv6.set_version(6); ipv6.set_payload_length(32); ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6.set_hop_limit(255); ipv6.set_source(target_ip); ipv6.set_destination(dst_ip);
    buffer[54] = 136; buffer[58] = 0x60;
    buffer[62..78].copy_from_slice(&target_ip.octets());
    buffer[78] = 2; buffer[79] = 1; buffer[80..86].copy_from_slice(&my_mac.octets());
    let cs = checksum(&Icmpv6Packet::new(&buffer[54..86]).unwrap(), &target_ip, &dst_ip);
    buffer[56] = (cs >> 8) as u8; buffer[57] = (cs & 0xff) as u8;
    buffer
}