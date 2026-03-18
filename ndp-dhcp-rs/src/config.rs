use ini::Ini;
use std::net::{Ipv4Addr, IpAddr};
use pnet::datalink; 

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub name: String,
    pub mode: String,
    pub ipv4_network: String,
    pub ipv4_mask: String,
    pub ipv4_prefix_len: u8, // NOVO CAMPO
    pub ipv4_gateway: String,
    pub ipv4_range_start: String,
    pub ipv6_prefix: String,
    pub ipv6_prefix_len: u8,
    pub ipv6_delegation_size: u8,
    pub use_nftables: bool,
    pub enable_nat: bool,
}

pub struct AppConfig {
    pub bridges: Vec<BridgeConfig>,
    pub leases_file: String,
}

pub fn load_config(path: &str) -> AppConfig {
    let conf = Ini::load_from_file(path).expect("Erro ao carregar ndp.conf");
    let mut bridges = Vec::new();
    let mut leases_file = String::from("leases.json");

    let all_interfaces = datalink::interfaces();

    for (sec, prop) in conf.iter() {
        let name = match sec {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => continue,
        };
        
        if name == "general" {
            if let Some(val) = prop.get("persistence_file") {
                leases_file = val.trim().to_string();
            }
            continue;
        }

        let mut v4_net = "10.0.0.0".to_string();
        let mut v4_mask = "255.0.0.0".to_string();
        let mut v4_pref = 8; // Default prefix
        let mut v4_gw = "10.0.0.1".to_string();
        let mut v6_pre = "::".to_string();
        let mut v6_len = 64;
        let mut v6_deleg = 128;
        let mut use_nft = false;
        let mut use_nat = false;

        if let Some(iface) = all_interfaces.iter().find(|i| i.name == name) {
            if let Some(ip_net) = iface.ips.iter().find(|ip| ip.is_ipv4()) {
                if let (IpAddr::V4(addr), IpAddr::V4(mask)) = (ip_net.ip(), ip_net.mask()) {
                    let network = u32::from(addr) & u32::from(mask);
                    v4_net = Ipv4Addr::from(network).to_string();
                    v4_mask = mask.to_string();
                    v4_pref = ip_net.prefix(); // Lê o prefixo (ex: 24) da interface real
                    v4_gw = addr.to_string(); 
                }
            }
            if let Some(ip_net) = iface.ips.iter().find(|ip| ip.is_ipv6() && !ip.ip().is_loopback() && !ip.ip().is_multicast()) {
                v6_pre = ip_net.ip().to_string();
                v6_len = ip_net.prefix();
            }
        }

        if let Some(raw_v4) = prop.get("ipv4_network") {
            let (addr, mask, pref) = parse_ipv4_cidr(raw_v4);
            v4_net = addr;
            v4_mask = mask;
            v4_pref = pref;
        }
        
        if let Some(gw) = prop.get("ipv4_gateway") { v4_gw = gw.trim().to_string(); }

        if let Some(raw_v6) = prop.get("ipv6_prefix") {
            let (addr, len) = parse_ipv6_cidr(raw_v6);
            v6_pre = addr;
            v6_len = len;
        }

        if let Some(raw_deleg) = prop.get("ipv6_delegation_size") {
            v6_deleg = raw_deleg.trim().parse::<u8>().unwrap_or(128);
        }
        if let Some(val) = prop.get("use_nftables") {
            use_nft = val.trim() == "true";
        }
        if let Some(val) = prop.get("enable_nat") {
            use_nat = val.trim() == "true";
        }

        bridges.push(BridgeConfig {
            name,
            mode: prop.get("type").map(|s| s.trim().to_string()).unwrap_or_else(|| "server".to_string()),
            ipv4_network: v4_net,
            ipv4_mask: v4_mask,
            ipv4_prefix_len: v4_pref, // SALVA O PREFIXO AQUI
            ipv4_gateway: v4_gw,
            ipv4_range_start: prop.get("ipv4_range_start").map(|s| s.trim().to_string()).unwrap_or_else(|| "10.0.0.2".to_string()),
            ipv6_prefix: v6_pre,
            ipv6_prefix_len: v6_len,
            ipv6_delegation_size: v6_deleg,
            use_nftables: use_nft,
            enable_nat: use_nat,
        });
    }
    AppConfig { bridges, leases_file }
}

fn parse_ipv4_cidr(input: &str) -> (String, String, u8) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].trim().to_string();
    let prefix = if parts.len() > 1 { parts[1].trim().parse::<u8>().unwrap_or(24) } else { 24 };
    let mask = if prefix == 0 { 0 } else { 0xffffffffu32 << (32 - prefix) };
    (addr, Ipv4Addr::from(mask).to_string(), prefix)
}

fn parse_ipv6_cidr(input: &str) -> (String, u8) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].trim().to_string();
    let len = if parts.len() > 1 { parts[1].trim().parse::<u8>().unwrap_or(64) } else { 64 };
    (addr, len)
}