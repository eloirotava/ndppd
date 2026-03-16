use ini::Ini;
use std::net::{Ipv4Addr, IpAddr};
use pnet::datalink; // Necessário pnet no Cargo.toml

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub name: String,
    pub mode: String,
    pub ipv4_network: String,
    pub ipv4_mask: String,
    pub ipv4_gateway: String,
    pub ipv4_range_start: String,
    pub ipv6_prefix: String,
    pub ipv6_prefix_len: u8,
}

pub struct AppConfig {
    pub bridges: Vec<BridgeConfig>,
    pub leases_file: String,
}

pub fn load_config(path: &str) -> AppConfig {
    let conf = Ini::load_from_file(path).expect("Erro ao carregar ndp.conf");
    let mut bridges = Vec::new();
    let mut leases_file = String::from("leases.json");

    // Coleta as interfaces do sistema para autodetecção
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

        // 1. Valores Iniciais (Fallbacks)
        let mut v4_net = "10.0.0.0".to_string();
        let mut v4_mask = "255.0.0.0".to_string();
        let mut v4_gw = "10.0.0.1".to_string();
        let mut v6_pre = "::".to_string();
        let mut v6_len = 64;

        // 2. Autodetecção inteligente pela Interface
        if let Some(iface) = all_interfaces.iter().find(|i| i.name == name) {
            // Detecta IPv4, Máscara e define Gateway como o IP da bridge
            if let Some(ip_net) = iface.ips.iter().find(|ip| ip.is_ipv4()) {
                if let (IpAddr::V4(addr), IpAddr::V4(mask)) = (ip_net.ip(), ip_net.mask()) {
                    let network = u32::from(addr) & u32::from(mask);
                    v4_net = Ipv4Addr::from(network).to_string();
                    v4_mask = mask.to_string();
                    v4_gw = addr.to_string(); 
                }
            }
            // Detecta IPv6 Global/ULA para o RADVD e NDP
            if let Some(ip_net) = iface.ips.iter().find(|ip| ip.is_ipv6() && !ip.ip().is_loopback() && !ip.ip().is_multicast()) {
                v6_pre = ip_net.ip().to_string();
                v6_len = ip_net.prefix();
            }
        }

        // 3. Sobrescrita manual (O que estiver no arquivo .conf tem prioridade)
        if let Some(raw_v4) = prop.get("ipv4_network") {
            let (addr, mask) = parse_ipv4_cidr(raw_v4);
            v4_net = addr;
            v4_mask = mask;
        }
        
        if let Some(gw) = prop.get("ipv4_gateway") {
            v4_gw = gw.trim().to_string();
        }

        if let Some(raw_v6) = prop.get("ipv6_prefix") {
            let (addr, len) = parse_ipv6_cidr(raw_v6);
            v6_pre = addr;
            v6_len = len;
        }

        bridges.push(BridgeConfig {
            name,
            mode: prop.get("type").map(|s| s.trim().to_string()).unwrap_or_else(|| "server".to_string()),
            ipv4_network: v4_net,
            ipv4_mask: v4_mask,
            ipv4_gateway: v4_gw,
            ipv4_range_start: prop.get("ipv4_range_start").map(|s| s.trim().to_string()).unwrap_or_else(|| "10.0.0.2".to_string()),
            ipv6_prefix: v6_pre,
            ipv6_prefix_len: v6_len,
        });
    }
    AppConfig { bridges, leases_file }
}

fn parse_ipv4_cidr(input: &str) -> (String, String) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].trim().to_string();
    let prefix = if parts.len() > 1 { parts[1].trim().parse::<u8>().unwrap_or(24) } else { 24 };
    let mask = if prefix == 0 { 0 } else { 0xffffffffu32 << (32 - prefix) };
    (addr, Ipv4Addr::from(mask).to_string())
}

fn parse_ipv6_cidr(input: &str) -> (String, u8) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].trim().to_string();
    let len = if parts.len() > 1 { parts[1].trim().parse::<u8>().unwrap_or(64) } else { 64 };
    (addr, len)
}