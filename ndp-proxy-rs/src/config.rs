use ini::Ini;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub name: String,
    pub mode: String,
    pub ipv4_network: String,
    pub ipv4_mask: String,
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

    for (sec, prop) in conf.iter() {
        let name: String = match sec {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => continue, // Ignora seções vazias ou nulas
        };
        
        if name == "general" {
            if let Some(val) = prop.get("persistence_file") {
                leases_file = val.trim().to_string();
            }
            continue;
        }

        let raw_v4 = prop.get("ipv4_network").map(|s| s.trim()).unwrap_or("10.0.0.0/8");
        let (v4_addr, v4_mask) = parse_ipv4_cidr(raw_v4);

        let raw_v6 = prop.get("ipv6_prefix").map(|s| s.trim()).unwrap_or("::/64");
        let (v6_addr, v6_len) = parse_ipv6_cidr(raw_v6);

        bridges.push(BridgeConfig {
            name,
            mode: prop.get("type").map(|s| s.trim().to_string()).unwrap_or_else(|| "server".to_string()),
            ipv4_network: v4_addr,
            ipv4_mask: v4_mask,
            ipv4_range_start: prop.get("ipv4_range_start").map(|s| s.trim().to_string()).unwrap_or_else(|| "10.0.0.2".to_string()),
            ipv6_prefix: v6_addr,
            ipv6_prefix_len: v6_len,
        });
    }
    AppConfig { bridges, leases_file }
}

fn parse_ipv4_cidr(input: &str) -> (String, String) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].trim().to_string();
    let prefix = if parts.len() > 1 { parts[1].trim().parse::<u8>().unwrap_or(24) } else { 24 };
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let mask_addr = Ipv4Addr::from(mask.to_be());
    (addr, mask_addr.to_string())
}

fn parse_ipv6_cidr(input: &str) -> (String, u8) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].trim().to_string();
    let len = if parts.len() > 1 { parts[1].trim().parse::<u8>().unwrap_or(64) } else { 64 };
    (addr, len)
}