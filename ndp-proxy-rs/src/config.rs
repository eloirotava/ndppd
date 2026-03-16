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
    let conf = Ini::load_from_file(path).expect("Erro ao carregar arquivo de configuracao");
    let mut bridges = Vec::new();
    let mut leases_file = String::from("leases.json");

    for (sec, prop) in conf.iter() {
        // Correção E0282: Especificando que 'name' é String de forma clara
        let name: String = match sec {
            Some(s) => s.to_string(),
            None => "default".to_string(),
        };
        
        if name == "general" {
            if let Some(val) = prop.get("persistence_file") {
                leases_file = val.to_string();
            }
            continue;
        }

        let raw_v4 = prop.get("ipv4_network").unwrap_or(&"10.0.0.0/8".to_string()).to_string();
        let (v4_addr, v4_mask) = parse_ipv4_cidr(&raw_v4);

        let raw_v6 = prop.get("ipv6_prefix").unwrap_or(&"::/64".to_string()).to_string();
        let (v6_addr, v6_len) = parse_ipv6_cidr(&raw_v6);

        bridges.push(BridgeConfig {
            name,
            mode: prop.get("type").unwrap_or(&"server".to_string()).to_string(),
            ipv4_network: v4_addr,
            ipv4_mask: v4_mask,
            ipv4_range_start: prop.get("ipv4_range_start").unwrap_or(&"".to_string()).to_string(),
            ipv6_prefix: v6_addr,
            ipv6_prefix_len: v6_len,
        });
    }
    AppConfig { bridges, leases_file }
}

fn parse_ipv4_cidr(input: &str) -> (String, String) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].to_string();
    let prefix = if parts.len() > 1 { parts[1].parse::<u8>().unwrap_or(24) } else { 24 };
    
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let mask_addr = Ipv4Addr::from(mask.to_be());
    (addr, mask_addr.to_string())
}

fn parse_ipv6_cidr(input: &str) -> (String, u8) {
    let parts: Vec<&str> = input.split('/').collect();
    let addr = parts[0].to_string();
    let len = if parts.len() > 1 { parts[1].parse::<u8>().unwrap_or(64) } else { 64 };
    (addr, len)
}