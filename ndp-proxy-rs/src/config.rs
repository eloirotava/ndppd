use ini::Ini;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub name: String,
    pub ipv4_range_start: String,
    pub ipv6_prefix: String,
    pub ipv6_prefix_len: u8,
    pub mode: String, // "server" ou "ndp-proxy"
}

pub struct AppConfig {
    pub bridges: Vec<BridgeConfig>,
    pub leases_file: String,
}

pub fn load_config(path: &str) -> AppConfig {
    let conf = Ini::load_from_file(path).unwrap();
    let mut bridges = Vec::new();
    let mut leases_file = String::from("leases.json");

    for (sec, prop) in &conf {
        let name = sec.as_ref().unwrap_or(&"default".to_string()).to_string();
        
        if name == "general" {
            leases_file = prop.get("persistence_file").unwrap_or(&"leases.json".to_string()).to_string();
            continue;
        }

        bridges.push(BridgeConfig {
            name: name.clone(),
            ipv4_range_start: prop.get("ipv4_range_start").unwrap_or(&"".to_string()).to_string(),
            ipv6_prefix: prop.get("ipv6_prefix").unwrap_or(&"".to_string()).to_string(),
            ipv6_prefix_len: prop.get("ipv6_prefix_len").unwrap_or(&"80").parse().unwrap_or(80),
            mode: prop.get("type").unwrap_or(&"server".to_string()).to_string(),
        });
    }

    AppConfig { bridges, leases_file }
}