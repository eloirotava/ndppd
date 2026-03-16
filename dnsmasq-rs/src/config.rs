use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct NetConfig {
    pub interface: String,
    
    // Configurações IPv4
    pub ipv4_range_start: String,
    pub ipv4_range_end: String,
    pub ipv4_netmask: String,
    pub ipv4_gateway: String,
    pub ipv4_dns: Vec<String>,
    
    // Configurações IPv6
    pub ipv6_range_start: String,
    pub ipv6_range_end: String,
    pub ipv6_prefix_len: u8,
    pub ipv6_dns: Vec<String>,
    pub enable_ra: bool,
}

pub fn load_config(path: &str) -> NetConfig {
    let mut config = NetConfig::default();
    let path_obj = Path::new(path);
    
    let file = match File::open(&path_obj) {
        Ok(file) => file,
        Err(e) => {
            log::error!("Erro ao ler o arquivo {}: {}", path, e);
            return config;
        }
    };

    let lines = io::BufReader::new(file).lines();

    for line in lines.flatten() {
        let line = line.trim();
        // Ignora comentários e linhas vazias
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        
        // Trata opções sem o sinal de igual (ex: bind-interfaces, enable-ra)
        if parts.len() != 2 {
            if line == "enable-ra" {
                config.enable_ra = true;
            }
            continue;
        }

        let key = parts[0].trim();
        let val = parts[1].trim();

        match key {
            "interface" => config.interface = val.to_string(),
            "dhcp-range" => {
                let args: Vec<&str> = val.split(',').collect();
                if args.len() >= 3 {
                    if args[0].contains(':') {
                        // Trata a linha do IPv6
                        config.ipv6_range_start = args[0].to_string();
                        config.ipv6_range_end = args[1].to_string();
                        config.ipv6_prefix_len = args[2].parse().unwrap_or(80);
                    } else {
                        // Trata a linha do IPv4
                        config.ipv4_range_start = args[0].to_string();
                        config.ipv4_range_end = args[1].to_string();
                        config.ipv4_netmask = args[2].to_string();
                    }
                }
            },
            "dhcp-option" => {
                let args: Vec<&str> = val.split(',').collect();
                if args[0] == "3" && args.len() >= 2 {
                    config.ipv4_gateway = args[1].to_string();
                } else if args[0] == "6" && args.len() >= 2 {
                    for dns in args.iter().skip(1) {
                        config.ipv4_dns.push(dns.to_string());
                    }
                } else if args[0] == "option6:dns-server" && args.len() >= 2 {
                    for dns in args.iter().skip(1) {
                        // Remove os colchetes dos IPs do DNS IPv6
                        let clean_dns = dns.replace('[', "").replace(']', "");
                        config.ipv6_dns.push(clean_dns);
                    }
                }
            },
            _ => {} // Ignora chaves desconhecidas
        }
    }
    config
}