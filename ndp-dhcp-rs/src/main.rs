mod config;
mod dhcp4;
mod dhcp6;
mod firewall;
mod radvd;
mod ndp;
mod storage;

use std::sync::Arc;
use std::env; 
use crate::storage::LeaseManager;
use crate::firewall::FirewallManager;

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let config_path = if let Some(pos) = args.iter().position(|x| x == "-c") {
        args.get(pos + 1).map(|s| s.as_str()).unwrap_or("ndp.conf")
    } else {
        "ndp.conf"
    };

    log::info!("🚀 Bunker-Net V2.4: Orquestrador com NAT IPv4 Dinâmico");
    log::info!("📖 Utilizando configuração: {}", config_path);

    let app_config = config::load_config(config_path);
    let lease_manager = LeaseManager::new(&app_config.leases_file);
    
    let fw_manager = Arc::new(FirewallManager::new());
    fw_manager.init_tables();

    // ====================================================================
    // INICIALIZA O NAT CASO SOLICITADO NO CONF (SÓ PARA IPv4)
    // ====================================================================
    let mut needs_nat = false;
    for b in &app_config.bridges {
        if b.enable_nat { needs_nat = true; break; }
    }
    
    if needs_nat {
        fw_manager.init_nat();
        for b in &app_config.bridges {
            if b.enable_nat {
                let v4_cidr = format!("{}/{}", b.ipv4_network, b.ipv4_prefix_len);
                fw_manager.enable_nat_for_network(&b.name, &v4_cidr);
            }
        }
    }
    // ====================================================================

    let all_leases = lease_manager.get_all_leases();
    if !all_leases.is_empty() {
        log::info!("🔄 [Firewall] Recarregando {} leases do histórico para o kernel...", all_leases.len());
        
        for (mac, lease) in all_leases {
            for b in &app_config.bridges {
                if b.mode == "server" && b.use_nftables {
                    if !lease.ipv4.is_empty() {
                        fw_manager.bind_mac_to_ipv4(&mac, &lease.ipv4);
                    }
                    if !lease.ipv6.is_empty() {
                        let mut cidr_str = format!("{}/128", lease.ipv6);
                        if let Ok(ip) = lease.ipv6.parse::<std::net::Ipv6Addr>() {
                            let mut cidr_octets = ip.octets();
                            let deleg_bits = b.ipv6_delegation_size as usize;
                            if deleg_bits < 128 {
                                for i in 0..16 {
                                    let bit_start = i * 8;
                                    if bit_start >= deleg_bits { cidr_octets[i] = 0; } 
                                    else if bit_start + 8 > deleg_bits {
                                        let shift = 8 - (deleg_bits - bit_start);
                                        cidr_octets[i] &= !((1 << shift) - 1);
                                    }
                                }
                                cidr_str = format!("{}/{}", std::net::Ipv6Addr::from(cidr_octets), deleg_bits);
                            }
                        }
                        fw_manager.bind_mac_to_ipv6(&mac, &cidr_str);
                    }
                    break; 
                }
            }
        }
    }

    check_system_health();

    let mut handles = vec![];
    let all_configs = app_config.bridges.clone();

    for bridge in app_config.bridges {
        let b = Arc::new(bridge);
        let lm = Arc::clone(&lease_manager);
        let fw = Arc::clone(&fw_manager);
        let ac = all_configs.clone();

        if b.mode == "server" {
            let b_c = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                tokio::join!(
                    dhcp4::start_server(b_c.clone(), lm.clone(), fw.clone()),
                    dhcp6::start_server(b_c.clone(), lm.clone(), fw.clone()),
                    radvd::start_server(b_c.clone())
                );
            }));
        } else if b.mode == "ndp-proxy" {
            let b_c = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                let _ = ndp::start_proxy((*b_c).clone(), ac).await;
            }));
        }
    }
    futures::future::join_all(handles).await;
}

fn check_system_health() {
    let check = |path: &str| std::fs::read_to_string(path).unwrap_or_default().trim() == "1";
    if !check("/proc/sys/net/ipv4/ip_forward") { log::error!("❌ IPv4 Forwarding OFF!"); }
    if !check("/proc/sys/net/ipv6/conf/all/forwarding") { log::error!("❌ IPv6 Forwarding OFF!"); }
}