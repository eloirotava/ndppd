mod config;
mod dhcp4;
mod dhcp6;
mod radvd;
mod ndp;
mod storage;

use std::sync::Arc;
use crate::storage::LeaseManager;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("🚀 Bunker-Net V2: Orquestrador Iniciado");

    let app_config = config::load_config("ndp.conf");
    let lease_manager = LeaseManager::new(&app_config.leases_file);
    
    check_system_health();

    let mut handles = vec![];

    for bridge in app_config.bridges {
        let b = Arc::new(bridge);
        let lm = Arc::clone(&lease_manager);

        if b.mode == "server" {
            log::info!("⚙️  Bridge SERVER em: {}", b.name);
            let b_c = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                tokio::join!(
                    dhcp4::start_server(b_c.clone(), lm.clone()),
                    dhcp6::start_server(b_c.clone(), lm.clone()),
                    radvd::start_server(b_c.clone())
                );
            }));
        } else if b.mode == "ndp-proxy" {
            log::info!("🛡️  Bridge PROXY em: {}", b.name);
            let b_c = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                let _ = ndp::start_proxy((*b_c).clone()).await;
            }));
        }
    }

    futures::future::join_all(handles).await;
}

fn check_system_health() {
    let v4 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
    let v6 = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").unwrap_or_default();
    
    if v4.trim() != "1" { log::error!("❌ IPv4 Forwarding OFF!"); }
    if v6.trim() != "1" { log::error!("❌ IPv6 Forwarding OFF!"); }
}