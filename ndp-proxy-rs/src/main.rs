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
            let b_c = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                tokio::join!(
                    dhcp4::start_server(b_c.clone(), lm.clone()),
                    dhcp6::start_server(b_c.clone(), lm.clone()),
                    radvd::start_server(b_c.clone())
                );
            }));
        } else if b.mode == "ndp-proxy" {
            let b_c = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                let _ = ndp::start_proxy((*b_c).clone()).await;
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