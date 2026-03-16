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
    log::info!("🚀 Bunker-Net V3: Orquestrador Iniciado");

    let app_config = config::load_config("ndp.conf");
    let lease_manager = LeaseManager::new(&app_config.leases_file);
    
    let mut handles = vec![];
    let all_bridges = Arc::new(app_config.bridges);

    for bridge in all_bridges.iter() {
        let b = Arc::new(bridge.clone());
        let lm = Arc::clone(&lease_manager);
        let all_configs = (*all_bridges).clone();

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
            // NDP Proxy precisa de thread blocking para o loop do pnet
            handles.push(tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(ndp::start_proxy((*b_c).clone(), all_configs));
            }));
        }
    }
    
    futures::future::join_all(handles).await;
}