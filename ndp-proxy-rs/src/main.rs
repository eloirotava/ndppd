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
    log::info!("🚀 Bunker-Net V2: Iniciando Orquestrador Multi-Bridge...");

    // Nome do arquivo de configuração ajustado
    let app_config = config::load_config("ndp.conf");
    let lease_manager = LeaseManager::new(&app_config.leases_file);
    
    check_system_health();

    let mut handles = vec![];

    for bridge in app_config.bridges {
        let b = Arc::new(bridge);
        let lm = Arc::clone(&lease_manager);

        if b.mode == "server" {
            log::info!("⚙️  Configurando Bridge SERVER: {}", b.name);
            let b_clone = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                tokio::join!(
                    dhcp4::start_server(b_clone.clone(), lm.clone()),
                    dhcp6::start_server(b_clone.clone(), lm.clone()),
                    radvd::start_server(b_clone.clone())
                );
            }));
        } else if b.mode == "ndp-proxy" {
            log::info!("🛡️  Configurando Bridge PROXY: {}", b.name);
            let b_clone = Arc::clone(&b);
            handles.push(tokio::spawn(async move {
                if let Err(e) = ndp::start_proxy((*b_clone).clone()).await {
                    log::error!("Erro no motor NDP da interface {}: {}", b_clone.name, e);
                }
            }));
        }
    }

    // Resolvido o erro futures::future::join_all
    futures::future::join_all(handles).await;
}

fn check_system_health() {
    let check = |path: &str| std::fs::read_to_string(path).unwrap_or_default().trim() == "1";
    
    if !check("/proc/sys/net/ipv4/ip_forward") {
        log::error!("❌ IPv4 Forwarding DESATIVADO!");
    }
    if !check("/proc/sys/net/ipv6/conf/all/forwarding") {
        log::error!("❌ IPv6 Forwarding DESATIVADO!");
    }
}