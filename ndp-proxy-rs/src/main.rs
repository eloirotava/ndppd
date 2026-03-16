mod config;
mod dhcp4;
mod dhcp6;
mod radvd;

use std::sync::Arc;
use tokio::task;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("🚀 Bunker-Net V2: Iniciando Orquestrador Multi-Bridge...");

    let app_config = config::load_config("ndp.conf");
    let shared_config = Arc::new(app_config);

    // Health Check
    check_system_health();

    let mut handles = vec![];

    for bridge in &shared_config.bridges {
        let b = bridge.clone();
        log::info!("⚙️  Configurando interface: {} [Modo: {}]", b.name, b.mode);

        if b.mode == "server" {
            let handle = task::spawn(async move {
                // Aqui rodaremos os 3 motores em paralelo para cada bridge
                tokio::join!(
                    dhcp4::start_server(Arc::new(b.clone())),
                    dhcp6::start_server(Arc::new(b.clone())),
                    radvd::start_server(Arc::new(b.clone()))
                );
            });
            handles.push(handle);
        } else if b.mode == "ndp-proxy" {
            // TODO: Implementar lógica de NDP Proxy
            log::info!("🛡️  NDP Proxy ativo para {}", b.name);
        }
    }

    for h in handles {
        let _ = h.await;
    }
}

fn check_system_health() {
    let v4_fwd = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
    if v4_fwd.trim() != "1" {
        log::error!("❌ IPv4 Forwarding DESATIVADO!");
    }
    
    let v6_fwd = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").unwrap_or_default();
    if v6_fwd.trim() != "1" {
        log::error!("❌ IPv6 Forwarding DESATIVADO!");
    }
}