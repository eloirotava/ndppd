mod config;
mod dhcp4;
mod dhcp6;
mod radvd;

use log::{info, error};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Iniciando Bunker-Net Daemon...");
    
    // Lê a configuração real do arquivo
    let conf = config::load_config("bunker.conf");
    info!("Configuração carregada com sucesso:");
    info!(" -> Interface: {}", conf.interface);
    info!(" -> IPv4 Range: {} até {}", conf.ipv4_range_start, conf.ipv4_range_end);
    info!(" -> IPv6 Prefix: {}/{}", conf.ipv6_range_start, conf.ipv6_prefix_len);
    info!(" -> RADVD Ativo: {}", conf.enable_ra);

    // Coloca a config num Arc (Atomic Reference Counting) para compartilhar entre as threads com segurança
    let shared_conf = Arc::new(conf);

    // Clonamos apenas o ponteiro (super leve) para cada thread
    let c4 = Arc::clone(&shared_conf);
    let c6 = Arc::clone(&shared_conf);
    let cra = Arc::clone(&shared_conf);

    // Spawna os 3 motores
    let t_dhcp4 = tokio::spawn(async move { dhcp4::start_server(c4).await });
    let t_dhcp6 = tokio::spawn(async move { dhcp6::start_server(c6).await });
    let t_radvd = tokio::spawn(async move { radvd::start_server(cra).await });

    // Mantém o daemon vivo
    let _ = tokio::join!(t_dhcp4, t_dhcp6, t_radvd);

    Ok(())
}