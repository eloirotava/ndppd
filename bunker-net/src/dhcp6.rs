use std::sync::Arc;
use crate::config::NetConfig;

pub async fn start_server(config: Arc<NetConfig>) {
    log::info!("Motor [...] aguardando implementação para a interface: {}", config.interface);
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    }
}