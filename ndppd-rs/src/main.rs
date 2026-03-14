mod address;
mod rule;
mod session;
mod proxy;
mod config;
mod iface;
mod engine;

use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Iniciando ndppd-rs...");

    let args: Vec<String> = env::args().collect();
    let config_path = args.get(args.iter().position(|x| x == "-c").map(|i| i+1).unwrap_or(0))
        .cloned().unwrap_or_else(|| "ndppd.conf".to_string());

    let proxies = config::parse_config(&config_path)?;
    if proxies.is_empty() {
        tracing::error!("Nenhum proxy configurado!");
        return Ok(());
    }

    let mut handles = vec![];

    for p in proxies {
        let iface_name = p.iface_name.clone();
        match iface::Iface::new(&iface_name) {
            Ok(interface) => {
                tracing::info!("Lançando motor para interface: {}", iface_name);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = engine::run_loop(interface, p).await {
                        tracing::error!("Erro no motor {}: {}", iface_name, e);
                    }
                }));
            }
            Err(e) => tracing::error!("Não foi possível abrir {}: {}", iface_name, e),
        }
    }

    // Mantém o programa rodando enquanto os motores trabalham
    for h in handles { let _ = h.await; }

    Ok(())
}