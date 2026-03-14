mod address;
mod rule;
mod session;
mod proxy;
mod config;
mod iface;
mod engine;

use clap::Parser;
use std::fs;
use std::path::Path;
use std::process;

/// NDP Proxy Daemon em Rust (compatível com o original)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Caminho para o ficheiro de configuração [padrão: /etc/ndppd.conf]
    #[arg(short, long, default_value = "/etc/ndppd.conf")]
    config: String,

    /// Escreve o PID do processo para este ficheiro
    #[arg(short, long)]
    pid: Option<String>,

    /// Ativa logs detalhados de debug
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Processa argumentos
    let args = Args::parse();

    // 2. Configura nível de log (Correção do erro unsafe)
    let log_level = if args.debug { "debug" } else { "info" };
    unsafe {
        std::env::set_var("RUST_LOG", log_level);
    }
    tracing_subscriber::fmt::init();

    tracing::info!("Iniciando ndppd-rs v{}...", env!("CARGO_PKG_VERSION"));

    // 3. Gestão do Ficheiro PID
    if let Some(pid_path) = args.pid {
        let pid = process::id().to_string();
        if let Err(e) = fs::write(&pid_path, pid) {
            tracing::error!("Falha ao escrever ficheiro PID em '{}': {}", pid_path, e);
        } else {
            tracing::info!("Ficheiro PID criado em: {}", pid_path);
        }
    }

    // 4. Verifica e lê a configuração
    if !Path::new(&args.config).exists() {
        tracing::error!("Erro: Ficheiro de configuração '{}' não encontrado.", args.config);
        return Ok(());
    }

    let proxies = config::parse_config(&args.config)?;
    if proxies.is_empty() {
        tracing::warn!("Aviso: Nenhum bloco 'proxy' encontrado no ficheiro.");
        return Ok(());
    }

    // 5. Lança os motores para cada interface configurada
    let mut handles = vec![];

    for p in proxies {
        let iface_name = p.iface_name.clone();
        match iface::Iface::new(&iface_name) {
            Ok(interface) => {
                tracing::info!("Motor lançado para interface: {}", iface_name);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = engine::run_loop(interface, p).await {
                        tracing::error!("Erro na interface {}: {}", iface_name, e);
                    }
                }));
            }
            Err(e) => tracing::error!("Não foi possível abrir {}: {}", iface_name, e),
        }
    }

    // Aguarda execução infinita dos motores
    for h in handles {
        let _ = h.await;
    }

    Ok(())
}