mod address;
mod rule;
mod session;
mod proxy;
mod config;
mod iface;

use std::net::Ipv6Addr;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Iniciando ndppd-rs...");

    match iface::Iface::new("eth0") {
        Ok(interface) => println!("Sucesso! Ligado à placa de rede: {:?}", interface),
        Err(e) => println!("Erro ao ligar placa (deves precisar de sudo): {}", e),
    }

    // Lê as regras diretamente do ficheiro ndppd.conf
    let mut proxies = config::parse_config("ndppd.conf")?;

    if proxies.is_empty() {
        tracing::error!("Nenhum proxy foi encontrado no ficheiro de configuração!");
        return Ok(());
    }

    // Vamos buscar o primeiro proxy configurado (o eth0)
    let my_proxy = &mut proxies[0];

    println!("Proxy carregado da interface: {}", my_proxy.iface_name);
    println!("Regras carregadas do ficheiro: {:#?}", my_proxy.rules);

    // --- SIMULAÇÃO DE TRÁFEGO ---
    
    let target_ip = Ipv6Addr::from_str("1234:5678::9999")?;
    println!("\n[>] 1. Recebido Neighbor Solicitation para: {}", target_ip);

    if let Some(rule) = my_proxy.find_rule(&target_ip).cloned() {
        println!("[!] Match encontrado! Regra: {}", rule.addr);
        
        // CORREÇÃO: Copiamos o número do timeout ANTES de pegar a referência mutável
        let timeout = my_proxy.timeout_ms;
        
        let session = my_proxy.get_or_create_session(target_ip);
        println!("[-] Sessão criada com timeout de {}ms: {:#?}", timeout, session);
        
        println!("\n[>] 2. Resposta (Neighbor Advert) recebida!");
        
        if let Some(active_session) = my_proxy.sessions.get_mut(&target_ip) {
            let ttl = my_proxy.ttl_ms as u64;
            active_session.mark_valid(ttl);
            println!("[+] Sessão atualizada para VÁLIDA (dura {}ms): {:#?}", ttl, active_session);
        }

    } else {
        println!("[-] Nenhuma regra cobre o IP {}. Ignorando pacote.", target_ip);
    }

    Ok(())
}