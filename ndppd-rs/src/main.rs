mod address;

use address::Address;
use std::net::Ipv6Addr;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Inicializa o sistema de log
    tracing_subscriber::fmt::init();
    tracing::info!("Iniciando ndppd-rs...");

    // Simulando o arquivo de configuração (ndppd.conf)
    let regra_subnet = Address::new("1234:5678::/96")?;
    let regra_ip_unico = Address::new("2001:db8::1")?; // Assume /128

    println!("Regra 1: {} (Prefixo: {})", regra_subnet, regra_subnet.prefix());
    println!("Regra 2: {} (Prefixo: {})", regra_ip_unico, regra_ip_unico.prefix());

    // Simulando a chegada de um pacote Neighbor Solicitation buscando o IP 1234:5678::1
    let target_ip = Ipv6Addr::from_str("1234:5678::1")?;
    
    if regra_subnet.contains(&target_ip) {
        println!("O IP {} pertence à regra {}! O proxy deve responder.", target_ip, regra_subnet);
    } else {
        println!("O IP {} NÃO pertence à regra {}.", target_ip, regra_subnet);
    }

    Ok(())
}