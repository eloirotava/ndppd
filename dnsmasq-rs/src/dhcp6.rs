use std::sync::Arc;
use std::net::Ipv6Addr;
use tokio::net::UdpSocket;
use crate::config::NetConfig;

fn get_ifindex(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
        .unwrap_or_else(|_| "0".to_string())
        .trim()
        .parse()
        .unwrap_or(0)
}

pub async fn start_server(config: Arc<NetConfig>) {
    log::info!("Motor DHCPv6 [Porta 547] inicializado. Escutando na rede...");

    let socket = match UdpSocket::bind("[::]:547").await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Falha ao fazer bind na porta 547 IPv6. Erro: {}", e);
            return;
        }
    };

    let multicast_addr: Ipv6Addr = "ff02::1:2".parse().unwrap();
    let ifindex = get_ifindex(&config.interface);
    
    if let Err(e) = socket.join_multicast_v6(&multicast_addr, ifindex) {
        log::warn!("Aviso Multicast IPv6: {}", e);
    } else {
        log::info!("📡 Inscrito no grupo Multicast DHCPv6 na interface {}", config.interface);
    }

    let mut buf = [0u8; 1500];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                if len < 4 { continue; }

                let msg_type = buf[0];
                // 1 = Solicit, 3 = Request (O ciclo que nos importa)
                if msg_type != 1 && msg_type != 3 {
                    continue;
                }

                let offered_ipv6: Ipv6Addr = config.ipv6_range_start.parse().unwrap_or(Ipv6Addr::new(0x2804, 0x14d, 0, 0, 0, 0, 0, 2));
                let dns1: Ipv6Addr = config.ipv6_dns.first().unwrap_or(&"2606:4700:4700::1111".to_string()).parse().unwrap();

                // MAGIA NEGRA: Extraindo o Client ID e IAID diretamente dos bytes (À prova de falhas)
                let mut client_id_bytes = Vec::new();
                let mut iaid_bytes = vec![0, 0, 0, 0];
                let mut offset = 4;
                
                while offset + 4 <= len {
                    let opt_type = u16::from_be_bytes([buf[offset], buf[offset+1]]);
                    let opt_len = u16::from_be_bytes([buf[offset+2], buf[offset+3]]) as usize;
                    offset += 4;
                    
                    if offset + opt_len > len { break; }
                    
                    if opt_type == 1 { // Achou o Client ID
                        client_id_bytes.extend_from_slice(&buf[offset-4 .. offset+opt_len]);
                    } else if opt_type == 3 { // Achou o bloco de IP (IA_NA)
                        if opt_len >= 4 {
                            iaid_bytes.copy_from_slice(&buf[offset .. offset+4]);
                        }
                    }
                    offset += opt_len;
                }

                if msg_type == 1 {
                    log::info!("🔍 DHCPv6 SOLICIT recebido de {}", peer);
                    log::info!("   🎯 Forjando pacote ADVERTISE com o IP: {}/{}", offered_ipv6, config.ipv6_prefix_len);
                } else {
                    log::info!("✅ DHCPv6 REQUEST recebido de {}", peer);
                    log::info!("   🎉 Forjando pacote REPLY fechando o contrato!");
                }

                // ========================================================
                // MONTANDO A RESPOSTA BINÁRIA (Exatamente como o Kernel quer)
                // ========================================================
                let mut out_buf = Vec::new();
                
                // 1. Tipo da Mensagem: Solicit -> Advertise (2), Request -> Reply (7)
                out_buf.push(if msg_type == 1 { 2 } else { 7 });
                
                // 2. Transaction ID (Copiando exatamente o que o cliente enviou)
                out_buf.extend_from_slice(&buf[1..4]);
                
                // 3. Client ID (Devolvendo a identidade dele)
                out_buf.extend_from_slice(&client_id_bytes);
                
                // 4. Server ID (Nosso ID fictício do Bunker-Net: 02:42:00:00:00:01)
                out_buf.extend_from_slice(&[
                    0, 2,  // Option 2 (Server ID)
                    0, 10, // Length 10
                    0, 3,  // DUID Type 3 (Link-Layer)
                    0, 1,  // Hardware Ethernet
                    0x02, 0x42, 0x00, 0x00, 0x00, 0x01 // MAC
                ]);
                
                // 5. IA_NA (A Maleta com o IP)
                out_buf.extend_from_slice(&[0, 3, 0, 40]);      // Option 3, Length 40
                out_buf.extend_from_slice(&iaid_bytes);         // IAID do Cliente
                out_buf.extend_from_slice(&[0, 0, 0x0e, 0x10]); // T1 (3600s)
                out_buf.extend_from_slice(&[0, 0, 0x15, 0x18]); // T2 (5400s)
                
                // 5.1 O IP de fato! (IA_ADDR)
                out_buf.extend_from_slice(&[0, 5, 0, 24]);      // Option 5, Length 24
                out_buf.extend_from_slice(&offered_ipv6.octets());
                out_buf.extend_from_slice(&[0, 0, 0x1c, 0x20]); // Preferred Lifetime (7200s)
                out_buf.extend_from_slice(&[0, 0, 0x2a, 0x30]); // Valid Lifetime (10800s)
                
                // 6. DNS Server (Para a navegação brilhar)
                out_buf.extend_from_slice(&[0, 23, 0, 16]); // Option 23, Length 16
                out_buf.extend_from_slice(&dns1.octets());

                // FOGO! Atirando o pacote pronto direto de volta para o cliente
                if let Err(e) = socket.send_to(&out_buf, peer).await {
                    log::error!("Erro ao enviar DHCPv6: {}", e);
                } else {
                    log::info!("   🚀 Resposta enviada com sucesso para {}", peer);
                }
            }
            Err(_) => {}
        }
    }
}