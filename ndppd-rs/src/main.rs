// --- SIMULAÇÃO DE TRÁFEGO ---
    
    let target_ip = Ipv6Addr::from_str("1234:5678::9999")?;
    println!("\n[>] 1. Recebido Neighbor Solicitation para: {}", target_ip);

    if let Some(rule) = my_proxy.find_rule(&target_ip).cloned() {
        println!("[!] Match encontrado! Regra: {}", rule.addr);
        
        // Criamos a sessão pendente (status: Waiting)
        let session = my_proxy.get_or_create_session(target_ip);
        println!("[-] Sessão criada: {:#?}", session);
        
        // Simulação: Enviamos o pacote para a eth1 e esperamos...
        // ... (100ms depois) recebemos a resposta (Neighbor Advert) da eth1!
        
        println!("\n[>] 2. Resposta (Neighbor Advert) recebida da interface eth1!");
        
        // Recuperamos a sessão e marcamos como válida!
        if let Some(active_session) = my_proxy.sessions.get_mut(&target_ip) {
            active_session.mark_valid(my_proxy.ttl_ms as u64);
            println!("[+] Sessão atualizada para VÁLIDA: {:#?}", active_session);
        }

    } else {
        println!("[-] Nenhuma regra cobre o IP {}. Ignorando.", target_ip);
    }