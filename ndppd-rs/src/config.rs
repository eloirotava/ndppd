use crate::address::Address;
use crate::proxy::Proxy;
use crate::rule::{Rule, RuleMethod};
use anyhow::{anyhow, Result};
use std::fs;

/// Lê um ficheiro ndppd.conf e retorna uma lista de Proxies configurados
pub fn parse_config(path: &str) -> Result<Vec<Proxy>> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow!("Falha ao ler o ficheiro de configuração '{}': {}", path, e))?;

    let mut proxies = Vec::new();
    let mut current_proxy: Option<Proxy> = None;
    let mut current_rule: Option<Rule> = None;

    for line in content.lines() {
        // Remove comentários e espaços
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();

        match tokens[0] {
            "proxy" => {
                if tokens.len() >= 2 {
                    current_proxy = Some(Proxy::new(tokens[1]));
                }
            }
            "rule" => {
                if tokens.len() >= 2 {
                    if let Ok(addr) = Address::new(tokens[1]) {
                        current_rule = Some(Rule::new_static(addr)); // Static por defeito
                    }
                }
            }
            "static" => {
                if let Some(rule) = &mut current_rule {
                    rule.method = RuleMethod::Static;
                }
            }
            "auto" => {
                if let Some(rule) = &mut current_rule {
                    rule.method = RuleMethod::Auto;
                }
            }
            "iface" => {
                if tokens.len() >= 2 {
                    if let Some(rule) = &mut current_rule {
                        rule.method = RuleMethod::Interface(tokens[1].to_string());
                    }
                }
            }
            "}" => {
                // Fim de um bloco. Se for o fim de uma rule, adicionamos ao proxy
                if let Some(rule) = current_rule.take() {
                    if let Some(proxy) = &mut current_proxy {
                        proxy.add_rule(rule);
                    }
                } 
                // Se for o fim de um proxy, adicionamos à lista final
                else if let Some(proxy) = current_proxy.take() {
                    proxies.push(proxy);
                }
            }
            _ => {
                // Outras configurações do proxy como router, timeout, ttl...
                if let Some(proxy) = &mut current_proxy {
                    if tokens.len() >= 2 {
                        match tokens[0] {
                            "router" => proxy.router = tokens[1] == "yes" || tokens[1] == "true",
                            "autowire" => proxy.autowire = tokens[1] == "yes" || tokens[1] == "true",
                            "ttl" => if let Ok(v) = tokens[1].parse() { proxy.ttl_ms = v },
                            "timeout" => if let Ok(v) = tokens[1].parse() { proxy.timeout_ms = v },
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(proxies)
}