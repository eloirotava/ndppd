use std::collections::HashMap;
use std::net::Ipv6Addr;

use crate::rule::Rule;
use crate::session::Session;

#[derive(Debug)]
pub struct Proxy {
    pub iface_name: String,
    pub rules: Vec<Rule>,
    
    // Cache de sessões ativas (Mapeia o IP alvo para a Sessão)
    pub sessions: HashMap<Ipv6Addr, Session>,
    
    // Configurações do ndppd.conf
    pub router: bool,
    pub autowire: bool,
    pub keepalive: bool,
    pub retries: u32,
    pub timeout_ms: u32,
    pub ttl_ms: u32,
}

impl Proxy {
    pub fn new(iface_name: &str) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            rules: Vec::new(),
            sessions: HashMap::new(), // Inicializa o HashMap vazio
            router: true,
            autowire: false,
            keepalive: true,
            retries: 3,
            timeout_ms: 500,
            ttl_ms: 30000,
        }
    }

    /// Adiciona uma nova regra a este proxy
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Procura a primeira regra que bate com o IP alvo
    pub fn find_rule(&self, target: &Ipv6Addr) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches(target))
    }

    /// Cria ou recupera uma sessão para um IP alvo
    pub fn get_or_create_session(&mut self, target: Ipv6Addr) -> &mut Session {
        // Extraímos as configurações antes do closure para evitar
        // problemas de mutabilidade múltipla (borrow checker do Rust)
        let autowire = self.autowire;
        let keepalive = self.keepalive;
        let retries = self.retries;
        let timeout_ms = self.timeout_ms as u64;

        // Se a sessão não existir, cria uma nova e insere. Retorna a referência mutável.
        self.sessions.entry(target).or_insert_with(|| {
            Session::new(
                target,
                autowire,
                keepalive,
                retries,
                timeout_ms,
            )
        })
    }
}