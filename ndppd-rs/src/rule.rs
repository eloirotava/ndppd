use crate::address::Address;
use std::net::Ipv6Addr;

/// Define o método que o ndppd vai usar para responder a uma solicitação
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMethod {
    /// Responde imediatamente (útil para honeypots ou roteamento garantido)
    Static,
    /// Procura a interface de saída lendo a tabela de rotas do Linux (/proc/net/ipv6_route)
    Auto,
    /// Encaminha o pacote (Neighbor Solicitation) para uma interface específica (ex: "eth1")
    Interface(String),
}

/// Representa uma regra configurada dentro de um Proxy
#[derive(Debug, Clone)]
pub struct Rule {
    pub addr: Address,
    pub method: RuleMethod,
    pub autovia: bool,
}

impl Rule {
    pub fn new_static(addr: Address) -> Self {
        Self { addr, method: RuleMethod::Static, autovia: false }
    }

    pub fn new_auto(addr: Address) -> Self {
        Self { addr, method: RuleMethod::Auto, autovia: false }
    }

    pub fn new_iface(addr: Address, iface: &str, autovia: bool) -> Self {
        Self { 
            addr, 
            method: RuleMethod::Interface(iface.to_string()), 
            autovia 
        }
    }

    /// Verifica se um IP alvo se encaixa nesta regra
    pub fn matches(&self, target: &Ipv6Addr) -> bool {
        self.addr.contains(target)
    }
}