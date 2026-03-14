use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

/// Estados que uma sessão pode ter, copiados da lógica original do ndppd
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Waiting,  // Esperando uma resposta de Advert
    Renewing, // Tentando renovar antes de expirar
    Valid,    // Rota válida e confirmada
    Invalid,  // Falhou após todas as tentativas
}

#[derive(Debug)]
pub struct Session {
    pub target_addr: Ipv6Addr,
    pub status: SessionStatus,
    pub retries: u32,
    pub fails: u32,
    pub autowire: bool,
    pub keepalive: bool,
    
    // A grande sacada do Rust: em vez de decrementar TTL num loop global,
    // nós guardamos o exato momento em que ela vai expirar.
    pub expires_at: Instant,
}

impl Session {
    pub fn new(target_addr: Ipv6Addr, autowire: bool, keepalive: bool, retries: u32, timeout_ms: u64) -> Self {
        Self {
            target_addr,
            status: SessionStatus::Waiting,
            retries,
            fails: 0,
            autowire,
            keepalive,
            expires_at: Instant::now() + Duration::from_millis(timeout_ms),
        }
    }

    /// Verifica se o tempo da sessão já estourou
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Chamado quando recebemos um Neighbor Advert confirmando o IP!
    pub fn mark_valid(&mut self, ttl_ms: u64) {
        self.status = SessionStatus::Valid;
        self.fails = 0;
        self.expires_at = Instant::now() + Duration::from_millis(ttl_ms);
    }

    /// Chamado quando dá timeout para tentar de novo (retries)
    pub fn handle_timeout(&mut self, timeout_ms: u64) {
        if self.fails < self.retries {
            self.fails += 1;
            self.expires_at = Instant::now() + Duration::from_millis(timeout_ms);
            // Aqui o status continua Waiting ou Renewing, e no futuro 
            // mandaremos outro pacote Solicit.
        } else {
            self.status = SessionStatus::Invalid;
        }
    }
}