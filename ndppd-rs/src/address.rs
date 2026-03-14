use ipnet::Ipv6Net;
use std::net::Ipv6Addr;
use std::str::FromStr;
use anyhow::Result;

/// Representa um endereço IPv6 ou uma sub-rede (regra) do ndppd
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    network: Ipv6Net,
}

impl Address {
    /// Cria um novo Address a partir de uma string (ex: "1111::/96" ou "1234::1")
    pub fn new(addr_str: &str) -> Result<Self> {
        // Se a string contiver '/', é tratado como rede. Se não, assume /128.
        let network = if addr_str.contains('/') {
            Ipv6Net::from_str(addr_str)?
        } else {
            let ip = Ipv6Addr::from_str(addr_str)?;
            Ipv6Net::new(ip, 128)?
        };

        Ok(Self { network })
    }

    /// Retorna o IP base da rede
    pub fn addr(&self) -> Ipv6Addr {
        self.network.addr()
    }

    /// Retorna o tamanho do prefixo (ex: 96, 128)
    pub fn prefix(&self) -> u8 {
        self.network.prefix_len()
    }

    /// Verifica se este Address abrange o IP alvo
    /// Equivalente ao `rule::check(const address& addr)` do C++
    pub fn contains(&self, target: &Ipv6Addr) -> bool {
        self.network.contains(target)
    }

    /// O C++ original tinha verificações de unicast/multicast. 
    /// O Rust já tem isso nativo no `Ipv6Addr`.
    pub fn is_multicast(&self) -> bool {
        self.network.addr().is_multicast()
    }

    pub fn is_unicast(&self) -> bool {
        // O Rust diferencia vários tipos, unicast global, link-local, etc.
        // O C++ original assumia que não ser multicast e não ser o endereço "::" era unicast.
        !self.is_multicast() && !self.network.addr().is_unspecified()
    }
}

// Para facilitar a conversão de Address para String
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.network)
    }
}