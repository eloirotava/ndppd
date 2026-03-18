use std::process::{Command, Stdio};
use std::io::Write;

pub struct FirewallManager {
    table: String,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self { table: "ndp_dhcp_sec".to_string() }
    }

    pub fn init_tables(&self) {
        log::info!("🛡️ [Firewall] Inicializando Tabela L2 (bridge): {}", self.table);
        let ruleset = format!(
            "table bridge {} {{\n\
                chain prerouting {{\n\
                    type filter hook prerouting priority -300; policy accept;\n\
                }}\n\
                chain postrouting {{\n\
                    type filter hook postrouting priority 300; policy accept;\n\
                }}\n\
            }}\n\
            flush chain bridge {} prerouting\n\
            flush chain bridge {} postrouting\n",
            self.table, self.table, self.table
        );
        self.apply(&ruleset);
    }

    pub fn init_nat(&self) {
        log::info!("🌍 [Firewall] Inicializando Tabela de NAT L3 (inet)");
        let ruleset = format!(
            "table inet {0}_nat {{\n\
                chain postrouting {{\n\
                    type nat hook postrouting priority 100; policy accept;\n\
                }}\n\
            }}\n\
            flush chain inet {0}_nat postrouting\n",
            self.table
        );
        self.apply(&ruleset);
    }

    // CORREÇÃO: Faz Masquerade EXCLUSIVAMENTE para IPv4
    pub fn enable_nat_for_network(&self, iface: &str, ipv4_cidr: &str) {
        log::info!("🌍 [Firewall] Ativando NAT (Masquerade) apenas para IPv4 na rede de {}", iface);
        let mut ruleset = String::new();
        if !ipv4_cidr.is_empty() {
            ruleset.push_str(&format!("add rule inet {}_nat postrouting ip saddr {} oifname != {} masquerade\n", self.table, ipv4_cidr, iface));
        }
        self.apply(&ruleset);
    }

    pub fn bind_mac_to_ipv4(&self, mac: &str, ipv4: &str) {
        log::info!("🔒 [Firewall] MAC {} restrito ao IPv4 {}", mac, ipv4);
        let ruleset = format!(
            "add rule bridge {} prerouting ether saddr {} ip saddr != {{ {}, 0.0.0.0 }} drop\n\
             add rule bridge {} postrouting ip daddr {} ether daddr != {} drop\n",
            self.table, mac, ipv4,
            self.table, ipv4, mac
        );
        self.apply(&ruleset);
    }

    pub fn bind_mac_to_ipv6(&self, mac: &str, ipv6_cidr: &str) {
        log::info!("🔒 [Firewall] MAC {} restrito ao Prefixo IPv6 {}", mac, ipv6_cidr);
        let ruleset = format!(
            "add rule bridge {} prerouting ether saddr {} ip6 saddr != {{ {}, fe80::/10, :: }} drop\n\
             add rule bridge {} postrouting ip6 daddr {} ether daddr != {} drop\n",
            self.table, mac, ipv6_cidr,
            self.table, ipv6_cidr, mac
        );
        self.apply(&ruleset);
    }

    fn apply(&self, ruleset: &str) {
        if let Ok(mut child) = Command::new("nft").arg("-f").arg("-").stdin(Stdio::piped()).spawn() {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(ruleset.as_bytes());
            }
            let _ = child.wait();
        }
    }
}