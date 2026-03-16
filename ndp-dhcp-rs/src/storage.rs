use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Lease {
    // Se a string for vazia, o campo não entra no JSON
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ipv4: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ipv6: String,
}

pub struct LeaseManager {
    file_path: String,
    pub leases: RwLock<HashMap<String, Lease>>,
}

impl LeaseManager {
    pub fn new(path: &str) -> Arc<Self> {
        let leases = if let Ok(data) = fs::read_to_string(path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Arc::new(Self {
            file_path: path.to_string(),
            leases: RwLock::new(leases),
        })
    }

    pub fn set_lease(&self, id: &str, ipv4: String, ipv6: String) {
        let mut leases = self.leases.write().unwrap();
        // Atualiza apenas o que foi enviado, preservando o que já existia se necessário
        let entry = leases.entry(id.to_string()).or_insert(Lease { ipv4: String::new(), ipv6: String::new() });
        if !ipv4.is_empty() { entry.ipv4 = ipv4; }
        if !ipv6.is_empty() { entry.ipv6 = ipv6; }

        if let Ok(data) = serde_json::to_string_pretty(&*leases) {
            let _ = fs::write(&self.file_path, data);
        }
    }
    
    pub fn get_lease(&self, id: &str) -> Option<Lease> {
        self.leases.read().unwrap().get(id).cloned()
    }
}