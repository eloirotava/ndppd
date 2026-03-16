use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::fs;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Lease {
    pub ipv4: String,
    pub ipv6: String,
}

pub struct LeaseManager {
    file_path: String,
    pub leases: RwLock<HashMap<String, Lease>>,
}

impl LeaseManager {
    pub fn new(path: &str) -> Arc<Self> {
        let content = fs::read_to_string(path).unwrap_or_else(|_| "{}".to_string());
        let leases: HashMap<String, Lease> = serde_json::from_str(&content).unwrap_or_default();
        Arc::new(Self { file_path: path.to_string(), leases: RwLock::new(leases) })
    }

    pub fn get_lease(&self, mac: &str) -> Option<Lease> {
        self.leases.read().unwrap().get(mac).cloned()
    }

    pub fn set_lease(&self, mac: &str, ipv4: String, ipv6: String) {
        let mut data = self.leases.write().unwrap();
        data.insert(mac.to_string(), Lease { ipv4, ipv6 });
        if let Ok(json) = serde_json::to_string_pretty(&*data) {
            let _ = fs::write(&self.file_path, json);
        }
    }
}