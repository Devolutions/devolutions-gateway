use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use base64::Engine as _;
use camino::Utf8PathBuf;
use parking_lot::RwLock;
use uuid::Uuid;

use crate::config::{WireGuardConf, WireGuardPeerConfig, get_data_dir};

const AGENT_STORE_FILE_NAME: &str = "wireguard-agents.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub assigned_ip: Ipv4Addr,
    pub enrolled_at_unix: u64,
}

impl AgentRecord {
    pub fn from_peer_config(peer: &WireGuardPeerConfig) -> Self {
        Self {
            agent_id: peer.agent_id,
            name: peer.name.clone(),
            public_key: base64::engine::general_purpose::STANDARD.encode(peer.public_key.as_bytes()),
            assigned_ip: peer.assigned_ip,
            enrolled_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_secs(),
        }
    }

    pub fn to_peer_config(&self) -> anyhow::Result<WireGuardPeerConfig> {
        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .with_context(|| format!("failed to decode public key for agent {}", self.agent_id))?;

        anyhow::ensure!(
            public_key_bytes.len() == 32,
            "invalid wireguard public key length for agent {}",
            self.agent_id
        );

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_key_bytes);

        Ok(WireGuardPeerConfig {
            agent_id: self.agent_id,
            name: self.name.clone(),
            public_key: wireguard_tunnel::PublicKey::from(public_key),
            assigned_ip: self.assigned_ip,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AgentStore {
    path: Utf8PathBuf,
    records: Arc<RwLock<BTreeMap<Uuid, AgentRecord>>>,
}

impl AgentStore {
    pub fn load_default() -> anyhow::Result<Self> {
        Self::load(get_data_dir().join(AGENT_STORE_FILE_NAME))
    }

    pub fn load(path: Utf8PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
        }

        let records = if path.exists() {
            let file = File::open(&path).with_context(|| format!("failed to open {}", path))?;
            let reader = BufReader::new(file);
            let records = serde_json::from_reader::<_, Vec<AgentRecord>>(reader)
                .with_context(|| format!("failed to deserialize {}", path))?;
            records.into_iter().map(|record| (record.agent_id, record)).collect()
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            path,
            records: Arc::new(RwLock::new(records)),
        })
    }

    pub fn list(&self) -> Vec<AgentRecord> {
        self.records.read().values().cloned().collect()
    }

    pub fn get(&self, agent_id: &Uuid) -> Option<AgentRecord> {
        self.records.read().get(agent_id).cloned()
    }

    pub fn upsert(&self, record: AgentRecord) -> anyhow::Result<()> {
        let mut records = self.records.write();
        let agent_id = record.agent_id;
        let replaced = records.insert(record.agent_id, record);
        if let Err(error) = persist_records(&self.path, &records) {
            match replaced {
                Some(previous) => {
                    records.insert(previous.agent_id, previous);
                }
                None => {
                    records.remove(&agent_id);
                }
            }

            return Err(error);
        }

        Ok(())
    }

    pub fn remove(&self, agent_id: &Uuid) -> anyhow::Result<Option<AgentRecord>> {
        let mut records = self.records.write();
        let removed = records.remove(agent_id);

        if let Err(error) = persist_records(&self.path, &records) {
            if let Some(record) = removed.as_ref() {
                records.insert(record.agent_id, record.clone());
            }

            return Err(error);
        }

        Ok(removed)
    }

    pub fn peer_configs(&self) -> anyhow::Result<Vec<WireGuardPeerConfig>> {
        self.list().into_iter().map(|record| record.to_peer_config()).collect()
    }

    pub fn allocate_and_upsert_enrolled_peer(
        &self,
        agent_id: Uuid,
        name: String,
        public_key: wireguard_tunnel::PublicKey,
        wireguard_conf: &WireGuardConf,
    ) -> anyhow::Result<WireGuardPeerConfig> {
        let mut records = self.records.write();
        let encoded_public_key = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
        anyhow::ensure!(
            !records.values().any(|record| record.public_key == encoded_public_key),
            "wireguard public key already enrolled"
        );

        let assigned_ip = allocate_assigned_ip(&records, wireguard_conf)?;
        let peer = WireGuardPeerConfig {
            agent_id,
            name,
            public_key,
            assigned_ip,
        };
        let record = AgentRecord::from_peer_config(&peer);
        records.insert(agent_id, record);

        if let Err(error) = persist_records(&self.path, &records) {
            records.remove(&agent_id);
            return Err(error);
        }

        Ok(peer)
    }
}

fn allocate_assigned_ip(
    records: &BTreeMap<Uuid, AgentRecord>,
    wireguard_conf: &WireGuardConf,
) -> anyhow::Result<Ipv4Addr> {
    let used_ips = records
        .values()
        .map(|record| record.assigned_ip)
        .collect::<std::collections::BTreeSet<_>>();
    let network_start = u32::from(wireguard_conf.tunnel_network.network());
    let network_end = u32::from(wireguard_conf.tunnel_network.broadcast());
    let gateway_ip = wireguard_conf.gateway_ip;

    for candidate in (network_start + 1)..network_end {
        let candidate_ip = Ipv4Addr::from(candidate);
        if candidate_ip == gateway_ip || used_ips.contains(&candidate_ip) {
            continue;
        }

        return Ok(candidate_ip);
    }

    anyhow::bail!("no free wireguard tunnel addresses remain")
}

fn persist_records(path: &Utf8PathBuf, records: &BTreeMap<Uuid, AgentRecord>) -> anyhow::Result<()> {
    let snapshot = records.values().cloned().collect::<Vec<_>>();
    let file = File::create(path).with_context(|| format!("failed to create {}", path))?;
    let mut writer = BufWriter::new(&file);
    serde_json::to_writer_pretty(&mut writer, &snapshot).with_context(|| format!("failed to serialize {}", path))?;
    std::io::Write::flush(&mut writer).with_context(|| format!("failed to flush {}", path))?;
    file.sync_all().with_context(|| format!("failed to sync {}", path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store_path(file_name: &str) -> Utf8PathBuf {
        let unique = Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("dgw-agent-store-{unique}-{file_name}"));
        Utf8PathBuf::from_path_buf(path).expect("temp path should be utf-8")
    }

    fn sample_peer(agent_id: Uuid, ip: Ipv4Addr) -> WireGuardPeerConfig {
        let private_key = wireguard_tunnel::StaticSecret::from([9u8; 32]);

        WireGuardPeerConfig {
            agent_id,
            name: format!("agent-{agent_id}"),
            public_key: wireguard_tunnel::PublicKey::from(&private_key),
            assigned_ip: ip,
        }
    }

    #[test]
    fn upsert_roundtrips_peer_config() {
        let path = temp_store_path("roundtrip.json");
        let store = AgentStore::load(path.clone()).expect("store should load");
        let peer = sample_peer(Uuid::new_v4(), Ipv4Addr::new(10, 10, 0, 3));

        store
            .upsert(AgentRecord::from_peer_config(&peer))
            .expect("upsert should succeed");

        let reloaded = AgentStore::load(path).expect("store should reload");
        let stored_peer = reloaded
            .peer_configs()
            .expect("peer configs should deserialize")
            .pop()
            .expect("peer should exist");

        assert_eq!(stored_peer.agent_id, peer.agent_id);
        assert_eq!(stored_peer.assigned_ip, peer.assigned_ip);
    }
}
