use std::{path::Path, sync::Arc, time::Duration};

use redb::{Database, TableDefinition};
use serde_json::json;

use crate::{
    crypto::ProofSystem,
    errors::{Error, Result},
    types::{ACLEntry, AdminKeySet, EntryId, SuccessionRecord},
};

pub mod audit;
pub mod proof_store;
pub mod rate_limit;
pub mod succession;

use self::{
    audit::AuditLog, proof_store::ProofStore, rate_limit::RateLimit, succession::SuccessionManager,
};

const DEFAULT_BATCH_SIZE: usize = 64;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_RATE_WINDOW: Duration = Duration::from_secs(300);
const DEFAULT_MAX_OPERATIONS: u64 = 100;

const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");
const ADMIN_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("admin_state");
const PROOFS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("proofs");
const SUCCESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("successions");

pub struct Storage {
    db: Arc<Database>,
    rate_limiter: Arc<RateLimit>,
    proof_system: Arc<ProofSystem>,
    proof_store: Arc<ProofStore>,
    succession_manager: SuccessionManager,
    audit_log: AuditLog,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub batch_size: usize,
    pub operation_timeout: Duration,
    pub rate_window: Duration,
    pub max_operations: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            operation_timeout: DEFAULT_TIMEOUT,
            rate_window: DEFAULT_RATE_WINDOW,
            max_operations: DEFAULT_MAX_OPERATIONS,
        }
    }
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P, config: Option<StorageConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();

        let db = Arc::new(
            Database::create(path)
                .map_err(|e| Error::database_error("Failed to create database", e.to_string()))?,
        );
        let proof_system = Arc::new(ProofSystem::new());
        let rate_limiter = Arc::new(RateLimit::new(config.rate_window, config.max_operations));

        let proof_store = Arc::new(ProofStore::new(
            Arc::clone(&db),
            Arc::clone(&rate_limiter),
            Arc::clone(&proof_system),
            config.operation_timeout,
        )?);

        let succession_manager = SuccessionManager::new(
            Arc::clone(&db),
            Arc::clone(&rate_limiter),
            Arc::clone(&proof_system),
            Arc::clone(&proof_store),
            config.operation_timeout,
        )?;

        let audit_log = AuditLog::new(
            Arc::clone(&db),
            Arc::clone(&rate_limiter),
            config.operation_timeout,
        )?;

        Ok(Self {
            db,
            rate_limiter,
            proof_system,
            proof_store,
            succession_manager,
            audit_log,
        })
    }

    pub async fn add_entry(&self, entry: &ACLEntry, admin: &AdminKeySet) -> Result<()> {
        let audit_details = json!({
            "entry_id": entry.id.0,
            "service_id": entry.service_id.0,
            "policy_generation": entry.policy_generation,
            "remaining_operations": self.rate_limiter.get_remaining(),
        });

        self.audit_log
            .record_event("ENTRY_ADDED".into(), admin.policy_generation, audit_details)
            .await?;

        self.proof_store.add_entry(entry, admin).await
    }

    pub async fn validate_entry(&self, entry_id: &[u8], admin: &AdminKeySet) -> Result<bool> {
        self.proof_store.validate_entry(entry_id, admin).await
    }

    pub async fn batch_validate(
        &self,
        entry_ids: &[EntryId],
        admin: &AdminKeySet,
    ) -> Result<Vec<bool>> {
        self.proof_store.batch_validate(entry_ids, admin).await
    }

    pub async fn process_succession(
        &self,
        succession: &SuccessionRecord,
        admin: &AdminKeySet,
    ) -> Result<()> {
        let audit_details = json!({
            "from_generation": admin.policy_generation,
            "to_generation": succession.generation,
            "affected_entries": succession.affected_entries.len(),
            "remaining_operations": self.rate_limiter.get_remaining(),
        });

        self.audit_log
            .record_event(
                "SUCCESSION_PROCESSED".into(),
                admin.policy_generation,
                audit_details,
            )
            .await?;

        self.succession_manager
            .process_succession(succession, admin)
            .await
    }

    pub async fn validate_across_succession(
        &self,
        entry: &ACLEntry,
        start_gen: u32,
        end_gen: u32,
    ) -> Result<bool> {
        let results = self
            .succession_manager
            .validate_across_chain(std::slice::from_ref(entry), start_gen, end_gen)
            .await?;
        Ok(results.first().copied().unwrap_or(false))
    }

    pub async fn get_audit_events(
        &self,
        start_time: time::OffsetDateTime,
        end_time: time::OffsetDateTime,
    ) -> Result<Vec<audit::AuditEntry>> {
        self.audit_log.get_events(start_time, end_time).await
    }

    pub async fn verify_audit_chain(&self) -> Result<bool> {
        self.audit_log.verify_chain().await
    }

    pub fn get_rate_limit_status(&self) -> (u64, Duration) {
        (
            self.rate_limiter.get_remaining(),
            self.rate_limiter.get_window_remaining(),
        )
    }

    pub fn proof_system(&self) -> &ProofSystem {
        &self.proof_system
    }

    pub fn get_current_admin(&self) -> Result<AdminKeySet> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::database_error("Failed to begin transaction", e.to_string()))?;

        let admin_table = read_txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::database_error("Failed to open admin state table", e.to_string())
        })?;

        let admin_bytes = admin_table
            .get(&b"current"[..])
            .map_err(|e| Error::database_error("Failed to read admin state", e.to_string()))?
            .ok_or_else(|| Error::database_error("Not found", "No admin state found"))?;

        serde_json::from_slice(admin_bytes.value())
            .map_err(|e| Error::database_error("Failed to deserialize admin state", e.to_string()))
    }

    pub fn get_entry(&self, entry_id: &[u8]) -> Result<Option<ACLEntry>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::database_error("Failed to begin transaction", e.to_string()))?;

        let entries_table = read_txn
            .open_table(ENTRIES)
            .map_err(|e| Error::database_error("Failed to open entries table", e.to_string()))?;

        if let Some(entry_bytes) = entries_table
            .get(entry_id)
            .map_err(|e| Error::database_error("Failed to read entry", e.to_string()))?
        {
            let entry = serde_json::from_slice(entry_bytes.value())
                .map_err(|e| Error::database_error("Failed to deserialize entry", e.to_string()))?;

            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub async fn set_admin_state(&mut self, admin: &AdminKeySet) -> Result<()> {
        self.rate_limiter.check()?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::database_error("Failed to begin transaction", e.to_string()))?;

        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).map_err(|e| {
                Error::database_error("Failed to open admin state table", e.to_string())
            })?;

            let admin_bytes = serde_json::to_vec(admin).map_err(|e| {
                Error::database_error("Failed to serialize admin state", e.to_string())
            })?;

            admin_table
                .insert(b"current".as_slice(), admin_bytes.as_slice())
                .map_err(|e| {
                    Error::database_error("Failed to insert admin state", e.to_string())
                })?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::database_error("Failed to commit transaction", e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EntryMetadata, SerializableSignature, ServiceId, SigningKeyPair};
    use ed25519_dalek::{Signature, SigningKey};
    use rand::{rngs::OsRng, RngCore};
    use tempfile::tempdir;

    async fn setup_test_storage() -> (Storage, SigningKeyPair, AdminKeySet) {
        let temp_dir = tempdir().unwrap();
        let storage = Storage::new(temp_dir.path().join("test.db"), None).unwrap();

        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let key_pair = SigningKeyPair::new(SigningKey::from_bytes(&seed));

        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: time::OffsetDateTime::now_utc(),
        };

        (storage, key_pair, admin)
    }

    fn create_test_entry(key_pair: &SigningKeyPair, proof_system: &ProofSystem) -> ACLEntry {
        let mut id = [0u8; 32];
        id[0] = 1;

        let mut entry = ACLEntry {
            id: EntryId::new(id),
            service_id: ServiceId("test".into()),
            policy_generation: 1,
            metadata: EntryMetadata {
                created_at: time::OffsetDateTime::now_utc(),
                expires_at: None,
                version: 1,
                service_specific: serde_json::Value::Null,
            },
            signature: SerializableSignature(Signature::from_bytes(&[0; 64])),
        };

        entry.signature = proof_system.sign_entry(&entry, key_pair).unwrap();
        entry
    }

    #[tokio::test]
    async fn test_entry_operations() {
        let (storage, key_pair, admin) = setup_test_storage().await;
        let entry = create_test_entry(&key_pair, storage.proof_system());

        storage.add_entry(&entry, &admin).await.unwrap();
        assert!(storage.validate_entry(&entry.id.0, &admin).await.unwrap());
    }

    #[tokio::test]
    async fn test_batch_operations() {
        let (storage, key_pair, admin) = setup_test_storage().await;
        let mut entries = Vec::new();
        let mut entry_ids = Vec::new();

        for i in 0..10 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let mut entry = create_test_entry(&key_pair, storage.proof_system());
            entry.id = EntryId::new(id);

            storage.add_entry(&entry, &admin).await.unwrap();
            entries.push(entry.clone());
            entry_ids.push(entry.id);
        }

        let results = storage.batch_validate(&entry_ids, &admin).await.unwrap();
        assert_eq!(results.len(), entries.len());
    }

    #[tokio::test]
    async fn test_succession_chain() {
        let (storage, key_pair, admin) = setup_test_storage().await;
        let entry = create_test_entry(&key_pair, storage.proof_system());

        storage.add_entry(&entry, &admin).await.unwrap();

        let mut current_admin = admin.clone();

        for gen in 2..=4 {
            let message = storage.proof_system().create_succession_message(
                current_admin.policy_generation,
                &current_admin.active_keys,
            );
            let signature = key_pair.sign(&message);

            let succession = SuccessionRecord {
                old_keys: current_admin.active_keys,
                new_keys: current_admin.active_keys,
                generation: gen,
                timestamp: time::OffsetDateTime::now_utc(),
                affected_entries: vec![entry.id],
                signatures: [signature.clone(), signature],
                request_metadata: None,
            };

            storage
                .process_succession(&succession, &current_admin)
                .await
                .unwrap();

            current_admin = AdminKeySet {
                active_keys: succession.new_keys,
                policy_generation: succession.generation,
                last_rotation: succession.timestamp,
            };
        }

        assert!(storage
            .validate_across_succession(&entry, 1, 4)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_audit_integration() {
        let (storage, key_pair, admin) = setup_test_storage().await;
        let start_time = time::OffsetDateTime::now_utc();
        let entry = create_test_entry(&key_pair, storage.proof_system());

        storage.add_entry(&entry, &admin).await.unwrap();

        let end_time = time::OffsetDateTime::now_utc();
        let events = storage
            .get_audit_events(start_time, end_time)
            .await
            .unwrap();

        assert!(!events.is_empty());
        assert!(storage.verify_audit_chain().await.unwrap());
    }
}
