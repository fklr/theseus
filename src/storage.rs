use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::{
    audit::AuditLog,
    crypto::{
        commitment::StateMatrixCommitment,
        merkle::SparseMerkleTree,
        primitives::{CurveGroups, G1},
        proofs::ProofSystem,
    },
    errors::{Error, Result},
    rate_limit::RateLimit,
    types::{ACLEntry, AdminKeySet, EntryId, SuccessionRecord},
};

const ADMIN_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("admin_state");
const STATE_ROOTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state_roots");
const SUCCESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("successions");
const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");

const CURRENT_KEY: &[u8] = b"current";
const ROOT_KEY: &[u8] = b"root";

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub operation_timeout: Duration,
    pub state_cache_size: usize,
    pub proof_cache_size: usize,
    pub max_batch_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_secs(30),
            state_cache_size: 10_000,
            proof_cache_size: 1_000,
            max_batch_size: 1_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemState {
    state_root: Vec<u8>,
    admin_keys: AdminKeySet,
    last_updated: time::OffsetDateTime,
}

pub struct Storage {
    db: Arc<Database>,
    state_tree: Arc<SparseMerkleTree>,
    proof_system: Arc<ProofSystem>,
    groups: Arc<CurveGroups>,
    audit_log: Arc<AuditLog>,
    rate_limiter: Arc<RateLimit>,
    config: StorageConfig,
    policy_generation: AtomicU64,
    current_state: ArcSwap<SystemState>,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(
        path: P,
        config: Option<StorageConfig>,
        groups: Arc<CurveGroups>,
    ) -> Result<Self> {
        let db = match Database::create(&path) {
            Ok(db) => Arc::new(db),
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to create database",
                    format!("Path: {:?}, Error: {}", path.as_ref(), e),
                ))
            }
        };

        let write_txn = match db.begin_write() {
            Ok(txn) => txn,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to begin transaction",
                    e.to_string(),
                ))
            }
        };

        // Initialize tables
        if let Err(e) = write_txn.open_table(ADMIN_STATE) {
            return Err(Error::database_error(
                "Failed to create admin state table",
                e.to_string(),
            ));
        }
        if let Err(e) = write_txn.open_table(STATE_ROOTS) {
            return Err(Error::database_error(
                "Failed to create state roots table",
                e.to_string(),
            ));
        }
        if let Err(e) = write_txn.open_table(SUCCESSIONS) {
            return Err(Error::database_error(
                "Failed to create successions table",
                e.to_string(),
            ));
        }
        if let Err(e) = write_txn.open_table(ENTRIES) {
            return Err(Error::database_error(
                "Failed to create entries table",
                e.to_string(),
            ));
        }

        if let Err(e) = write_txn.commit() {
            return Err(Error::database_error(
                "Failed to commit initial transaction",
                e.to_string(),
            ));
        }

        let config = config.unwrap_or_default();
        let proof_system = Arc::new(ProofSystem::new(Arc::clone(&groups)));
        let state_tree = Arc::new(SparseMerkleTree::new(Arc::clone(&groups)));
        let rate_limiter = Arc::new(RateLimit::new(Duration::from_secs(300), 1000));
        let audit_log = Arc::new(
            AuditLog::new(
                Arc::clone(&db),
                Arc::clone(&rate_limiter),
                config.operation_timeout,
            )
            .map_err(|e| Error::database_error("Failed to initialize audit log", e.to_string()))?,
        );

        let initial_state = SystemState {
            state_root: Vec::new(),
            admin_keys: AdminKeySet::default(),
            last_updated: time::OffsetDateTime::now_utc(),
        };

        Ok(Self {
            db,
            state_tree,
            proof_system,
            groups,
            audit_log,
            rate_limiter,
            config,
            policy_generation: AtomicU64::new(0),
            current_state: ArcSwap::new(Arc::new(initial_state)),
        })
    }

    pub async fn add_entry(
        &self,
        entry: &ACLEntry,
        admin: &AdminKeySet,
    ) -> Result<StateMatrixCommitment> {
        if let Err(e) = self.rate_limiter.check() {
            return Err(Error::rate_limited(
                "Rate limit exceeded for add_entry",
                e.to_string(),
            ));
        }

        let current_generation = self.policy_generation.load(Ordering::Acquire);
        if entry.policy_generation as u64 != current_generation {
            return Err(Error::invalid_entry(
                "Invalid policy generation",
                format!(
                    "Entry generation {} does not match current {}",
                    entry.policy_generation, current_generation
                ),
            ));
        }

        // Create commitment
        let commitment = StateMatrixCommitment::from_entry(entry, &self.groups)?;

        let write_txn = self.db.begin_write()?;

        // Insert entry into database
        {
            let mut entries_table = write_txn.open_table(ENTRIES)?;
            let entry_bytes = serde_json::to_vec(&entry)?;
            entries_table.insert(entry.id.0.as_slice(), entry_bytes.as_slice())?;
        }

        // Update Merkle tree
        let proof = self.state_tree.insert(entry.id.0, *commitment.value())?;

        // Update system state
        let mut state_root = Vec::new();
        proof.root.inner().serialize_uncompressed(&mut state_root)?;
        let new_state = SystemState {
            state_root,
            admin_keys: self.current_state.load().admin_keys.clone(),
            last_updated: time::OffsetDateTime::now_utc(),
        };

        self.save_system_state(&write_txn, &new_state)?;
        write_txn.commit()?;

        self.current_state.store(new_state.into());

        // Record audit event
        self.audit_log
            .record_event(
                "ENTRY_ADDED".into(),
                entry.policy_generation,
                serde_json::json!({
                    "entry_id": entry.id.0.to_vec(),
                }),
            )
            .await?;

        Ok(commitment)
    }

    pub async fn process_succession(
        &self,
        succession: &SuccessionRecord,
        current_admin: &AdminKeySet,
    ) -> Result<()> {
        if let Err(e) = self.rate_limiter.check() {
            return Err(Error::rate_limited(
                "Rate limit exceeded for process_succession",
                e.to_string(),
            ));
        }

        let verification = match self
            .proof_system
            .verify_succession(succession, current_admin)
        {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::verification_failed(
                    "Succession verification failed",
                    e.to_string(),
                ))
            }
        };

        if !verification {
            return Err(Error::invalid_succession(
                "Invalid succession record",
                "Verification failed",
            ));
        }

        let current_generation = self.policy_generation.load(Ordering::Acquire);
        if succession.generation as u64 <= current_generation {
            return Err(Error::invalid_succession(
                "Invalid generation",
                format!(
                    "Succession generation {} must be greater than current {}",
                    succession.generation, current_generation
                ),
            ));
        }

        let new_state = SystemState {
            state_root: self.current_state.load().state_root.clone(),
            admin_keys: AdminKeySet {
                active_keys: succession.new_keys.clone(),
                policy_generation: succession.generation,
                last_rotation: succession.timestamp,
            },
            last_updated: time::OffsetDateTime::now_utc(),
        };

        let write_txn = match self.db.begin_write() {
            Ok(txn) => txn,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to begin transaction",
                    e.to_string(),
                ))
            }
        };

        // Save succession record
        let mut successions_table = match write_txn.open_table(SUCCESSIONS) {
            Ok(table) => table,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to open successions table",
                    e.to_string(),
                ))
            }
        };

        let succession_bytes = match serde_json::to_vec(succession) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to serialize succession record",
                    e.to_string(),
                ))
            }
        };

        let generation_bytes = succession.generation.to_le_bytes();
        if let Err(e) =
            successions_table.insert(generation_bytes.as_slice(), succession_bytes.as_slice())
        {
            return Err(Error::database_error(
                "Failed to insert succession record",
                e.to_string(),
            ));
        }
        drop(successions_table);

        if let Err(e) = self.save_system_state(&write_txn, &new_state) {
            return Err(Error::database_error(
                "Failed to save system state",
                e.to_string(),
            ));
        }

        if let Err(e) = write_txn.commit() {
            return Err(Error::database_error(
                "Failed to commit transaction",
                e.to_string(),
            ));
        }

        self.policy_generation
            .store(succession.generation as u64, Ordering::Release);
        self.current_state.store(new_state.into());

        if let Err(e) = self
            .audit_log
            .record_event(
                "SUCCESSION_PROCESSED".into(),
                succession.generation,
                serde_json::json!({
                    "old_generation": current_admin.policy_generation,
                    "new_generation": succession.generation,
                    "affected_entries": succession.affected_entries.len(),
                }),
            )
            .await
        {
            return Err(Error::database_error(
                "Failed to record audit event",
                e.to_string(),
            ));
        }

        Ok(())
    }

    pub async fn verify_access(&self, entry_id: &EntryId, generation: u32) -> Result<bool> {
        self.rate_limiter.check()?;

        let current_generation = self.policy_generation.load(Ordering::Acquire);
        if generation as u64 > current_generation {
            return Ok(false);
        }

        let current_state = self.current_state.load();
        let mut root_bytes = &current_state.state_root[..];
        let root = G1::deserialize_compressed(&mut root_bytes)?;

        let proof = self.state_tree.get_proof(&entry_id.0)?;
        if !self
            .state_tree
            .verify_proof(&entry_id.0, proof.value.inner(), &proof)?
        {
            return Ok(false);
        }

        let read_txn = self.db.begin_read()?;
        let entries_table = read_txn.open_table(ENTRIES)?;

        match entries_table.get(entry_id.0.as_slice())? {
            Some(bytes) => {
                let entry: ACLEntry = serde_json::from_slice(bytes.value())?;
                let commitment = StateMatrixCommitment::from_entry(&entry, &self.groups)?;
                Ok(!commitment.is_revoked())
            }
            None => Ok(false),
        }
    }

    fn save_system_state(&self, txn: &redb::WriteTransaction, state: &SystemState) -> Result<()> {
        let mut admin_table = match txn.open_table(ADMIN_STATE) {
            Ok(table) => table,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to open admin state table",
                    e.to_string(),
                ))
            }
        };

        let state_bytes = match serde_json::to_vec(state) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to serialize system state",
                    e.to_string(),
                ))
            }
        };

        if let Err(e) = admin_table.insert(CURRENT_KEY, state_bytes.as_slice()) {
            return Err(Error::database_error(
                "Failed to insert system state",
                e.to_string(),
            ));
        }

        Ok(())
    }

    pub async fn get_entry(&self, id: &EntryId) -> Result<Option<ACLEntry>> {
        if let Err(e) = self.rate_limiter.check() {
            return Err(Error::rate_limited(
                "Rate limit exceeded for get_entry",
                e.to_string(),
            ));
        }

        let read_txn = match self.db.begin_read() {
            Ok(txn) => txn,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to begin transaction",
                    e.to_string(),
                ))
            }
        };

        let entries_table = match read_txn.open_table(ENTRIES) {
            Ok(table) => table,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to open entries table",
                    e.to_string(),
                ))
            }
        };

        let entry_bytes = match entries_table.get(id.0.as_slice()) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(Error::database_error("Failed to read entry", e.to_string())),
        };

        let entry = match serde_json::from_slice(entry_bytes.value()) {
            Ok(entry) => entry,
            Err(e) => {
                return Err(Error::database_error(
                    "Failed to deserialize entry",
                    e.to_string(),
                ))
            }
        };

        Ok(Some(entry))
    }

    pub fn get_current_admin(&self) -> Result<AdminKeySet> {
        Ok(self.current_state.load().admin_keys.clone())
    }

    pub fn proof_system(&self) -> &Arc<ProofSystem> {
        &self.proof_system
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{AggregateSignature, SerializableG2},
        types::{AuthProof, EntryMetadata, ServiceId},
    };

    use super::*;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    fn create_test_admin_key_set(groups: &CurveGroups) -> AdminKeySet {
        AdminKeySet {
            active_keys: vec![SerializableG2::from(groups.g2_generator)],
            policy_generation: 0,
            last_rotation: OffsetDateTime::now_utc(),
        }
    }

    fn create_test_entry(admin: &AdminKeySet) -> ACLEntry {
        ACLEntry {
            id: EntryId([1u8; 32]),
            service_id: ServiceId("test_service".to_string()),
            policy_generation: admin.policy_generation,
            metadata: EntryMetadata::default(),
            auth_proof: AuthProof {
                aggregate_signature: AggregateSignature {
                    aggregate: G1::default(),
                    public_keys: admin.active_keys.iter().map(|key| *key.inner()).collect(),
                },
                policy_generation: admin.policy_generation,
                threshold: 1,
            },
        }
    }

    #[tokio::test]
    async fn test_storage_initialization() -> Result<()> {
        let temp_dir = tempdir()
            .map_err(|e| Error::database_error("Failed to create temp directory", e.to_string()))?;

        let groups = Arc::new(CurveGroups::new());
        let storage = Storage::new(temp_dir.path().join("test.db"), None, Arc::clone(&groups))?;

        assert_eq!(storage.policy_generation.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_entry_lifecycle() -> Result<()> {
        let temp_dir = tempdir()
            .map_err(|e| Error::database_error("Failed to create temp directory", e.to_string()))?;

        let groups = Arc::new(CurveGroups::new());
        let storage = Storage::new(temp_dir.path().join("test.db"), None, Arc::clone(&groups))?;

        let admin = create_test_admin_key_set(&groups);
        let entry = create_test_entry(&admin);

        // Add entry
        let commitment = storage.add_entry(&entry, &admin).await?;
        assert!(!commitment.is_revoked());

        // Verify access
        let access_valid = storage
            .verify_access(&entry.id, admin.policy_generation)
            .await?;
        assert!(access_valid);

        // Retrieve entry
        let stored_entry = storage
            .get_entry(&entry.id)
            .await?
            .expect("Entry should exist");
        assert_eq!(stored_entry.id, entry.id);
        assert_eq!(stored_entry.policy_generation, entry.policy_generation);

        Ok(())
    }

    #[tokio::test]
    async fn test_succession() -> Result<()> {
        let temp_dir = tempdir()
            .map_err(|e| Error::database_error("Failed to create temp directory", e.to_string()))?;

        let groups = Arc::new(CurveGroups::new());
        let storage = Storage::new(temp_dir.path().join("test.db"), None, Arc::clone(&groups))?;

        let old_admin = create_test_admin_key_set(&groups);

        // Create new admin keys
        let new_keys = vec![SerializableG2::from(groups.random_g2())];

        let succession = SuccessionRecord {
            old_keys: old_admin.active_keys.clone(),
            new_keys: new_keys.clone(),
            generation: old_admin.policy_generation + 1,
            timestamp: OffsetDateTime::now_utc(),
            affected_entries: Vec::new(),
            auth_proof: AuthProof {
                aggregate_signature: AggregateSignature {
                    aggregate: G1::default(),
                    public_keys: old_admin
                        .active_keys
                        .iter()
                        .map(|key| *key.inner())
                        .collect(),
                },
                policy_generation: old_admin.policy_generation,
                threshold: 1,
            },
            request_metadata: None,
        };

        storage.process_succession(&succession, &old_admin).await?;

        let current_admin = storage.get_current_admin()?;
        assert_eq!(current_admin.active_keys, new_keys);
        assert_eq!(current_admin.policy_generation, succession.generation);

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_access() -> Result<()> {
        let temp_dir = tempdir()
            .map_err(|e| Error::database_error("Failed to create temp directory", e.to_string()))?;

        let groups = Arc::new(CurveGroups::new());
        let storage = Arc::new(Storage::new(
            temp_dir.path().join("test.db"),
            None,
            Arc::clone(&groups),
        )?);

        let admin = create_test_admin_key_set(&groups);
        let mut handles = Vec::new();

        for i in 0..10 {
            let storage = Arc::clone(&storage);
            let admin = admin.clone();

            let mut entry = create_test_entry(&admin);
            entry.id = EntryId([i as u8; 32]);

            handles.push(tokio::spawn(async move {
                storage.add_entry(&entry, &admin).await
            }));
        }

        for handle in handles {
            handle
                .await
                .map_err(|e| Error::database_error("Task join failed", e.to_string()))??;
        }

        Ok(())
    }
}
