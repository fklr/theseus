use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::{
    audit::AuditLog,
    crypto::{
        commitment::StateMatrixCommitment, merkle::SparseMerkleTree, primitives::CurveGroups,
        proofs::ProofSystem,
    },
    errors::{Error, Result},
    rate_limit::RateLimit,
    types::{ACLEntry, AdminKeySet, AuthProof, EntryId, SuccessionRecord},
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

#[derive(Debug, Clone)]
struct StateCache {
    commitment: StateMatrixCommitment,
    generation: u32,
    timestamp: time::OffsetDateTime,
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
    state_cache: DashMap<Vec<u8>, StateCache>,
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
            state_cache: DashMap::new(),
        })
    }

    pub async fn add_entry(
        &self,
        entry: &ACLEntry,
        admin: &AdminKeySet,
    ) -> Result<StateMatrixCommitment> {
        self.rate_limiter.check()?;

        let canonical_data = serde_json::json!({
            "id": entry.id.0,
            "service_id": entry.service_id.0,
            "policy_generation": entry.policy_generation,
            "metadata": entry.metadata,
        });

        if !entry
            .auth_proof
            .aggregate_signature
            .verify(&serde_json::to_vec(&canonical_data)?, &self.groups)?
        {
            return Err(Error::invalid_entry(
                "Invalid signature",
                "Entry signature verification failed",
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

        let commitment = StateMatrixCommitment::from_entry(entry, &self.groups)?;

        let write_txn = self.db.begin_write()?;

        {
            let new_state = {
                let mut entries_table = write_txn.open_table(ENTRIES)?;
                let mut state_roots = write_txn.open_table(STATE_ROOTS)?;

                let proof = self.state_tree.insert(entry.id.0, *commitment.value())?;
                let mut root_bytes = Vec::new();
                proof.root.inner().serialize_compressed(&mut root_bytes)?;

                entries_table
                    .insert(entry.id.0.as_slice(), serde_json::to_vec(entry)?.as_slice())?;
                state_roots.insert(ROOT_KEY, root_bytes.as_slice())?;

                let new_state = SystemState {
                    state_root: root_bytes,
                    admin_keys: self.current_state.load().admin_keys.clone(),
                    last_updated: time::OffsetDateTime::now_utc(),
                };

                self.save_system_state(&write_txn, &new_state)?;
                drop(entries_table);
                drop(state_roots);

                new_state
            };

            write_txn.commit()?;

            self.current_state.store(Arc::new(new_state));
            if self.state_cache.len() < self.config.state_cache_size {
                self.state_cache.insert(
                    entry.id.0.to_vec(),
                    StateCache {
                        commitment: commitment.clone(),
                        generation: entry.policy_generation,
                        timestamp: time::OffsetDateTime::now_utc(),
                    },
                );
            }
        }

        self.audit_log
            .record_event(
                "ENTRY_ADDED".into(),
                entry.policy_generation,
                serde_json::json!({
                    "entry_id": entry.id.0.to_vec(),
                    "admin": admin.active_keys[0],
                    "root_updated": true,
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
        self.rate_limiter.check()?;

        if !self
            .proof_system
            .verify_succession(succession, current_admin)?
        {
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

        let write_txn = self.db.begin_write()?;

        {
            let mut successions_table = write_txn.open_table(SUCCESSIONS)?;
            successions_table.insert(
                current_generation.to_le_bytes().as_slice(),
                serde_json::to_vec(succession)?.as_slice(),
            )?;
        }

        let mut updated_entries = Vec::new();
        {
            let entries_table = write_txn.open_table(ENTRIES)?;
            for entry_id in &succession.affected_entries {
                let bytes = entries_table.get(entry_id.0.as_slice())?.ok_or_else(|| {
                    Error::invalid_succession("Missing entry", "Affected entry not found")
                })?;

                let mut entry: ACLEntry = serde_json::from_slice(bytes.value())?;
                entry.policy_generation = succession.generation;
                entry.auth_proof = AuthProof {
                    aggregate_signature: succession.auth_proof.aggregate_signature.clone(),
                    policy_generation: succession.generation,
                    threshold: succession.auth_proof.threshold,
                    succession_proof: Some(succession.auth_proof.succession_proof.clone().unwrap()),
                };

                updated_entries.push(entry);
            }
        }

        {
            let mut entries_table = write_txn.open_table(ENTRIES)?;
            let mut state_roots = write_txn.open_table(STATE_ROOTS)?;

            for entry in &updated_entries {
                let commitment = StateMatrixCommitment::from_entry(entry, &self.groups)?;
                self.state_tree.insert(entry.id.0, *commitment.value())?;
                entries_table
                    .insert(entry.id.0.as_slice(), serde_json::to_vec(entry)?.as_slice())?;
            }

            let final_proof = self
                .state_tree
                .get_proof(&succession.affected_entries[0].0)?;
            let mut root_bytes = Vec::new();
            final_proof
                .root
                .inner()
                .serialize_compressed(&mut root_bytes)?;
            state_roots.insert(ROOT_KEY, root_bytes.as_slice())?;
        }

        let system_state = SystemState {
            state_root: self.current_state.load().state_root.clone(),
            admin_keys: AdminKeySet {
                active_keys: succession.new_keys.clone(),
                policy_generation: succession.generation,
                last_rotation: succession.timestamp,
            },
            last_updated: time::OffsetDateTime::now_utc(),
        };

        self.save_system_state(&write_txn, &system_state)?;

        write_txn.commit()?;

        self.policy_generation
            .store(succession.generation as u64, Ordering::Release);
        self.current_state.store(Arc::new(system_state));

        Ok(())
    }

    pub async fn verify_access(&self, entry_id: &EntryId, generation: u32) -> Result<bool> {
        self.rate_limiter.check()?;

        if let Some(cached) = self.state_cache.get(&entry_id.0.to_vec()) {
            if cached.generation == generation
                && cached.timestamp + Duration::from_secs(300) > time::OffsetDateTime::now_utc()
            {
                return Ok(!cached.commitment.is_revoked());
            }
        }

        let current_generation = self.policy_generation.load(Ordering::Acquire);
        if generation as u64 > current_generation {
            return Ok(false);
        }

        let read_txn = self.db.begin_read()?;
        let entries_table = read_txn.open_table(ENTRIES)?;

        match entries_table.get(entry_id.0.as_slice())? {
            Some(bytes) => {
                let entry: ACLEntry = serde_json::from_slice(bytes.value())?;

                let commitment = StateMatrixCommitment::from_entry(&entry, &self.groups)?;

                if generation < entry.policy_generation {
                    return Ok(false);
                }

                if generation == entry.policy_generation {
                    if self.state_cache.len() < self.config.state_cache_size {
                        self.state_cache.insert(
                            entry_id.0.to_vec(),
                            StateCache {
                                commitment: commitment.clone(),
                                generation,
                                timestamp: time::OffsetDateTime::now_utc(),
                            },
                        );
                    }
                    return Ok(!commitment.is_revoked());
                }

                let successions = read_txn.open_table(SUCCESSIONS)?;
                let mut current_gen = entry.policy_generation;

                while current_gen < generation {
                    let succession_bytes = successions
                        .get(current_gen.to_le_bytes().as_slice())?
                        .ok_or_else(|| {
                        Error::invalid_succession("Missing succession", "Chain broken")
                    })?;

                    let succession: SuccessionRecord =
                        serde_json::from_slice(succession_bytes.value())?;

                    if !succession.affected_entries.contains(&entry.id) {
                        return Ok(false);
                    }

                    if !self.proof_system.verify_succession(
                        &succession,
                        &AdminKeySet {
                            active_keys: succession.old_keys.clone(),
                            policy_generation: current_gen,
                            last_rotation: succession.timestamp,
                        },
                    )? {
                        return Ok(false);
                    }

                    current_gen = succession.generation;
                }

                if self.state_cache.len() < self.config.state_cache_size {
                    self.state_cache.insert(
                        entry_id.0.to_vec(),
                        StateCache {
                            commitment: commitment.clone(),
                            generation,
                            timestamp: time::OffsetDateTime::now_utc(),
                        },
                    );
                }

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
        crypto::{
            primitives::RandomGenerator, AggregateSignature, BlsSignature, Circuit, Scalar,
            SerializableG2,
        },
        types::{AuthProof, EntryMetadata, ServiceId},
    };

    use super::*;
    use ark_ec::CurveGroup;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    fn create_test_admin_key_set(groups: &CurveGroups) -> AdminKeySet {
        let rng = RandomGenerator::new();
        let secret_key = rng.random_scalar();
        let public_key = (groups.g2_generator * secret_key).into_affine();

        AdminKeySet {
            active_keys: vec![SerializableG2::from(public_key)],
            policy_generation: 0,
            last_rotation: OffsetDateTime::now_utc(),
        }
    }

    fn create_test_entry(
        admin: &AdminKeySet,
        secret_key: &Scalar,
        groups: &CurveGroups,
    ) -> Result<ACLEntry> {
        let signing_data = ACLEntry {
            id: EntryId([1u8; 32]),
            service_id: ServiceId("test_service".to_string()),
            policy_generation: admin.policy_generation,
            metadata: EntryMetadata::default(),
            auth_proof: AuthProof {
                aggregate_signature: AggregateSignature::default(),
                policy_generation: admin.policy_generation,
                threshold: 1,
                succession_proof: None,
            },
        };

        let canonical_data = serde_json::json!({
            "id": signing_data.id.0,
            "service_id": signing_data.service_id.0,
            "policy_generation": signing_data.policy_generation,
            "metadata": signing_data.metadata,
        });

        let signature =
            BlsSignature::sign(&serde_json::to_vec(&canonical_data)?, secret_key, groups)?;

        Ok(ACLEntry {
            auth_proof: AuthProof {
                aggregate_signature: AggregateSignature::aggregate(&[signature])?,
                ..signing_data.auth_proof
            },
            ..signing_data
        })
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
        let rng = RandomGenerator::new();
        let secret_key = rng.random_scalar();
        let entry = create_test_entry(&admin, &secret_key, &groups)?;

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
        let rng = RandomGenerator::new();

        // Create initial admin keys
        let old_secret_key = rng.random_scalar();
        let old_public_key = (groups.g2_generator * old_secret_key).into_affine();
        let old_admin = AdminKeySet {
            active_keys: vec![SerializableG2::from(old_public_key)],
            policy_generation: 0,
            last_rotation: OffsetDateTime::now_utc(),
        };

        // Create test entry and verify initial access
        let test_entry = create_test_entry(&old_admin, &old_secret_key, &groups)?;
        let initial_commitment = storage.add_entry(&test_entry, &old_admin).await?;

        assert!(
            storage
                .verify_access(&test_entry.id, old_admin.policy_generation)
                .await?
        );

        // Generate new admin keys
        let new_secret_key = rng.random_scalar();
        let new_public_key = (groups.g2_generator * new_secret_key).into_affine();
        let new_keys = vec![SerializableG2::from(new_public_key)];

        // Create succession proof circuit
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let old_policy_var =
            circuit.allocate_scalar(&Scalar::from(old_admin.policy_generation as u64));
        let new_policy_var =
            circuit.allocate_scalar(&Scalar::from((old_admin.policy_generation + 1) as u64));
        circuit.enforce_policy_transition(old_policy_var, new_policy_var);

        let old_key_point = circuit.allocate_g2_point(&old_public_key);
        let new_key_point = circuit.allocate_g2_point(&new_public_key);
        circuit.enforce_key_succession(old_key_point, new_key_point);

        let proof = storage.proof_system().prove(&circuit)?;

        // Create succession record
        let succession = SuccessionRecord {
            old_keys: old_admin.active_keys.clone(),
            new_keys: new_keys.clone(),
            generation: old_admin.policy_generation + 1,
            timestamp: OffsetDateTime::now_utc(),
            affected_entries: vec![test_entry.id],
            auth_proof: AuthProof {
                aggregate_signature: {
                    let message = serde_json::to_vec(&proof)?;
                    let signature = BlsSignature::sign(&message, &old_secret_key, &groups)?;
                    AggregateSignature::aggregate(&[signature])?
                },
                policy_generation: old_admin.policy_generation,
                threshold: 1,
                succession_proof: Some(proof),
            },
            request_metadata: None,
        };

        // Process succession and verify admin update
        storage.process_succession(&succession, &old_admin).await?;
        let current_admin = storage.get_current_admin()?;
        assert_eq!(current_admin.active_keys, new_keys);
        assert_eq!(current_admin.policy_generation, succession.generation);

        // Verify that the affected entry remains valid under new admin
        assert!(
            storage
                .verify_access(&test_entry.id, current_admin.policy_generation)
                .await?
        );

        // Verify that access with old policy generation fails
        assert!(
            !storage
                .verify_access(&test_entry.id, old_admin.policy_generation)
                .await?
        );

        // Verify that initial commitment is still recognized but updated
        let updated_commitment = StateMatrixCommitment::from_entry(&test_entry, &groups)?;
        assert_eq!(initial_commitment.value(), updated_commitment.value());
        assert!(!initial_commitment.is_revoked());

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
            let rng = RandomGenerator::new();
            let secret_key = rng.random_scalar();

            let signing_data = ACLEntry {
                id: EntryId([i as u8; 32]), // Unique ID for each entry
                service_id: ServiceId(format!("test_service_{}", i)), // Unique service ID
                policy_generation: admin.policy_generation,
                metadata: EntryMetadata::default(),
                auth_proof: AuthProof {
                    aggregate_signature: AggregateSignature::default(),
                    policy_generation: admin.policy_generation,
                    threshold: 1,
                    succession_proof: None,
                },
            };

            let canonical_data = serde_json::json!({
                "id": signing_data.id.0,
                "service_id": signing_data.service_id.0,
                "policy_generation": signing_data.policy_generation,
                "metadata": signing_data.metadata,
            });

            let signature =
                BlsSignature::sign(&serde_json::to_vec(&canonical_data)?, &secret_key, &groups)?;

            let entry = ACLEntry {
                auth_proof: AuthProof {
                    aggregate_signature: AggregateSignature::aggregate(&[signature])?,
                    ..signing_data.auth_proof
                },
                ..signing_data
            };

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
