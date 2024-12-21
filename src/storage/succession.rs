use dashmap::DashMap;
use ed25519_dalek::Verifier;
use rayon::prelude::*;
use redb::Database;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use crate::{
    crypto::ProofSystem,
    errors::{Error, Result},
    types::{
        ACLEntry, AdminKeySet, AdminPolicy, EntryMetadata, SerializableSignature, ServiceId,
        SuccessionRecord,
    },
};

use super::{proof_store::ProofStore, rate_limit::RateLimit, ADMIN_STATE, SUCCESSIONS};

const ADMIN_KEY: &[u8] = b"current";
const DEFAULT_BATCH_SIZE: usize = 64;
const MAX_BATCH_SIZE: usize = 1024;

#[derive(Clone)]
struct ChainState {
    start_generation: u32,
    end_generation: u32,
    records: Vec<SuccessionRecord>,
    affected_entries: Vec<ACLEntry>,
    composite_proof: Option<Vec<u8>>,
    timestamp: time::OffsetDateTime,
}

impl ChainState {
    fn new(
        start_gen: u32,
        end_gen: u32,
        records: Vec<SuccessionRecord>,
        affected: Vec<ACLEntry>,
        timestamp: time::OffsetDateTime,
    ) -> Self {
        Self {
            start_generation: start_gen,
            end_generation: end_gen,
            records,
            affected_entries: affected,
            composite_proof: None,
            timestamp,
        }
    }
}

pub struct SuccessionManager {
    db: Arc<Database>,
    rate_limiter: Arc<RateLimit>,
    proof_system: Arc<ProofSystem>,
    proof_store: Arc<ProofStore>,
    chain_cache: DashMap<u32, ChainState>,
    operation_timeout: Duration,
}

impl SuccessionManager {
    pub fn new(
        db: Arc<Database>,
        rate_limiter: Arc<RateLimit>,
        proof_system: Arc<ProofSystem>,
        proof_store: Arc<ProofStore>,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            db,
            rate_limiter,
            proof_system,
            proof_store,
            chain_cache: DashMap::new(),
            operation_timeout: timeout,
        })
    }

    pub async fn process_succession(
        &self,
        succession: &SuccessionRecord,
        admin: &AdminKeySet,
    ) -> Result<()> {
        self.rate_limiter.check()?;

        timeout(self.operation_timeout, async {
            let write_txn = self
                .db
                .begin_write()
                .map_err(|e| Error::database_error("Transaction failed", e.to_string()))?;

            self.verify_succession_record(succession, admin)?;

            let is_recovery = succession
                .request_metadata
                .as_ref()
                .and_then(|m| m.get("is_recovery"))
                .and_then(|v| v.as_bool())
                .map_or(false, |v| v);

            let updated_policy = self.update_admin_policy(&write_txn, succession, is_recovery)?;
            let new_admin = AdminKeySet {
                active_keys: updated_policy.administrators,
                policy_generation: updated_policy.policy_generation,
                last_rotation: succession.timestamp,
            };

            let admin_bytes = serde_json::to_vec(&new_admin).map_err(|e| {
                Error::database_error("Failed to serialize admin state", e.to_string())
            })?;

            self.update_admin_state(&write_txn, ADMIN_KEY, &admin_bytes)?;

            let succession_bytes = serde_json::to_vec(succession).map_err(|e| {
                Error::database_error("Failed to serialize succession record", e.to_string())
            })?;

            {
                let mut successions = write_txn.open_table(SUCCESSIONS).map_err(|e| {
                    Error::database_error("Failed to open successions table", e.to_string())
                })?;

                successions
                    .insert(
                        &succession.generation.to_be_bytes().as_slice(),
                        succession_bytes.as_slice(),
                    )
                    .map_err(|e| {
                        Error::database_error("Failed to insert succession", e.to_string())
                    })?;
            }

            let chain_state = self.build_chain_state(succession, admin)?;
            self.chain_cache.insert(succession.generation, chain_state);

            write_txn.commit().map_err(|e| {
                Error::database_error("Failed to commit transaction", e.to_string())
            })?;

            Ok(())
        })
        .await
        .map_err(|_| {
            Error::database_error("Operation timeout", "Succession operation timed out")
        })??;

        Ok(())
    }

    pub async fn validate_across_chain(
        &self,
        entries: &[ACLEntry],
        start_gen: u32,
        end_gen: u32,
    ) -> Result<Vec<bool>> {
        self.rate_limiter.check()?;

        let results = timeout(self.operation_timeout, async {
            if entries.is_empty() {
                return Ok(vec![]);
            }

            let chain_state = match self.find_covering_chain(start_gen, end_gen)? {
                Some(chain) => chain,
                None => {
                    let records = self.get_succession_chain(start_gen, end_gen)?;
                    if records.is_empty() {
                        let admin = self.get_current_admin()?;
                        if admin.policy_generation < start_gen || admin.policy_generation > end_gen
                        {
                            return Ok(vec![false; entries.len()]);
                        }
                        // If there are no succession records but the admin state is valid,
                        // validate against current admin
                        return entries
                            .iter()
                            .map(|entry| {
                                if entry.policy_generation != admin.policy_generation {
                                    return Ok(false);
                                }
                                match self.proof_store.load_proof(&entry.id)? {
                                    Some(proof) => self
                                        .proof_system
                                        .verify_validation_proof(&proof, entry, &admin),
                                    None => Ok(false),
                                }
                            })
                            .collect::<Result<Vec<_>>>();
                    }
                    ChainState::new(
                        start_gen,
                        end_gen,
                        records,
                        entries.to_vec(),
                        time::OffsetDateTime::now_utc(),
                    )
                }
            };

            let batch_size = calculate_optimal_batch_size(entries.len());
            let mut results = Vec::with_capacity(entries.len());

            for chunk in entries.chunks(batch_size) {
                let chunk_results: Vec<bool> = chunk
                    .par_iter()
                    .map(|entry| {
                        let proof = match self.proof_store.load_proof(&entry.id) {
                            Ok(Some(p)) => p,
                            _ => return Ok(false),
                        };

                        let relevant_records: Vec<_> = chain_state
                            .records
                            .iter()
                            .filter(|record| {
                                record.affected_entries.contains(&entry.id)
                                    && record.generation >= entry.policy_generation
                            })
                            .collect();

                        for record in relevant_records {
                            let admin = AdminKeySet {
                                active_keys: record.old_keys,
                                policy_generation: record.generation - 1,
                                last_rotation: record.timestamp,
                            };

                            if self
                                .proof_system
                                .verify_validation_proof(&proof, entry, &admin)?
                            {
                                return Ok(true);
                            }
                        }

                        let current_admin = self.get_current_admin()?;
                        if entry.policy_generation == current_admin.policy_generation {
                            return self.proof_system.verify_validation_proof(
                                &proof,
                                entry,
                                &current_admin,
                            );
                        }

                        Ok(false)
                    })
                    .collect::<Result<Vec<_>>>()?;

                results.extend(chunk_results);
            }

            Ok(results)
        })
        .await
        .map_err(|_| Error::database_error("Operation timeout", "Chain validation timed out"))??;

        Ok(results)
    }

    fn verify_succession_record(
        &self,
        succession: &SuccessionRecord,
        admin: &AdminKeySet,
    ) -> Result<()> {
        if succession.generation <= admin.policy_generation {
            return Err(Error::invalid_succession(
                "Invalid succession",
                "Invalid generation sequence",
            ));
        }

        let is_recovery = succession
            .request_metadata
            .as_ref()
            .and_then(|m| m.get("is_recovery"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let message = self
            .proof_system
            .create_succession_message(admin.policy_generation, &succession.new_keys);

        if is_recovery {
            let current_admin_policy = self.get_current_admin_policy()?;

            let recovery_keys = current_admin_policy.recovery_keys.ok_or_else(|| {
                Error::invalid_succession(
                    "Recovery attempted",
                    "No recovery keys configured for this service",
                )
            })?;

            let valid_recovery = succession
                .signatures
                .iter()
                .zip(&recovery_keys)
                .any(|(sig, key)| key.verify(&message, &sig.0).is_ok());

            if !valid_recovery {
                return Err(Error::invalid_succession(
                    "Invalid recovery",
                    "Recovery signature verification failed",
                ));
            }
        } else {
            if succession.old_keys != admin.active_keys {
                return Err(Error::invalid_succession(
                    "Invalid succession",
                    "Old keys do not match current admin keys",
                ));
            }

            let valid_signatures = succession
                .signatures
                .iter()
                .zip(&admin.active_keys)
                .all(|(sig, key)| key.verify(&message, &sig.0).is_ok());

            if !valid_signatures {
                return Err(Error::invalid_succession(
                    "Invalid succession",
                    "Signature verification failed",
                ));
            }
        }

        Ok(())
    }

    fn get_current_admin_policy(&self) -> Result<AdminPolicy> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::database_error("Transaction failed", e.to_string()))?;

        let admin_table = read_txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::database_error("Failed to open admin state table", e.to_string())
        })?;

        let policy_bytes = admin_table
            .get(b"admin_policy".as_slice())
            .map_err(|e| Error::database_error("Failed to read admin policy", e.to_string()))?
            .ok_or_else(|| Error::database_error("Not found", "No admin policy found"))?;

        serde_json::from_slice(policy_bytes.value())
            .map_err(|e| Error::database_error("Failed to deserialize admin policy", e.to_string()))
    }

    fn update_admin_policy(
        &self,
        txn: &redb::WriteTransaction,
        succession: &SuccessionRecord,
        is_recovery: bool,
    ) -> Result<AdminPolicy> {
        let mut current_policy = self.get_current_admin_policy()?;

        current_policy.administrators = succession.new_keys;
        current_policy.policy_generation = succession.generation;

        if is_recovery {
            if let Some(recovery_metadata) = succession
                .request_metadata
                .as_ref()
                .and_then(|m| m.get("recovery_policy_updates"))
            {
                if let Some(new_recovery_keys) = recovery_metadata.get("new_recovery_keys") {
                    let key_bytes: [[u8; 32]; 2] =
                        serde_json::from_value(new_recovery_keys.clone()).map_err(|e| {
                            Error::invalid_succession(
                                "Invalid recovery keys format",
                                format!("Failed to parse recovery keys: {}", e),
                            )
                        })?;

                    let recovery_keys = [
                        ed25519_dalek::VerifyingKey::from_bytes(&key_bytes[0]).map_err(|e| {
                            Error::invalid_succession(
                                "Invalid recovery key",
                                format!("Failed to parse first recovery key: {}", e),
                            )
                        })?,
                        ed25519_dalek::VerifyingKey::from_bytes(&key_bytes[1]).map_err(|e| {
                            Error::invalid_succession(
                                "Invalid recovery key",
                                format!("Failed to parse second recovery key: {}", e),
                            )
                        })?,
                    ];

                    current_policy.recovery_keys = Some(recovery_keys);
                }
            }
        }

        let policy_bytes = serde_json::to_vec(&current_policy).map_err(|e| {
            Error::database_error("Failed to serialize updated admin policy", e.to_string())
        })?;

        let mut admin_table = txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::database_error("Failed to open admin state table", e.to_string())
        })?;

        admin_table
            .insert(b"admin_policy".as_slice(), policy_bytes.as_slice())
            .map_err(|e| Error::database_error("Failed to update admin policy", e.to_string()))?;

        Ok(current_policy)
    }

    pub fn get_proof_system(&self) -> &ProofSystem {
        &self.proof_system
    }

    fn find_covering_chain(&self, start_gen: u32, end_gen: u32) -> Result<Option<ChainState>> {
        if let Some(chain) = self.chain_cache.get(&end_gen) {
            if chain.start_generation <= start_gen {
                return Ok(Some(chain.clone()));
            }
        }
        Ok(None)
    }

    fn get_succession_chain(&self, start_gen: u32, end_gen: u32) -> Result<Vec<SuccessionRecord>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::database_error("Transaction failed", e.to_string()))?;

        let successions = read_txn.open_table(SUCCESSIONS).map_err(|e| {
            Error::database_error("Failed to open successions table", e.to_string())
        })?;

        let mut records = Vec::new();
        for gen in start_gen..=end_gen {
            if let Some(bytes) = successions
                .get(&gen.to_be_bytes().as_slice())
                .map_err(|e| Error::database_error("Failed to read succession", e.to_string()))?
            {
                let record: SuccessionRecord =
                    serde_json::from_slice(bytes.value()).map_err(|e| {
                        Error::database_error("Failed to deserialize record", e.to_string())
                    })?;
                records.push(record);
            }
        }

        Ok(records)
    }

    fn get_current_admin(&self) -> Result<AdminKeySet> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::database_error("Transaction failed", e.to_string()))?;

        let admin_table = read_txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::database_error("Failed to open admin state table", e.to_string())
        })?;

        let admin_bytes = admin_table
            .get(ADMIN_KEY)
            .map_err(|e| Error::database_error("Failed to read admin state", e.to_string()))?
            .ok_or_else(|| Error::database_error("Not found", "No admin state found"))?;

        serde_json::from_slice(admin_bytes.value())
            .map_err(|e| Error::database_error("Failed to deserialize admin state", e.to_string()))
    }

    fn update_admin_state(
        &self,
        txn: &redb::WriteTransaction,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let mut admin_table = txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::database_error("Failed to open admin state table", e.to_string())
        })?;

        admin_table
            .insert(key, value)
            .map_err(|e| Error::database_error("Failed to update admin state", e.to_string()))?;

        Ok(())
    }

    fn build_chain_state(
        &self,
        succession: &SuccessionRecord,
        admin: &AdminKeySet,
    ) -> Result<ChainState> {
        let chain_state = if let Some(existing) = self.chain_cache.get(&admin.policy_generation) {
            let mut state = existing.clone();

            if !state
                .records
                .iter()
                .any(|r| r.generation == succession.generation)
            {
                state.records.push(succession.clone());
            }

            let (service_id, metadata) = if !state.affected_entries.is_empty() {
                (
                    state.affected_entries[0].service_id.clone(),
                    state.affected_entries[0].metadata.clone(),
                )
            } else {
                (
                    ServiceId("succession".into()),
                    EntryMetadata {
                        created_at: succession.timestamp,
                        expires_at: None,
                        version: 1,
                        service_specific: serde_json::Value::Null,
                    },
                )
            };

            let mut new_entries: Vec<_> = succession
                .affected_entries
                .iter()
                .filter(|entry_id| !state.affected_entries.iter().any(|e| e.id == **entry_id))
                .map(|entry_id| ACLEntry {
                    id: *entry_id,
                    service_id: service_id.clone(),
                    policy_generation: succession.generation,
                    metadata: metadata.clone(),
                    signature: SerializableSignature(ed25519_dalek::Signature::from_bytes(
                        &[0; 64],
                    )),
                })
                .collect();

            state.affected_entries.append(&mut new_entries);
            state.end_generation = succession.generation;
            state.composite_proof = None;
            state.timestamp = succession.timestamp;
            state
        } else {
            ChainState::new(
                admin.policy_generation,
                succession.generation,
                vec![succession.clone()],
                succession
                    .affected_entries
                    .iter()
                    .map(|entry_id| ACLEntry {
                        id: *entry_id,
                        service_id: ServiceId("succession".into()),
                        policy_generation: succession.generation,
                        metadata: EntryMetadata {
                            created_at: succession.timestamp,
                            expires_at: None,
                            version: 1,
                            service_specific: serde_json::Value::Null,
                        },
                        signature: SerializableSignature(ed25519_dalek::Signature::from_bytes(
                            &[0; 64],
                        )),
                    })
                    .collect(),
                succession.timestamp,
            )
        };

        Ok(chain_state)
    }
}

fn calculate_optimal_batch_size(total_entries: usize) -> usize {
    let cpu_count = num_cpus::get();
    let base_size = DEFAULT_BATCH_SIZE;

    let scaled_size = (total_entries / cpu_count).max(base_size);
    scaled_size.min(MAX_BATCH_SIZE)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;
    use crate::{
        storage::{rate_limit::MockClock, ENTRIES, PROOFS},
        types::{EntryId, SigningKeyPair, SuccessionPolicy},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tempfile::tempdir;

    async fn setup_test_succession() -> (SuccessionManager, SigningKeyPair, AdminKeySet) {
        let temp_dir = tempdir().unwrap();
        let db = Arc::new(Database::create(temp_dir.path().join("test.db")).unwrap());
        let rate_limiter = Arc::new(RateLimit::new(Duration::from_secs(1), 1000));
        let proof_system = Arc::new(ProofSystem::new());

        // Initialize database tables
        let write_txn = db.begin_write().unwrap();
        write_txn.open_table(SUCCESSIONS).unwrap();
        write_txn.open_table(ADMIN_STATE).unwrap();
        write_txn.open_table(ENTRIES).unwrap();
        write_txn.open_table(PROOFS).unwrap();
        write_txn.commit().unwrap();

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let key_pair = SigningKeyPair::new(signing_key);
        let recovery_key = SigningKeyPair::new(SigningKey::from_bytes(&[2u8; 32]));

        // Create initial admin state and policy
        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: time::OffsetDateTime::now_utc(),
        };

        let initial_policy = AdminPolicy {
            administrators: admin.active_keys,
            policy_generation: admin.policy_generation,
            succession_requirements: SuccessionPolicy {
                min_key_age: time::Duration::hours(24),
                required_signatures: 2,
            },
            recovery_keys: Some([recovery_key.verifying_key; 2]),
        };

        // Initialize admin policy and state
        let write_txn = db.begin_write().unwrap();
        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).unwrap();

            // Store policy
            let policy_bytes = serde_json::to_vec(&initial_policy).unwrap();
            admin_table
                .insert(b"admin_policy".as_slice(), policy_bytes.as_slice())
                .unwrap();

            // Store admin state
            let admin_bytes = serde_json::to_vec(&admin).unwrap();
            admin_table
                .insert(ADMIN_KEY, admin_bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        let proof_store = Arc::new(
            ProofStore::new(
                Arc::clone(&db),
                Arc::clone(&rate_limiter),
                Arc::clone(&proof_system),
                Duration::from_secs(30),
            )
            .unwrap(),
        );

        let manager = SuccessionManager::new(
            Arc::clone(&db),
            Arc::clone(&rate_limiter),
            Arc::clone(&proof_system),
            Arc::clone(&proof_store),
            Duration::from_secs(30),
        )
        .unwrap();

        (manager, key_pair, admin)
    }

    fn create_test_entry(
        id: [u8; 32],
        policy_gen: u32,
        key_pair: &SigningKeyPair,
        proof_system: &ProofSystem,
    ) -> ACLEntry {
        let mut entry = ACLEntry {
            id: EntryId::new(id),
            service_id: ServiceId("test".into()),
            policy_generation: policy_gen,
            metadata: EntryMetadata {
                created_at: time::OffsetDateTime::now_utc(),
                expires_at: None,
                version: 1,
                service_specific: serde_json::Value::Null,
            },
            signature: SerializableSignature(ed25519_dalek::Signature::from_bytes(&[0; 64])),
        };

        let message = proof_system.create_entry_message(&entry);
        entry.signature = key_pair.sign(&message);
        entry
    }

    fn create_test_succession(
        old_keys: [ed25519_dalek::VerifyingKey; 2],
        new_keys: [ed25519_dalek::VerifyingKey; 2],
        generation: u32,
        affected_entries: Vec<EntryId>,
        key_pair: &SigningKeyPair,
        proof_system: &ProofSystem,
    ) -> SuccessionRecord {
        let message = proof_system.create_succession_message(generation - 1, &new_keys);
        let signature = SerializableSignature(key_pair.signing_key.sign(&message));

        SuccessionRecord {
            old_keys,
            new_keys,
            generation,
            timestamp: time::OffsetDateTime::now_utc(),
            affected_entries,
            signatures: [signature.clone(), signature],
            request_metadata: None,
        }
    }

    #[tokio::test]
    async fn test_succession_chain_validation() {
        let (manager, key_pair, admin) = setup_test_succession().await;

        // Create and store initial entries
        for i in 0..5 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let entry = create_test_entry(id, 1, &key_pair, manager.get_proof_system());
            manager.proof_store.add_entry(&entry, &admin).await.unwrap();
        }

        // Setup admin chain
        let mut current_admin = admin.clone();
        let mut entries = Vec::new();

        for i in 0..5 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let entry = create_test_entry(
                id,
                current_admin.policy_generation,
                &key_pair,
                manager.get_proof_system(),
            );
            entries.push(entry);
        }

        // Process succession chain
        for gen in 2..=4 {
            let succession = create_test_succession(
                current_admin.active_keys,
                current_admin.active_keys,
                gen,
                entries.iter().map(|e| e.id).collect(),
                &key_pair,
                manager.get_proof_system(),
            );

            manager
                .process_succession(&succession, &current_admin)
                .await
                .unwrap();

            current_admin = AdminKeySet {
                active_keys: succession.new_keys,
                policy_generation: succession.generation,
                last_rotation: succession.timestamp,
            };
        }

        let results = manager.validate_across_chain(&entries, 1, 4).await.unwrap();
        assert_eq!(results.len(), entries.len());
        assert!(results.iter().all(|&r| r));
    }

    #[tokio::test]
    async fn test_invalid_succession() {
        let (manager, key_pair, admin) = setup_test_succession().await;

        let invalid_succession = create_test_succession(
            admin.active_keys,
            admin.active_keys,
            admin.policy_generation + 2, // Invalid generation gap
            vec![],
            &key_pair,
            manager.get_proof_system(),
        );

        let result = manager
            .process_succession(&invalid_succession, &admin)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("succession"));
    }

    #[tokio::test]
    async fn test_chain_caching() {
        let (manager, key_pair, admin) = setup_test_succession().await;

        let entry = create_test_entry([1u8; 32], 1, &key_pair, manager.get_proof_system());
        manager.proof_store.add_entry(&entry, &admin).await.unwrap();

        let succession = create_test_succession(
            admin.active_keys,
            admin.active_keys,
            2,
            vec![entry.id],
            &key_pair,
            manager.get_proof_system(),
        );

        manager
            .process_succession(&succession, &admin)
            .await
            .unwrap();

        let results = manager.validate_across_chain(&[entry], 1, 2).await.unwrap();
        assert!(results[0]);

        assert!(manager.chain_cache.contains_key(&2));
        let cached_chain = manager.chain_cache.get(&2).unwrap();
        assert_eq!(cached_chain.start_generation, 1);
        assert_eq!(cached_chain.end_generation, 2);
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let (manager, key_pair, admin) = setup_test_succession().await;

        let entry_count = 100;
        let mut entries = Vec::new();
        let mut entry_ids = Vec::new();

        // Create and store initial entries
        for i in 0..entry_count {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let entry = create_test_entry(id, 1, &key_pair, manager.get_proof_system());
            manager.proof_store.add_entry(&entry, &admin).await.unwrap();
            entry_ids.push(entry.id);
            entries.push(entry);
        }

        let succession = create_test_succession(
            admin.active_keys,
            admin.active_keys,
            2,
            entry_ids,
            &key_pair,
            manager.get_proof_system(),
        );

        manager
            .process_succession(&succession, &admin)
            .await
            .unwrap();

        let results = manager.validate_across_chain(&entries, 1, 2).await.unwrap();
        assert_eq!(results.len(), entry_count);
        assert!(results.iter().all(|&r| r));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let clock = Arc::new(MockClock {
            now: AtomicU64::new(0),
        });

        let temp_dir = tempdir().unwrap();
        let db = Arc::new(Database::create(temp_dir.path().join("test.db")).unwrap());
        let rate_limiter = Arc::new(RateLimit::with_clock(
            Duration::from_millis(100),
            3,
            clock.clone(),
        ));
        let proof_system = Arc::new(ProofSystem::new());

        // Initialize database tables and policies
        let write_txn = db.begin_write().unwrap();
        write_txn.open_table(SUCCESSIONS).unwrap();
        write_txn.open_table(ADMIN_STATE).unwrap();
        write_txn.open_table(ENTRIES).unwrap();
        write_txn.open_table(PROOFS).unwrap();
        write_txn.commit().unwrap();

        let key_pair = SigningKeyPair::new(SigningKey::from_bytes(&[1u8; 32]));
        let recovery_key = SigningKeyPair::new(SigningKey::from_bytes(&[2u8; 32]));

        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: time::OffsetDateTime::now_utc(),
        };

        // Initialize admin state and policy
        let write_txn = db.begin_write().unwrap();
        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).unwrap();

            // Set up initial policy
            let initial_policy = AdminPolicy {
                administrators: admin.active_keys,
                policy_generation: admin.policy_generation,
                succession_requirements: SuccessionPolicy {
                    min_key_age: time::Duration::hours(24),
                    required_signatures: 2,
                },
                recovery_keys: Some([recovery_key.verifying_key; 2]),
            };

            let policy_bytes = serde_json::to_vec(&initial_policy).unwrap();
            admin_table
                .insert(b"admin_policy".as_slice(), policy_bytes.as_slice())
                .unwrap();

            // Set up admin state
            let admin_bytes = serde_json::to_vec(&admin).unwrap();
            admin_table
                .insert(ADMIN_KEY, admin_bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        let proof_store = Arc::new(
            ProofStore::new(
                Arc::clone(&db),
                Arc::clone(&rate_limiter),
                Arc::clone(&proof_system),
                Duration::from_secs(30),
            )
            .unwrap(),
        );

        let manager = SuccessionManager::new(
            Arc::clone(&db),
            Arc::clone(&rate_limiter),
            Arc::clone(&proof_system),
            Arc::clone(&proof_store),
            Duration::from_secs(30),
        )
        .unwrap();

        let entry = create_test_entry([1u8; 32], 1, &key_pair, manager.get_proof_system());
        manager.proof_store.add_entry(&entry, &admin).await.unwrap();

        let succession = create_test_succession(
            admin.active_keys,
            admin.active_keys,
            2,
            vec![entry.id],
            &key_pair,
            manager.get_proof_system(),
        );

        // Rate limit testing sequence
        assert!(manager
            .process_succession(&succession, &admin)
            .await
            .is_ok());
        assert!(manager
            .validate_across_chain(&[entry.clone()], 1, 2)
            .await
            .is_ok());

        clock.advance(Duration::from_millis(50));
        let err = manager
            .validate_across_chain(&[entry.clone()], 1, 2)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Rate limit exceeded");

        clock.advance(Duration::from_millis(100));
        assert!(manager.validate_across_chain(&[entry], 1, 2).await.is_ok());
    }

    #[tokio::test]
    async fn test_normal_succession() {
        let (manager, key_pair, admin) = setup_test_succession().await;
        let entry = create_test_entry([1u8; 32], 1, &key_pair, manager.get_proof_system());
        manager.proof_store.add_entry(&entry, &admin).await.unwrap();

        let succession = create_test_succession(
            admin.active_keys,
            admin.active_keys,
            2,
            vec![entry.id],
            &key_pair,
            manager.get_proof_system(),
        );

        assert!(manager
            .process_succession(&succession, &admin)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_recovery_succession() {
        let (manager, admin_key_pair, admin) = setup_test_succession().await;

        // Create recovery keys
        let recovery_key = SigningKeyPair::new(SigningKey::from_bytes(&[2u8; 32]));

        // Set up admin policy with recovery keys
        let policy = AdminPolicy {
            administrators: admin.active_keys,
            policy_generation: admin.policy_generation,
            succession_requirements: SuccessionPolicy {
                min_key_age: time::Duration::hours(24),
                required_signatures: 2,
            },
            recovery_keys: Some([recovery_key.verifying_key; 2]),
        };

        // Update admin policy in storage
        let write_txn = manager.db.begin_write().unwrap();
        let policy_bytes = serde_json::to_vec(&policy).unwrap();
        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).unwrap();
            admin_table
                .insert(b"admin_policy".as_slice(), policy_bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        // Create test entry
        let entry = create_test_entry([1u8; 32], 1, &admin_key_pair, manager.get_proof_system());
        manager.proof_store.add_entry(&entry, &admin).await.unwrap();

        // Create recovery succession record
        let mut succession = create_test_succession(
            admin.active_keys,
            [recovery_key.verifying_key; 2],
            admin.policy_generation + 1,
            vec![entry.id],
            &recovery_key,
            manager.get_proof_system(),
        );

        // Add recovery metadata
        succession.request_metadata = Some(json!({
            "is_recovery": true,
            "reason": "Emergency key rotation"
        }));

        assert!(manager
            .process_succession(&succession, &admin)
            .await
            .is_ok());

        // Verify new admin state
        let new_admin = manager.get_current_admin().unwrap();
        assert_eq!(new_admin.active_keys, succession.new_keys);
        assert_eq!(new_admin.policy_generation, succession.generation);
    }

    #[tokio::test]
    async fn test_unauthorized_recovery() {
        let (manager, admin_key_pair, admin) = setup_test_succession().await;

        // Create unauthorized keys
        let unauthorized_key = SigningKeyPair::new(SigningKey::from_bytes(&[3u8; 32]));

        let entry = create_test_entry([1u8; 32], 1, &admin_key_pair, manager.get_proof_system());
        manager.proof_store.add_entry(&entry, &admin).await.unwrap();

        // Create unauthorized succession record
        let mut succession = create_test_succession(
            admin.active_keys,
            [unauthorized_key.verifying_key; 2],
            admin.policy_generation + 1,
            vec![entry.id],
            &unauthorized_key,
            manager.get_proof_system(),
        );

        succession.request_metadata = Some(json!({
            "is_recovery": true,
            "reason": "Unauthorized attempt"
        }));

        assert!(manager
            .process_succession(&succession, &admin)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_policy_preservation() {
        let (manager, admin_key_pair, admin) = setup_test_succession().await;

        // Create recovery keys
        let recovery_key = SigningKeyPair::new(SigningKey::from_bytes(&[2u8; 32]));
        let initial_policy = AdminPolicy {
            administrators: admin.active_keys,
            policy_generation: admin.policy_generation,
            succession_requirements: SuccessionPolicy {
                min_key_age: time::Duration::hours(24),
                required_signatures: 2,
            },
            recovery_keys: Some([recovery_key.verifying_key; 2]),
        };

        // Set initial policy
        let write_txn = manager.db.begin_write().unwrap();
        let policy_bytes = serde_json::to_vec(&initial_policy).unwrap();
        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).unwrap();
            admin_table
                .insert(b"admin_policy".as_slice(), policy_bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        // Perform normal succession
        let new_admin_key = SigningKeyPair::new(SigningKey::from_bytes(&[3u8; 32]));
        let succession = create_test_succession(
            admin.active_keys,
            [new_admin_key.verifying_key; 2],
            admin.policy_generation + 1,
            vec![],
            &admin_key_pair,
            manager.get_proof_system(),
        );

        manager
            .process_succession(&succession, &admin)
            .await
            .unwrap();

        // Verify policy state
        let updated_policy = manager.get_current_admin_policy().unwrap();
        assert_eq!(updated_policy.administrators, succession.new_keys);
        assert_eq!(updated_policy.policy_generation, succession.generation);
        assert_eq!(
            updated_policy.recovery_keys.unwrap(),
            initial_policy.recovery_keys.unwrap()
        );
    }
}
