use dashmap::DashMap;
use rayon::prelude::*;
use redb::Database;
use std::sync::Arc;
use tokio::time::timeout;

use crate::{
    crypto::ProofSystem,
    errors::{Error, Result},
    types::{ACLEntry, AdminKeySet, EntryId, ValidationProof},
};

use super::{rate_limit::RateLimit, ENTRIES, PROOFS};

const DEFAULT_BATCH_SIZE: usize = 64;
const MAX_BATCH_SIZE: usize = 1024;
const CACHE_TTL: time::Duration = time::Duration::minutes(5);

#[derive(Clone)]
struct CachedProof {
    proof: ValidationProof,
    generation: u32,
    timestamp: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct ProofStore {
    db: Arc<Database>,
    rate_limiter: Arc<RateLimit>,
    proof_system: Arc<ProofSystem>,
    proof_cache: DashMap<EntryId, CachedProof>,
    operation_timeout: std::time::Duration,
}

impl ProofStore {
    pub fn new(
        db: Arc<Database>,
        rate_limiter: Arc<RateLimit>,
        proof_system: Arc<ProofSystem>,
        timeout: std::time::Duration,
    ) -> Result<Self> {
        Ok(Self {
            db,
            rate_limiter,
            proof_system,
            proof_cache: DashMap::new(),
            operation_timeout: timeout,
        })
    }

    pub async fn add_entry(&self, entry: &ACLEntry, admin: &AdminKeySet) -> Result<()> {
        self.rate_limiter.check()?;

        timeout(self.operation_timeout, async {
            let write_txn = self.db.begin_write().map_err(|e| {
                Error::database_error(
                    "Transaction failed",
                    format!("Failed to begin transaction: {}", e),
                )
            })?;

            let proof = self
                .proof_system
                .generate_validation_proof(entry, admin, None)?;

            let entry_bytes = serde_json::to_vec(entry).map_err(|e| {
                Error::database_error(
                    "Serialization failed",
                    format!("Failed to serialize entry: {}", e),
                )
            })?;

            let proof_bytes = serde_json::to_vec(&proof).map_err(|e| {
                Error::database_error(
                    "Serialization failed",
                    format!("Failed to serialize proof: {}", e),
                )
            })?;

            {
                let mut entries = write_txn.open_table(ENTRIES).map_err(|e| {
                    Error::database_error("Failed to open entries table", e.to_string())
                })?;

                let mut proofs = write_txn.open_table(PROOFS).map_err(|e| {
                    Error::database_error("Failed to open proofs table", e.to_string())
                })?;

                entries
                    .insert(entry.id.0.as_ref(), entry_bytes.as_slice())
                    .map_err(|e| Error::database_error("Failed to insert entry", e.to_string()))?;

                proofs
                    .insert(entry.id.0.as_ref(), proof_bytes.as_slice())
                    .map_err(|e| Error::database_error("Failed to insert proof", e.to_string()))?;
            }

            self.proof_cache.insert(
                entry.id,
                CachedProof {
                    proof,
                    generation: admin.policy_generation,
                    timestamp: time::OffsetDateTime::now_utc(),
                },
            );

            write_txn.commit().map_err(|e| {
                Error::database_error("Failed to commit transaction", e.to_string())
            })?;

            Ok(())
        })
        .await
        .map_err(|_| {
            Error::database_error("Operation timeout", "Add entry operation timed out")
        })??;

        Ok(())
    }

    fn verify_with_admin(
        &self,
        entry: &ACLEntry,
        proof: &ValidationProof,
        admin: &AdminKeySet,
    ) -> Result<bool> {
        if entry.policy_generation != admin.policy_generation {
            return Ok(false);
        }

        if !self.proof_system.verify_entry_signature(entry, admin)? {
            return Ok(false);
        }

        self.proof_system
            .verify_validation_proof(proof, entry, admin)
    }

    pub async fn validate_entry(&self, entry_id: &[u8], admin: &AdminKeySet) -> Result<bool> {
        self.rate_limiter.check()?;

        timeout(self.operation_timeout, async {
            let mut id_array = [0u8; 32];
            id_array.copy_from_slice(&entry_id[..32]);
            let entry_id = EntryId::new(id_array);

            let entry = match self.load_entry(&entry_id)? {
                Some(entry) => entry,
                None => return Ok(false),
            };

            if entry.policy_generation != admin.policy_generation {
                return Ok(false);
            }

            if let Some(cached) = self.get_valid_cached_proof_by_id(&entry_id, admin) {
                return self
                    .proof_system
                    .verify_validation_proof(&cached.proof, &entry, admin);
            }

            match self.load_proof(&entry_id)? {
                Some(proof) => {
                    let result = self
                        .proof_system
                        .verify_validation_proof(&proof, &entry, admin)?;

                    if result {
                        self.proof_cache.insert(
                            entry_id,
                            CachedProof {
                                proof,
                                generation: admin.policy_generation,
                                timestamp: time::OffsetDateTime::now_utc(),
                            },
                        );
                    }

                    Ok(result)
                }
                None => Ok(false),
            }
        })
        .await
        .map_err(|_| Error::database_error("Operation timeout", "Validation timed out"))?
    }

    pub async fn batch_validate(
        &self,
        entry_ids: &[EntryId],
        admin: &AdminKeySet,
    ) -> Result<Vec<bool>> {
        if entry_ids.is_empty() {
            return Ok(vec![]);
        }

        if entry_ids.len() > MAX_BATCH_SIZE {
            return Err(Error::validation_failed(
                "Batch size exceeded",
                format!("Maximum batch size is {}", MAX_BATCH_SIZE),
            ));
        }

        let batch_size = calculate_optimal_batch_size(entry_ids.len());

        let results = entry_ids
            .chunks(batch_size)
            .map(|chunk| {
                chunk
                    .par_iter()
                    .map(|id| {
                        if let Some(cached) = self.get_valid_cached_proof_by_id(id, admin) {
                            if let Ok(Some(entry)) = self.load_entry(id) {
                                return self.verify_with_admin(&entry, &cached.proof, admin);
                            }
                        }

                        match self.load_entry(id) {
                            Ok(Some(entry)) => {
                                if let Ok(Some(proof)) = self.load_proof(id) {
                                    self.verify_with_admin(&entry, &proof, admin)
                                } else {
                                    Ok(false)
                                }
                            }
                            _ => Ok(false),
                        }
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(results)
    }

    fn get_valid_cached_proof_by_id(
        &self,
        entry_id: &EntryId,
        admin: &AdminKeySet,
    ) -> Option<CachedProof> {
        let now = time::OffsetDateTime::now_utc();

        if let Some(cached) = self.proof_cache.get(entry_id) {
            if cached.generation == admin.policy_generation && (now - cached.timestamp) < CACHE_TTL
            {
                return Some(cached.clone());
            }
        }
        None
    }

    fn load_entry(&self, entry_id: &EntryId) -> Result<Option<ACLEntry>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            Error::database_error(
                "Transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let entries = read_txn
            .open_table(ENTRIES)
            .map_err(|e| Error::database_error("Failed to open entries table", e.to_string()))?;

        if let Some(bytes) = entries
            .get(entry_id.0.as_ref())
            .map_err(|e| Error::database_error("Failed to read entry", e.to_string()))?
        {
            let entry = serde_json::from_slice(bytes.value())
                .map_err(|e| Error::database_error("Failed to deserialize entry", e.to_string()))?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn load_proof(&self, entry_id: &EntryId) -> Result<Option<ValidationProof>> {
        let read_txn = self.db.begin_read().map_err(|e: redb::TransactionError| {
            Error::database_error(
                "Transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let proofs = read_txn
            .open_table(PROOFS)
            .map_err(|e| Error::database_error("Failed to open proofs table", e.to_string()))?;

        if let Some(bytes) = proofs
            .get(entry_id.0.as_ref())
            .map_err(|e| Error::database_error("Failed to read proof", e.to_string()))?
        {
            let proof = serde_json::from_slice(bytes.value())
                .map_err(|e| Error::database_error("Failed to deserialize proof", e.to_string()))?;
            Ok(Some(proof))
        } else {
            Ok(None)
        }
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
    use std::time::Duration;

    use super::*;
    use crate::types::{EntryMetadata, SerializableSignature, ServiceId, SigningKeyPair};
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    async fn setup_test_store() -> (ProofStore, SigningKeyPair, AdminKeySet) {
        let temp_dir = tempdir().unwrap();
        let db = Arc::new(Database::create(temp_dir.path().join("test.db")).unwrap());
        let rate_limiter = Arc::new(RateLimit::new(std::time::Duration::from_secs(1), 1000));
        let proof_system = Arc::new(ProofSystem::new());

        let store = ProofStore::new(
            Arc::clone(&db),
            Arc::clone(&rate_limiter),
            Arc::clone(&proof_system),
            std::time::Duration::from_secs(30),
        )
        .unwrap();

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let key_pair = SigningKeyPair::new(signing_key);

        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: time::OffsetDateTime::now_utc(),
        };

        (store, key_pair, admin)
    }

    fn create_test_entry(key_pair: &mut SigningKeyPair, id: [u8; 32]) -> ACLEntry {
        let metadata = EntryMetadata {
            created_at: time::OffsetDateTime::now_utc(),
            expires_at: None,
            version: 1,
            service_specific: serde_json::Value::Null,
        };

        let mut entry = ACLEntry {
            id: EntryId::new(id),
            service_id: ServiceId("test".into()),
            policy_generation: 1,
            metadata,
            signature: SerializableSignature(ed25519_dalek::Signature::from_bytes(&[0; 64])),
        };

        let proof_system = ProofSystem::new();
        entry.signature = proof_system.sign_entry(&entry, key_pair).unwrap();
        entry
    }

    #[tokio::test]
    async fn test_store_and_validate() {
        let (store, mut key_pair, admin) = setup_test_store().await;
        let entry = create_test_entry(&mut key_pair, [1u8; 32]);

        // Sign entry with current admin key
        let message = store.proof_system.create_entry_message(&entry);
        let signature = key_pair.sign(&message);
        let mut signed_entry = entry;
        signed_entry.signature = signature;

        store.add_entry(&signed_entry, &admin).await.unwrap();
        assert!(store
            .validate_entry(&signed_entry.id.0, &admin)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_batch_validation() {
        let (store, mut key_pair, admin) = setup_test_store().await;
        let mut entries = Vec::new();
        let mut entry_ids = Vec::new();

        for i in 0..10 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let entry = create_test_entry(&mut key_pair, id);

            // Sign each entry properly
            let message = store.proof_system.create_entry_message(&entry);
            let signature = key_pair.sign(&message);
            let mut signed_entry = entry;
            signed_entry.signature = signature;

            store.add_entry(&signed_entry, &admin).await.unwrap();
            entry_ids.push(signed_entry.id);
            entries.push(signed_entry);
        }

        let results = store.batch_validate(&entry_ids, &admin).await.unwrap();
        assert_eq!(results.len(), entries.len());
        assert!(results.iter().all(|&r| r));
    }

    #[tokio::test]
    async fn test_cache_behavior() {
        let (store, mut key_pair, admin) = setup_test_store().await;
        let entry = create_test_entry(&mut key_pair, [1u8; 32]);

        store.add_entry(&entry, &admin).await.unwrap();
        assert!(store.validate_entry(&entry.id.0, &admin).await.unwrap());
        assert!(store.proof_cache.contains_key(&entry.id));

        if let Some(mut cached) = store.proof_cache.get_mut(&entry.id) {
            cached.timestamp =
                time::OffsetDateTime::now_utc() - CACHE_TTL - time::Duration::minutes(1);
        }

        let now = time::OffsetDateTime::now_utc();
        store
            .proof_cache
            .retain(|_, cached| (now - cached.timestamp) < CACHE_TTL);

        assert!(!store.proof_cache.contains_key(&entry.id));

        // Should still validate from storage
        assert!(store.validate_entry(&entry.id.0, &admin).await.unwrap());
    }

    #[tokio::test]
    async fn test_invalid_admin_state() {
        let (store, mut key_pair, mut admin) = setup_test_store().await;
        let entry = create_test_entry(&mut key_pair, [1u8; 32]);

        // Store with original admin state
        store.add_entry(&entry, &admin).await.unwrap();
        assert!(store.validate_entry(&entry.id.0, &admin).await.unwrap());

        // Modify admin state
        admin.policy_generation += 1;
        assert!(!store.validate_entry(&entry.id.0, &admin).await.unwrap());
    }

    #[tokio::test]
    async fn test_batch_size_limits() {
        let (store, mut key_pair, admin) = setup_test_store().await;

        let test_size = 100;
        let mut entries = Vec::with_capacity(test_size);
        let mut entry_ids = Vec::with_capacity(MAX_BATCH_SIZE + 10);

        // Create entries in memory first
        for i in 0..test_size {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let entry = create_test_entry(&mut key_pair, id);
            entries.push(entry);
        }

        // Store entries in a single transaction
        let write_txn = store.db.begin_write().unwrap();
        {
            let mut db_entries = write_txn.open_table(ENTRIES).unwrap();
            let mut db_proofs = write_txn.open_table(PROOFS).unwrap();

            for entry in entries {
                let proof = store
                    .proof_system
                    .generate_validation_proof(&entry, &admin, None)
                    .unwrap();
                let entry_bytes = serde_json::to_vec(&entry).unwrap();
                let proof_bytes = serde_json::to_vec(&proof).unwrap();

                db_entries
                    .insert(entry.id.0.as_ref(), entry_bytes.as_slice())
                    .unwrap();
                db_proofs
                    .insert(entry.id.0.as_ref(), proof_bytes.as_slice())
                    .unwrap();
                entry_ids.push(entry.id);
            }
        }
        write_txn.commit().unwrap();

        // Pad entry_ids to test limit
        entry_ids.resize(MAX_BATCH_SIZE + 10, entry_ids[0]);

        // Test batch size limit
        assert!(store.batch_validate(&entry_ids, &admin).await.is_err());

        // Test smaller batch
        let small_batch = &entry_ids[0..test_size];
        let results = store.batch_validate(small_batch, &admin).await.unwrap();
        assert!(results.iter().all(|&r| r));
    }

    #[tokio::test]
    async fn test_parallel_validation_performance() {
        let (store, mut key_pair, admin) = setup_test_store().await;
        let entry_count = 100;
        let mut entries = Vec::new();
        let mut entry_ids = Vec::new();

        // Create and store entries
        for i in 0..entry_count {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let entry = create_test_entry(&mut key_pair, id);
            store.add_entry(&entry, &admin).await.unwrap();
            entry_ids.push(entry.id);
            entries.push(entry);
        }

        // Measure time for parallel validation
        let start = std::time::Instant::now();
        let parallel_results = store.batch_validate(&entry_ids, &admin).await.unwrap();
        let parallel_duration = start.elapsed();

        // Measure time for sequential validation
        let start = std::time::Instant::now();
        let mut sequential_results = Vec::new();
        for entry_id in &entry_ids {
            sequential_results.push(store.validate_entry(&entry_id.0, &admin).await.unwrap());
        }
        let sequential_duration = start.elapsed();

        // Verify results are the same
        assert_eq!(parallel_results, sequential_results);
        assert!(parallel_results.iter().all(|&r| r));

        // Parallel should be significantly faster
        assert!(parallel_duration < sequential_duration / 2);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let temp_dir = tempdir().unwrap();
        let db = Arc::new(Database::create(temp_dir.path().join("test.db")).unwrap());

        let rate_limiter = Arc::new(RateLimit::new(Duration::from_millis(100), 2));
        let proof_system = Arc::new(ProofSystem::new());

        let store = ProofStore::new(
            Arc::clone(&db),
            Arc::clone(&rate_limiter),
            Arc::clone(&proof_system),
            std::time::Duration::from_secs(30),
        )
        .unwrap();

        let mut key_pair = SigningKeyPair::new(SigningKey::from_bytes(&[1u8; 32]));
        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: time::OffsetDateTime::now_utc(),
        };

        let entry = create_test_entry(&mut key_pair, [1u8; 32]);

        // First two operations should succeed
        assert!(store.add_entry(&entry, &admin).await.is_ok());
        assert!(store.validate_entry(&entry.id.0, &admin).await.is_ok());

        // Third operation should fail due to rate limiting
        assert!(store.validate_entry(&entry.id.0, &admin).await.is_err());

        // Wait for rate limit window to expire - use full second
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Operation should succeed again
        assert!(store.validate_entry(&entry.id.0, &admin).await.is_ok());
    }
}
