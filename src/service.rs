use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::RwLock as AsyncRwLock;

use crate::errors::{Error, Result};
use crate::storage::Storage;
use crate::types::{AdminKeySet, EntryId, ServiceDefinition, ServiceId};

pub struct ServiceValidator {
    storage: Arc<Storage>,
    service_def: ServiceDefinition,
    cache: RwLock<HashMap<EntryId, CacheEntry>>,
    admin_state: AsyncRwLock<AdminKeySet>,
    sync_interval: Duration,
}

struct CacheEntry {
    valid: bool,
    policy_generation: u32,
    timestamp: time::OffsetDateTime,
}

impl ServiceValidator {
    pub fn new(
        storage: Arc<Storage>,
        service_def: ServiceDefinition,
        sync_interval: Duration,
    ) -> Result<Self> {
        let admin_state = storage.get_current_admin()?;
        Ok(Self {
            storage,
            service_def,
            cache: RwLock::new(HashMap::new()),
            admin_state: AsyncRwLock::new(admin_state),
            sync_interval,
        })
    }

    pub fn service_id(&self) -> &ServiceId {
        &self.service_def.id
    }

    pub async fn validate_access(&self, entry_id: &EntryId) -> Result<bool> {
        // First check cache
        if let Some(cached) = self.check_cache(entry_id)? {
            return Ok(cached);
        }

        // Get current admin state for validation
        let admin = self.admin_state.read().await;

        let valid = self.storage.validate_entry(&entry_id.0, &admin)?;

        // If valid, verify service ID matches
        if valid {
            if let Some(entry) = self.storage.get_entry(&entry_id.0)? {
                if entry.service_id != self.service_def.id {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        // Update cache with validation result
        self.update_cache(entry_id, valid, admin.policy_generation)?;

        Ok(valid)
    }

    pub async fn sync_admin_state(&self) -> Result<()> {
        let new_admin = self.storage.get_current_admin()?;
        let mut admin = self.admin_state.write().await;

        // If admin state has changed, invalidate cache entries from old generations
        if new_admin.policy_generation > admin.policy_generation {
            let mut cache = self
                .cache
                .write()
                .map_err(|_| Error::crypto_error("Failed to acquire cache lock"))?;

            cache.retain(|_, entry| entry.policy_generation >= new_admin.policy_generation);
        }

        *admin = new_admin;
        Ok(())
    }

    pub async fn verify_service_access(&self, entry_id: &EntryId) -> Result<bool> {
        if let Some(entry) = self.storage.get_entry(&entry_id.0)? {
            if entry.service_id != self.service_def.id {
                return Ok(false);
            }

            if !self.validate_access(entry_id).await? {
                return Ok(false);
            }

            if let Some(expires_at) = entry.metadata.expires_at {
                if expires_at < time::OffsetDateTime::now_utc() {
                    return Ok(false);
                }
            }

            let policy_age = time::OffsetDateTime::now_utc() - entry.metadata.created_at;
            if policy_age < self.service_def.min_policy_age {
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn get_service_definition(&self) -> &ServiceDefinition {
        &self.service_def
    }

    fn check_cache(&self, entry_id: &EntryId) -> Result<Option<bool>> {
        let cache = self
            .cache
            .read()
            .map_err(|_| Error::crypto_error("Failed to acquire cache lock"))?;

        if let Some(entry) = cache.get(entry_id) {
            // Check if cache entry is still valid based on time and policy generation
            let now = time::OffsetDateTime::now_utc();
            if (now - entry.timestamp) < self.sync_interval {
                return Ok(Some(entry.valid));
            }
        }

        Ok(None)
    }

    fn update_cache(&self, entry_id: &EntryId, valid: bool, generation: u32) -> Result<()> {
        let mut cache = self
            .cache
            .write()
            .map_err(|_| Error::crypto_error("Failed to acquire cache lock"))?;

        cache.insert(
            *entry_id,
            CacheEntry {
                valid,
                policy_generation: generation,
                timestamp: time::OffsetDateTime::now_utc(),
            },
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ACLEntry, EntryMetadata, SigningKeyPair};
    use ed25519_dalek::SigningKey;
    use rand::{rngs::OsRng, RngCore};
    use tempfile::tempdir;

    async fn setup_test_validator() -> (ServiceValidator, SigningKeyPair, ACLEntry) {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::new(db_path).unwrap());

        // Generate test keys
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let key_pair = SigningKeyPair::new(SigningKey::from_bytes(&seed));

        let service_id = ServiceId("test".into());
        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: time::OffsetDateTime::now_utc() - time::Duration::hours(2),
        };

        // Initialize admin state
        storage.set_admin_state(&admin).unwrap();

        let service_def = ServiceDefinition {
            id: service_id.clone(),
            name: "Test Service".into(),
            requirements: crate::types::ServiceRequirements {
                auth_type: crate::types::AuthenticationType::SingleSignature,
                required_proofs: vec![],
                minimum_signatures: 1,
            },
            admin_policy: crate::types::AdminPolicy {
                administrators: admin.active_keys,
                policy_generation: admin.policy_generation,
                succession_requirements: crate::types::SuccessionPolicy {
                    min_key_age: time::Duration::days(1),
                    required_signatures: 2,
                },
                recovery_keys: None,
            },
            min_policy_age: time::Duration::hours(1),
        };

        let creation_time = time::OffsetDateTime::now_utc() - time::Duration::hours(2);
        let entry = ACLEntry {
            id: EntryId::new([1; 32]),
            service_id: service_id.clone(),
            policy_generation: 1,
            metadata: EntryMetadata {
                created_at: creation_time,
                expires_at: None,
                version: 1,
                service_specific: serde_json::Value::Null,
            },
            signature: storage
                .proof_system()
                .sign_entry(
                    &ACLEntry {
                        id: EntryId::new([1; 32]),
                        service_id,
                        policy_generation: 1,
                        metadata: EntryMetadata {
                            created_at: time::OffsetDateTime::now_utc(),
                            expires_at: None,
                            version: 1,
                            service_specific: serde_json::Value::Null,
                        },
                        signature: crate::types::SerializableSignature(
                            ed25519_dalek::Signature::from_bytes(&[0; 64]),
                        ),
                    },
                    &key_pair,
                )
                .unwrap(),
        };

        storage.add_entry(&entry, &admin).unwrap();

        let validator =
            ServiceValidator::new(storage, service_def, Duration::from_secs(300)).unwrap();

        (validator, key_pair, entry)
    }

    #[tokio::test]
    async fn test_validation() {
        let (validator, _key_pair, entry) = setup_test_validator().await;
        assert!(validator.validate_access(&entry.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_caching() {
        let (validator, _key_pair, entry) = setup_test_validator().await;

        // First validation should cache the result
        assert!(validator.validate_access(&entry.id).await.unwrap());

        // Second validation should use cache
        assert!(validator.check_cache(&entry.id).unwrap().unwrap());
    }

    #[tokio::test]
    async fn test_sync() {
        let (validator, _key_pair, _entry) = setup_test_validator().await;

        // Should sync without error
        validator.sync_admin_state().await.unwrap();

        // Admin state should match storage
        let admin = validator.admin_state.read().await;
        let storage_admin = validator.storage.get_current_admin().unwrap();
        assert_eq!(admin.policy_generation, storage_admin.policy_generation);
    }

    #[tokio::test]
    async fn test_service_verification() {
        let (validator, _key_pair, entry) = setup_test_validator().await;
        assert!(validator.verify_service_access(&entry.id).await.unwrap());

        // Test with wrong service ID
        let wrong_service = ServiceDefinition {
            id: ServiceId("wrong".into()),
            ..validator.service_def.clone()
        };

        let wrong_validator = ServiceValidator::new(
            Arc::clone(&validator.storage),
            wrong_service,
            Duration::from_secs(300),
        )
        .unwrap();

        assert!(!wrong_validator
            .verify_service_access(&entry.id)
            .await
            .unwrap());
    }
}
