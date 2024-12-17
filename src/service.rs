use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{oneshot, watch};

use crate::errors::Result;
use crate::storage::Storage;
use crate::types::{AdminKeySet, EntryId, ServiceDefinition, ServiceId};

pub struct ServiceValidator {
    storage: Arc<Storage>,
    service_def: ServiceDefinition,
    cache: DashMap<EntryId, CacheEntry>,
    admin_state_tx: watch::Sender<AdminKeySet>,
    admin_state: watch::Receiver<AdminKeySet>,
    sync_interval: Duration,
    _shutdown: oneshot::Sender<()>,
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
        let (tx, rx) = watch::channel(admin_state);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let tx_clone = tx.clone();
        let storage_clone = Arc::clone(&storage);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(sync_interval) => {
                        if let Ok(new_admin) = storage_clone.get_current_admin() {
                            if tx_clone.send(new_admin).is_err() {
                                break;
                            }
                        }
                    }
                    _ = &mut shutdown_rx => break
                }
            }
        });
        Ok(Self {
            storage,
            service_def,
            cache: DashMap::new(),
            admin_state_tx: tx,
            admin_state: rx,
            sync_interval,
            _shutdown: shutdown_tx,
        })
    }

    pub fn service_id(&self) -> &ServiceId {
        &self.service_def.id
    }

    pub async fn validate_access(&self, entry_id: &EntryId) -> Result<bool> {
        if let Some(cached) = self.check_cache(entry_id)? {
            return Ok(cached);
        }

        let admin = self.admin_state.borrow().clone();
        let result = match self.storage.get_entry(&entry_id.0)? {
            Some(entry) if entry.service_id == self.service_def.id => {
                self.storage.validate_entry(&entry_id.0, &admin).await?
            }
            _ => false,
        };

        self.update_cache(entry_id, result, admin.policy_generation)?;
        Ok(result)
    }

    pub async fn sync_admin_state(&self) -> Result<()> {
        let new_admin = self.storage.get_current_admin()?;
        if new_admin.policy_generation > self.admin_state.borrow().policy_generation {
            self.cache
                .retain(|_, entry| entry.policy_generation >= new_admin.policy_generation);
            let _ = self.admin_state_tx.send(new_admin);
        }
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
        if let Some(entry) = self.cache.get(entry_id) {
            let now = time::OffsetDateTime::now_utc();
            let interval = time::Duration::seconds(self.sync_interval.as_secs() as i64);

            if (now - entry.timestamp) < interval {
                return Ok(Some(entry.valid));
            }
        }
        Ok(None)
    }

    fn update_cache(&self, entry_id: &EntryId, valid: bool, generation: u32) -> Result<()> {
        self.cache.insert(
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
    use time::OffsetDateTime;

    async fn setup_test_validator() -> (ServiceValidator, SigningKeyPair, ACLEntry) {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let mut storage = Arc::new(Storage::new(db_path, None).unwrap());

        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let key_pair = SigningKeyPair::new(SigningKey::from_bytes(&seed));

        let service_id = ServiceId("test".into());

        let fixed_time = OffsetDateTime::from_unix_timestamp(1640995200).unwrap();

        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: fixed_time,
        };

        Arc::get_mut(&mut storage)
            .unwrap()
            .set_admin_state(&admin)
            .await
            .unwrap();

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

        let metadata = EntryMetadata {
            created_at: fixed_time - time::Duration::hours(2),
            expires_at: None,
            version: 1,
            service_specific: serde_json::Value::Null,
        };

        let mut entry = ACLEntry {
            id: EntryId::new([1; 32]),
            service_id: service_id.clone(),
            policy_generation: 1,
            metadata,
            signature: crate::types::SerializableSignature(ed25519_dalek::Signature::from_bytes(
                &[0; 64],
            )),
        };

        entry.signature = storage
            .proof_system()
            .sign_entry(&entry, &key_pair)
            .unwrap();

        let _ = Arc::get_mut(&mut storage)
            .unwrap()
            .add_entry(&entry, &admin)
            .await;

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
        let admin = validator.admin_state.borrow().clone();
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
