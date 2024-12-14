use redb::{Database, TableDefinition};
use std::path::Path;

use crate::crypto::ProofSystem;
use crate::errors::{Error, Result};
use crate::types::{ACLEntry, AdminKeySet, SuccessionRecord, ValidationProof};

const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");
const PROOFS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("proofs");
const SUCCESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("successions");
const ADMIN_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("admin_state");

pub struct Storage {
    db: Database,
    proof_system: ProofSystem,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::create(path)
            .map_err(|e| Error::crypto_error(format!("Failed to create database: {}", e)))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::crypto_error(format!("Failed to begin transaction: {}", e)))?;

        write_txn
            .open_table(ENTRIES)
            .map_err(|e| Error::crypto_error(format!("Failed to create entries table: {}", e)))?;
        write_txn
            .open_table(PROOFS)
            .map_err(|e| Error::crypto_error(format!("Failed to create proofs table: {}", e)))?;
        write_txn.open_table(SUCCESSIONS).map_err(|e| {
            Error::crypto_error(format!("Failed to create successions table: {}", e))
        })?;
        write_txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::crypto_error(format!("Failed to create admin state table: {}", e))
        })?;

        write_txn
            .commit()
            .map_err(|e| Error::crypto_error(format!("Failed to commit transaction: {}", e)))?;

        Ok(Self {
            db,
            proof_system: ProofSystem::new(),
        })
    }

    pub fn add_entry(&self, entry: &ACLEntry, admin: &AdminKeySet) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::crypto_error(format!("Failed to begin transaction: {}", e)))?;

        let proof = self
            .proof_system
            .generate_validation_proof(entry, admin, None)?;

        let entry_bytes = serde_json::to_vec(&entry)
            .map_err(|e| Error::crypto_error(format!("Failed to serialize entry: {}", e)))?;
        let proof_bytes = serde_json::to_vec(&proof)
            .map_err(|e| Error::crypto_error(format!("Failed to serialize proof: {}", e)))?;

        {
            let mut entries_table = write_txn
                .open_table(ENTRIES)
                .map_err(|e| Error::crypto_error(format!("Failed to open entries table: {}", e)))?;
            let mut proofs_table = write_txn
                .open_table(PROOFS)
                .map_err(|e| Error::crypto_error(format!("Failed to open proofs table: {}", e)))?;

            entries_table
                .insert(entry.id.0.as_ref() as &[u8], entry_bytes.as_ref() as &[u8])
                .map_err(|e| Error::crypto_error(format!("Failed to insert entry: {}", e)))?;
            proofs_table
                .insert(entry.id.0.as_ref() as &[u8], proof_bytes.as_ref() as &[u8])
                .map_err(|e| Error::crypto_error(format!("Failed to insert proof: {}", e)))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::crypto_error(format!("Failed to commit transaction: {}", e)))
    }

    pub fn validate_entry(&self, entry_id: &[u8], admin: &AdminKeySet) -> Result<bool> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::crypto_error(format!("Failed to begin transaction: {}", e)))?;

        let entries_table = read_txn
            .open_table(ENTRIES)
            .map_err(|e| Error::crypto_error(format!("Failed to open entries table: {}", e)))?;
        let proofs_table = read_txn
            .open_table(PROOFS)
            .map_err(|e| Error::crypto_error(format!("Failed to open proofs table: {}", e)))?;

        let entry_bytes = match entries_table
            .get(entry_id)
            .map_err(|e| Error::crypto_error(format!("Failed to read entry: {}", e)))?
        {
            Some(bytes) => bytes,
            None => return Ok(false),
        };

        let proof_bytes = match proofs_table
            .get(entry_id)
            .map_err(|e| Error::crypto_error(format!("Failed to read proof: {}", e)))?
        {
            Some(bytes) => bytes,
            None => return Ok(false),
        };

        let entry: ACLEntry = serde_json::from_slice(entry_bytes.value())
            .map_err(|e| Error::crypto_error(format!("Failed to deserialize entry: {}", e)))?;

        let proof: ValidationProof = serde_json::from_slice(proof_bytes.value())
            .map_err(|e| Error::crypto_error(format!("Failed to deserialize proof: {}", e)))?;

        self.proof_system
            .verify_validation_proof(&proof, &entry, admin)
    }

    pub fn process_succession(
        &self,
        succession: &SuccessionRecord,
        admin: &AdminKeySet,
    ) -> Result<()> {
        if !self.proof_system.verify_succession(succession, admin)? {
            return Err(Error::invalid_succession("Invalid succession record"));
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::crypto_error(format!("Failed to begin transaction: {}", e)))?;

        {
            let mut successions_table = write_txn.open_table(SUCCESSIONS).map_err(|e| {
                Error::crypto_error(format!("Failed to open successions table: {}", e))
            })?;

            let succession_bytes = serde_json::to_vec(succession).map_err(|e| {
                Error::crypto_error(format!("Failed to serialize succession: {}", e))
            })?;

            let generation_bytes = succession.generation.to_be_bytes();
            successions_table
                .insert(
                    generation_bytes.as_slice() as &[u8],
                    succession_bytes.as_ref() as &[u8],
                )
                .map_err(|e| Error::crypto_error(format!("Failed to insert succession: {}", e)))?;
        }

        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).map_err(|e| {
                Error::crypto_error(format!("Failed to open admin state table: {}", e))
            })?;

            let new_admin = AdminKeySet {
                active_keys: succession.new_keys,
                policy_generation: succession.generation,
                last_rotation: succession.timestamp,
            };

            let admin_bytes = serde_json::to_vec(&new_admin).map_err(|e| {
                Error::crypto_error(format!("Failed to serialize admin state: {}", e))
            })?;

            admin_table
                .insert(
                    b"current".as_slice() as &[u8],
                    admin_bytes.as_ref() as &[u8],
                )
                .map_err(|e| Error::crypto_error(format!("Failed to update admin state: {}", e)))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::crypto_error(format!("Failed to commit transaction: {}", e)))
    }

    pub fn get_current_admin(&self) -> Result<AdminKeySet> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::crypto_error(format!("Failed to begin transaction: {}", e)))?;

        let admin_table = read_txn
            .open_table(ADMIN_STATE)
            .map_err(|e| Error::crypto_error(format!("Failed to open admin state table: {}", e)))?;

        let admin_bytes = admin_table
            .get(&b"current"[..])
            .map_err(|e| Error::crypto_error(format!("Failed to read admin state: {}", e)))?
            .ok_or_else(|| Error::crypto_error("No admin state found"))?;

        serde_json::from_slice(admin_bytes.value())
            .map_err(|e| Error::crypto_error(format!("Failed to deserialize admin state: {}", e)))
    }

    pub fn proof_system(&self) -> &ProofSystem {
        &self.proof_system
    }

    pub fn get_entry(&self, entry_id: &[u8]) -> Result<Option<ACLEntry>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::crypto_error(format!("Failed to begin transaction: {}", e)))?;
        let entries_table = read_txn
            .open_table(ENTRIES)
            .map_err(|e| Error::crypto_error(format!("Failed to open entries table: {}", e)))?;

        if let Some(entry_bytes) = entries_table
            .get(entry_id)
            .map_err(|e| Error::crypto_error(format!("Failed to read entry: {}", e)))?
        {
            let entry = serde_json::from_slice(entry_bytes.value())
                .map_err(|e| Error::crypto_error(format!("Failed to deserialize entry: {}", e)))?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn set_admin_state(&self, admin: &AdminKeySet) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::crypto_error(format!("Failed to begin transaction: {}", e)))?;
        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).map_err(|e| {
                Error::crypto_error(format!("Failed to open admin state table: {}", e))
            })?;

            let admin_bytes = serde_json::to_vec(admin).map_err(|e| {
                Error::crypto_error(format!("Failed to serialize admin state: {}", e))
            })?;

            admin_table
                .insert(
                    b"current".as_slice() as &[u8],
                    admin_bytes.as_ref() as &[u8],
                )
                .map_err(|e| Error::crypto_error(format!("Failed to insert admin state: {}", e)))?;
        }
        write_txn
            .commit()
            .map_err(|e| Error::crypto_error(format!("Failed to commit transaction: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EntryId, EntryMetadata, ServiceId, SigningKeyPair};
    use ed25519_dalek::SigningKey;
    use rand::{rngs::OsRng, RngCore};
    use tempfile::tempdir;
    use time::OffsetDateTime;

    #[test]
    fn test_storage_operations() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Storage::new(db_path).unwrap();

        // Generate test keys
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let key_pair = SigningKeyPair::new(SigningKey::from_bytes(&seed));

        // Create test admin set
        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: OffsetDateTime::now_utc(),
        };

        // Create and add test entry
        let entry = ACLEntry {
            id: EntryId::new([1; 32]),
            service_id: ServiceId("test".into()),
            policy_generation: 1,
            metadata: EntryMetadata {
                created_at: OffsetDateTime::now_utc(),
                expires_at: None,
                version: 1,
                service_specific: serde_json::Value::Null,
            },
            signature: storage
                .proof_system
                .sign_entry(
                    &ACLEntry {
                        id: EntryId::new([1; 32]),
                        service_id: ServiceId("test".into()),
                        policy_generation: 1,
                        metadata: EntryMetadata {
                            created_at: OffsetDateTime::now_utc(),
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

        // Test entry operations
        storage.add_entry(&entry, &admin).unwrap();
        assert!(storage.validate_entry(&entry.id.0, &admin).unwrap());
    }
}
