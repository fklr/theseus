use base64::{engine::general_purpose::URL_SAFE as B64, Engine};
use blake3::Hash;
use ed25519_dalek::Verifier;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use time::OffsetDateTime;

use crate::crypto::ProofSystem;
use crate::errors::{Error, Result};
use crate::types::{ACLEntry, AdminKeySet, SuccessionRecord, ValidationProof};

const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");
const PROOFS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("proofs");
const SUCCESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("successions");
const ADMIN_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("admin_state");
const AUDIT_LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("audit_log");

#[derive(Serialize, Deserialize)]
pub struct AuditEntry {
    timestamp: OffsetDateTime,
    event: String,
    policy_generation: u32,
    details: serde_json::Value,
    operation_id: Hash,
    previous_operation: Option<Hash>,
}

pub struct Storage {
    db: Database,
    proof_system: ProofSystem,
    last_audit_hash: Option<Hash>,
}

impl Storage {
    fn write_audit_log(
        &self,
        txn: &redb::WriteTransaction,
        event: String,
        policy_gen: u32,
        details: serde_json::Value,
    ) -> Result<Hash> {
        let mut audit_table = txn.open_table(AUDIT_LOG).map_err(|e| {
            Error::database_error(
                "Database access failed",
                format!("Failed to open audit log table: {}", e),
            )
        })?;

        let operation_id = blake3::hash(serde_json::to_vec(&details).unwrap().as_slice());

        let entry = AuditEntry {
            timestamp: OffsetDateTime::now_utc(),
            event,
            policy_generation: policy_gen,
            details,
            operation_id,
            previous_operation: self.last_audit_hash,
        };

        let entry_bytes = serde_json::to_vec(&entry).map_err(|e| {
            Error::database_error(
                "Serialization failed",
                format!("Failed to serialize audit entry: {}", e),
            )
        })?;

        let key = B64.encode(entry.operation_id.as_bytes());
        audit_table
            .insert(key.as_bytes(), entry_bytes.as_slice())
            .map_err(|e| {
                Error::database_error(
                    "Database write failed",
                    format!("Failed to write audit log: {}", e),
                )
            })?;

        Ok(entry.operation_id)
    }

    fn update_last_audit_hash(&mut self, hash: Hash) {
        self.last_audit_hash = Some(hash);
    }

    pub fn get_audit_log(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<Vec<AuditEntry>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let audit_table = read_txn.open_table(AUDIT_LOG).map_err(|e| {
            Error::database_error(
                "Database access failed",
                format!("Failed to open audit log table: {}", e),
            )
        })?;

        let mut entries = Vec::new();
        for result in audit_table.iter().map_err(|e| {
            Error::database_error(
                "Database iteration failed",
                format!("Failed to iterate over audit log table: {}", e),
            )
        })? {
            let (_, value) = result.map_err(|e| {
                Error::database_error(
                    "Database read failed",
                    format!("Failed to read audit log entry: {}", e),
                )
            })?;

            let entry: AuditEntry = serde_json::from_slice(value.value()).map_err(|e| {
                Error::database_error(
                    "Deserialization failed",
                    format!("Failed to deserialize audit entry: {}", e),
                )
            })?;

            if entry.timestamp >= start_time && entry.timestamp <= end_time {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    pub fn verify_audit_chain(&self) -> Result<bool> {
        let read_txn = self.db.begin_read().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let audit_table = read_txn.open_table(AUDIT_LOG).map_err(|e| {
            Error::database_error(
                "Database access failed",
                format!("Failed to open audit log table: {}", e),
            )
        })?;

        let mut last_hash = None;
        for result in audit_table.iter().map_err(|e| {
            Error::database_error(
                "Database iteration failed",
                format!("Failed to iterate over audit log table: {}", e),
            )
        })? {
            let (_, value) = result.map_err(|e| {
                Error::database_error(
                    "Database read failed",
                    format!("Failed to read audit log entry: {}", e),
                )
            })?;

            let entry: AuditEntry = serde_json::from_slice(value.value()).map_err(|e| {
                Error::database_error(
                    "Deserialization failed",
                    format!("Failed to deserialize audit entry: {}", e),
                )
            })?;

            if entry.previous_operation != last_hash {
                return Ok(false);
            }
            last_hash = Some(entry.operation_id);
        }

        Ok(true)
    }

    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::create(path).map_err(|e| {
            Error::database_error(
                "Database initialization failed",
                format!("Failed to create database: {}", e),
            )
        })?;

        let write_txn = db.begin_write().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        write_txn.open_table(ENTRIES).map_err(|e| {
            Error::database_error(
                "Table initialization failed",
                format!("Failed to create entries table: {}", e),
            )
        })?;

        write_txn.open_table(PROOFS).map_err(|e| {
            Error::database_error(
                "Table initialization failed",
                format!("Failed to create proofs table: {}", e),
            )
        })?;

        write_txn.open_table(SUCCESSIONS).map_err(|e| {
            Error::database_error(
                "Table initialization failed",
                format!("Failed to create successions table: {}", e),
            )
        })?;

        write_txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::database_error(
                "Table initialization failed",
                format!("Failed to create admin state table: {}", e),
            )
        })?;

        write_txn.open_table(AUDIT_LOG).map_err(|e| {
            Error::database_error(
                "Table initialization failed",
                format!("Failed to create audit log table: {}", e),
            )
        })?;

        write_txn.commit().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to commit transaction: {}", e),
            )
        })?;

        Ok(Self {
            db,
            proof_system: ProofSystem::new(),
            last_audit_hash: None,
        })
    }

    pub fn add_entry(&mut self, entry: &ACLEntry, admin: &AdminKeySet) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let message = self.proof_system.create_entry_message(entry);
        let valid_signature = admin
            .active_keys
            .iter()
            .any(|key| key.verify(&message, &entry.signature.0).is_ok());

        if !valid_signature {
            let audit_details = json!({
                "error": "invalid_signature",
                "service_id": entry.service_id.0,
                "policy_generation": entry.policy_generation,
            });
            self.write_audit_log(
                &write_txn,
                "entry_validation_failed".into(),
                admin.policy_generation,
                audit_details,
            )?;

            return Err(Error::invalid_entry(
                "Access validation failed",
                "Invalid entry signature",
            ));
        }

        let proof = self
            .proof_system
            .generate_validation_proof(entry, admin, None)?;

        let entry_bytes = serde_json::to_vec(&entry).map_err(|e| {
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
            let mut entries_table = write_txn.open_table(ENTRIES).map_err(|e| {
                Error::database_error(
                    "Database access failed",
                    format!("Failed to open entries table: {}", e),
                )
            })?;
            let mut proofs_table = write_txn.open_table(PROOFS).map_err(|e| {
                Error::database_error(
                    "Database access failed",
                    format!("Failed to open proofs table: {}", e),
                )
            })?;

            entries_table
                .insert(entry.id.0.as_ref() as &[u8], entry_bytes.as_ref() as &[u8])
                .map_err(|e| {
                    Error::database_error(
                        "Database write failed",
                        format!("Failed to insert entry: {}", e),
                    )
                })?;
            proofs_table
                .insert(entry.id.0.as_ref() as &[u8], proof_bytes.as_ref() as &[u8])
                .map_err(|e| {
                    Error::database_error(
                        "Database write failed",
                        format!("Failed to insert proof: {}", e),
                    )
                })?;
        }

        let audit_details = json!({
            "entry_id": B64.encode(entry.id.0),
            "service_id": entry.service_id.0,
            "policy_generation": entry.policy_generation,
        });
        let hash = self.write_audit_log(
            &write_txn,
            "entry_added".into(),
            admin.policy_generation,
            audit_details,
        )?;
        self.update_last_audit_hash(hash);

        write_txn.commit().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to commit transaction: {}", e),
            )
        })?;

        Ok(())
    }

    pub fn validate_entry(&self, entry_id: &[u8], admin: &AdminKeySet) -> Result<bool> {
        let read_txn = self.db.begin_read().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let entries_table = read_txn.open_table(ENTRIES).map_err(|e| {
            Error::database_error(
                "Database access failed",
                format!("Failed to open entries table: {}", e),
            )
        })?;
        let proofs_table = read_txn.open_table(PROOFS).map_err(|e| {
            Error::database_error(
                "Database access failed",
                format!("Failed to open proofs table: {}", e),
            )
        })?;

        let entry_bytes = match entries_table.get(entry_id).map_err(|e| {
            Error::database_error(
                "Database read failed",
                format!("Failed to read entry: {}", e),
            )
        })? {
            Some(bytes) => bytes,
            None => return Ok(false),
        };

        let proof_bytes = match proofs_table.get(entry_id).map_err(|e| {
            Error::database_error(
                "Database read failed",
                format!("Failed to read proof: {}", e),
            )
        })? {
            Some(bytes) => bytes,
            None => return Ok(false),
        };

        let entry: ACLEntry = serde_json::from_slice(entry_bytes.value()).map_err(|e| {
            Error::database_error(
                "Deserialization failed",
                format!("Failed to deserialize entry: {}", e),
            )
        })?;

        let proof: ValidationProof = serde_json::from_slice(proof_bytes.value()).map_err(|e| {
            Error::database_error(
                "Deserialization failed",
                format!("Failed to deserialize proof: {}", e),
            )
        })?;

        self.proof_system
            .verify_validation_proof(&proof, &entry, admin)
    }

    pub fn process_succession(
        &mut self,
        succession: &SuccessionRecord,
        admin: &AdminKeySet,
    ) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        if !self.proof_system.verify_succession(succession, admin)? {
            let audit_details = json!({
                "error": "invalid_succession",
                "from_generation": admin.policy_generation,
                "to_generation": succession.generation,
            });
            self.write_audit_log(
                &write_txn,
                "succession_verification_failed".into(),
                admin.policy_generation,
                audit_details,
            )?;

            return Err(Error::invalid_succession(
                "Key succession validation failed",
                "Invalid succession record",
            ));
        }

        {
            let mut successions_table = write_txn.open_table(SUCCESSIONS).map_err(|e| {
                Error::database_error(
                    "Database access failed",
                    format!("Failed to open successions table: {}", e),
                )
            })?;

            let succession_bytes = serde_json::to_vec(succession).map_err(|e| {
                Error::database_error(
                    "Serialization failed",
                    format!("Failed to serialize succession: {}", e),
                )
            })?;

            let generation_bytes = succession.generation.to_be_bytes();
            successions_table
                .insert(
                    generation_bytes.as_slice() as &[u8],
                    succession_bytes.as_ref() as &[u8],
                )
                .map_err(|e| {
                    Error::database_error(
                        "Database write failed",
                        format!("Failed to insert succession: {}", e),
                    )
                })?;
        }

        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).map_err(|e| {
                Error::database_error(
                    "Database access failed",
                    format!("Failed to open admin state table: {}", e),
                )
            })?;

            let new_admin = AdminKeySet {
                active_keys: succession.new_keys,
                policy_generation: succession.generation,
                last_rotation: succession.timestamp,
            };

            let admin_bytes = serde_json::to_vec(&new_admin).map_err(|e| {
                Error::database_error(
                    "Serialization failed",
                    format!("Failed to serialize admin state: {}", e),
                )
            })?;

            admin_table
                .insert(
                    b"current".as_slice() as &[u8],
                    admin_bytes.as_ref() as &[u8],
                )
                .map_err(|e| {
                    Error::database_error(
                        "Database write failed",
                        format!("Failed to update admin state: {}", e),
                    )
                })?;
        }

        let audit_details = json!({
            "from_generation": admin.policy_generation,
            "to_generation": succession.generation,
            "affected_entries": succession.affected_entries.len(),
            "timestamp": succession.timestamp,
        });
        let hash = self.write_audit_log(
            &write_txn,
            "succession_completed".into(),
            admin.policy_generation,
            audit_details,
        )?;
        self.update_last_audit_hash(hash);

        write_txn.commit().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to commit transaction: {}", e),
            )
        })?;

        Ok(())
    }

    pub fn get_current_admin(&self) -> Result<AdminKeySet> {
        let read_txn = self.db.begin_read().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let admin_table = read_txn.open_table(ADMIN_STATE).map_err(|e| {
            Error::database_error(
                "Database access failed",
                format!("Failed to open admin state table: {}", e),
            )
        })?;

        let admin_bytes = admin_table
            .get(&b"current"[..])
            .map_err(|e| {
                Error::database_error(
                    "Database read failed",
                    format!("Failed to read admin state: {}", e),
                )
            })?
            .ok_or_else(|| Error::database_error("Not found", "No admin state found"))?;

        serde_json::from_slice(admin_bytes.value()).map_err(|e| {
            Error::database_error(
                "Deserialization failed",
                format!("Failed to deserialize admin state: {}", e),
            )
        })
    }

    pub fn proof_system(&self) -> &ProofSystem {
        &self.proof_system
    }

    pub fn get_entry(&self, entry_id: &[u8]) -> Result<Option<ACLEntry>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;
        let entries_table = read_txn.open_table(ENTRIES).map_err(|e| {
            Error::database_error(
                "Database access failed",
                format!("Failed to open entries table: {}", e),
            )
        })?;

        if let Some(entry_bytes) = entries_table.get(entry_id).map_err(|e| {
            Error::database_error(
                "Database read failed",
                format!("Failed to read entry: {}", e),
            )
        })? {
            let entry = serde_json::from_slice(entry_bytes.value()).map_err(|e| {
                Error::database_error(
                    "Deserialization failed",
                    format!("Failed to deserialize entry: {}", e),
                )
            })?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn set_admin_state(&mut self, admin: &AdminKeySet) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to begin transaction: {}", e),
            )
        })?;

        let audit_details = json!({
            "policy_generation": admin.policy_generation,
            "timestamp": admin.last_rotation,
        });
        let hash = self.write_audit_log(
            &write_txn,
            "admin_state_updated".into(),
            admin.policy_generation,
            audit_details,
        )?;
        self.update_last_audit_hash(hash);

        {
            let mut admin_table = write_txn.open_table(ADMIN_STATE).map_err(|e| {
                Error::database_error(
                    "Database access failed",
                    format!("Failed to open admin state table: {}", e),
                )
            })?;

            let admin_bytes = serde_json::to_vec(admin).map_err(|e| {
                Error::database_error(
                    "Serialization failed",
                    format!("Failed to serialize admin state: {}", e),
                )
            })?;

            admin_table
                .insert(
                    b"current".as_slice() as &[u8],
                    admin_bytes.as_ref() as &[u8],
                )
                .map_err(|e| {
                    Error::database_error(
                        "Database write failed",
                        format!("Failed to insert admin state: {}", e),
                    )
                })?;
        }

        write_txn.commit().map_err(|e| {
            Error::database_error(
                "Database transaction failed",
                format!("Failed to commit transaction: {}", e),
            )
        })?;

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
        let mut storage = Storage::new(db_path).unwrap();

        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let key_pair = SigningKeyPair::new(SigningKey::from_bytes(&seed));

        let fixed_time = OffsetDateTime::from_unix_timestamp(1640995200).unwrap();

        let admin = AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: fixed_time,
        };

        let metadata = EntryMetadata {
            created_at: fixed_time,
            expires_at: None,
            version: 1,
            service_specific: serde_json::Value::Null,
        };

        let mut entry = ACLEntry {
            id: EntryId::new([1; 32]),
            service_id: ServiceId("test".into()),
            policy_generation: 1,
            metadata,
            signature: crate::types::SerializableSignature(ed25519_dalek::Signature::from_bytes(
                &[0; 64],
            )),
        };

        entry.signature = storage.proof_system.sign_entry(&entry, &key_pair).unwrap();

        storage.add_entry(&entry, &admin).unwrap();
        assert!(storage.validate_entry(&entry.id.0, &admin).unwrap());

        let mut tampered_entry = entry.clone();
        tampered_entry.metadata.created_at = fixed_time + time::Duration::hours(1);
        assert!(storage.add_entry(&tampered_entry, &admin).is_err());
    }

    #[test]
    fn test_timestamp_invariance() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let mut storage = Storage::new(db_path).unwrap();

        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let key_pair = SigningKeyPair::new(SigningKey::from_bytes(&seed));

        let timestamps = [
            OffsetDateTime::from_unix_timestamp(1640995200).unwrap(),
            OffsetDateTime::from_unix_timestamp(1641081600).unwrap(),
            OffsetDateTime::from_unix_timestamp(1641168000).unwrap(),
        ];

        for &ts in &timestamps {
            let admin = AdminKeySet {
                active_keys: [key_pair.verifying_key; 2],
                policy_generation: 1,
                last_rotation: ts,
            };

            let metadata = EntryMetadata {
                created_at: ts,
                expires_at: None,
                version: 1,
                service_specific: serde_json::Value::Null,
            };

            let mut entry = ACLEntry {
                id: EntryId::new([1; 32]),
                service_id: ServiceId("test".into()),
                policy_generation: 1,
                metadata,
                signature: crate::types::SerializableSignature(
                    ed25519_dalek::Signature::from_bytes(&[0; 64]),
                ),
            };

            entry.signature = storage.proof_system.sign_entry(&entry, &key_pair).unwrap();
            storage.add_entry(&entry, &admin).unwrap();
            assert!(storage.validate_entry(&entry.id.0, &admin).unwrap());
        }
    }
}
