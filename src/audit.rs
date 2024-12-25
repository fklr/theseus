use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec, Value};
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::time::timeout;

use crate::{
    errors::{Error, Result},
    rate_limit::RateLimit,
};

const AUDIT_ENTRIES: TableDefinition<u64, &[u8]> = TableDefinition::new("audit_entries");
const CHAIN_HEAD: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chain_head");
const SEQUENCE_COUNTER: TableDefinition<&[u8], u64> = TableDefinition::new("sequence_counter");

const CURRENT_KEY: &[u8] = b"current";
const HEAD_KEY: &[u8] = b"head";
const GENESIS_HASH: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainEntry {
    pub sequence: u64,
    pub timestamp: OffsetDateTime,
    pub event_type: String,
    pub policy_generation: u32,
    pub details: Value,
    pub previous_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl AuditChainEntry {
    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.timestamp.unix_timestamp().to_le_bytes());
        hasher.update(self.event_type.as_bytes());
        hasher.update(&self.policy_generation.to_le_bytes());
        hasher.update(self.details.to_string().as_bytes());
        hasher.update(&self.previous_hash);
        *hasher.finalize().as_bytes()
    }
}

pub struct AuditLog {
    db: Arc<Database>,
    rate_limiter: Arc<RateLimit>,
    operation_timeout: Duration,
}

impl AuditLog {
    pub fn new(db: Arc<Database>, rate_limiter: Arc<RateLimit>, timeout: Duration) -> Result<Self> {
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(AUDIT_ENTRIES)?;
            write_txn.open_table(CHAIN_HEAD)?;
            let mut seq_table = write_txn.open_table(SEQUENCE_COUNTER)?;
            if seq_table.get(CURRENT_KEY)?.is_none() {
                seq_table.insert(CURRENT_KEY, &0u64)?;
            }
        }
        write_txn.commit()?;

        Ok(Self {
            db,
            rate_limiter,
            operation_timeout: timeout,
        })
    }

    pub async fn record_event(
        &self,
        event_type: String,
        policy_generation: u32,
        details: serde_json::Value,
    ) -> Result<[u8; 32]> {
        self.rate_limiter.check()?;

        let entry_hash = timeout(self.operation_timeout, async {
            let write_txn = self.db.begin_write()?;
            let sequence = {
                let mut seq_table = write_txn.open_table(SEQUENCE_COUNTER)?;
                let current_value = seq_table
                    .get(CURRENT_KEY)?
                    .ok_or_else(|| {
                        Error::database_error(
                            "Missing sequence",
                            "Sequence counter not initialized",
                        )
                    })?
                    .value();
                let next = current_value + 1;
                seq_table.insert(CURRENT_KEY, &next)?;
                next
            };

            let previous_hash = {
                let head_table = write_txn.open_table(CHAIN_HEAD)?;
                let x = head_table
                    .get(HEAD_KEY)?
                    .map(|v| {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(v.value());
                        hash
                    })
                    .unwrap_or(GENESIS_HASH);
                x
            };

            let mut entry = AuditChainEntry {
                sequence,
                timestamp: OffsetDateTime::now_utc(),
                event_type,
                policy_generation,
                details,
                previous_hash,
                entry_hash: GENESIS_HASH,
            };

            entry.entry_hash = entry.compute_hash();

            let entry_bytes = to_vec(&entry)?;
            {
                let mut entries_table = write_txn.open_table(AUDIT_ENTRIES)?;
                if entries_table.get(sequence)?.is_some() {
                    return Err(Error::database_error(
                        "Sequence collision",
                        "Audit log sequence number already exists",
                    ));
                }
                entries_table.insert(sequence, entry_bytes.as_slice())?;
            }

            {
                let mut head_table = write_txn.open_table(CHAIN_HEAD)?;
                head_table.insert(HEAD_KEY, entry.entry_hash.as_slice())?;
            }

            let entry_hash = entry.entry_hash;
            write_txn.commit()?;
            Ok(entry_hash)
        })
        .await
        .map_err(|_| Error::database_error("Operation timeout", "Audit log write timed out"))??;

        Ok(entry_hash)
    }

    pub async fn verify_chain_integrity(&self) -> Result<bool> {
        self.rate_limiter.check()?;

        timeout(self.operation_timeout, async {
            let read_txn = self.db.begin_read()?;
            let entries_table = read_txn.open_table(AUDIT_ENTRIES)?;
            let head_table = read_txn.open_table(CHAIN_HEAD)?;

            // Get stored head hash
            let current_hash = match head_table.get(HEAD_KEY)? {
                Some(bytes) => {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(bytes.value());
                    hash
                }
                None => return Ok::<bool, Error>(true),
            };

            let total_entries = entries_table.len()?;
            if total_entries == 0 {
                return Ok(true);
            }

            // Walk chain backwards verifying hashes
            let mut next_hash = current_hash;
            let mut sequence = total_entries;

            while sequence > 0 {
                let entry_bytes = entries_table.get(sequence)?.ok_or_else(|| {
                    Error::database_error("Missing entry", "Audit chain is discontinuous")
                })?;
                let entry: AuditChainEntry = from_slice(entry_bytes.value())?;

                // Verify entry hash matches content
                let computed_hash = entry.compute_hash();
                if computed_hash != entry.entry_hash {
                    return Ok(false);
                }

                // Verify chain linkage
                if computed_hash != next_hash {
                    return Ok(false);
                }

                next_hash = entry.previous_hash;
                sequence -= 1;
            }

            Ok(next_hash == GENESIS_HASH)
        })
        .await
        .map_err(|_| Error::database_error("Operation timeout", "Chain verification timed out"))?
    }

    pub async fn get_events(
        &self,
        start_time: OffsetDateTime,
        end_time: OffsetDateTime,
    ) -> Result<Vec<AuditChainEntry>> {
        self.rate_limiter.check()?;

        timeout(self.operation_timeout, async {
            let read_txn = self.db.begin_read()?;
            let entries_table = read_txn.open_table(AUDIT_ENTRIES)?;
            let mut entries = Vec::new();

            for result in entries_table.iter()? {
                let (_, value) = result?;
                let entry: AuditChainEntry = from_slice(value.value())?;
                if entry.timestamp >= start_time && entry.timestamp <= end_time {
                    entries.push(entry);
                }
            }

            Ok(entries)
        })
        .await
        .map_err(|_| Error::database_error("Operation timeout", "Event retrieval timed out"))?
    }

    pub async fn get_entry(&self, sequence: u64) -> Result<Option<AuditChainEntry>> {
        self.rate_limiter.check()?;

        let read_txn = self.db.begin_read()?;
        let entries_table = read_txn.open_table(AUDIT_ENTRIES)?;

        Ok(if let Some(entry_bytes) = entries_table.get(sequence)? {
            Some(from_slice(entry_bytes.value())?)
        } else {
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;
    use tempfile::tempdir;

    async fn setup_test_log() -> AuditLog {
        let temp_dir = tempdir().unwrap();
        let db = Arc::new(Database::create(temp_dir.path().join("test.db")).unwrap());
        let rate_limiter = Arc::new(RateLimit::new(Duration::from_secs(1), 1000));

        AuditLog::new(db, rate_limiter, Duration::from_secs(30)).unwrap()
    }

    #[tokio::test]
    async fn test_chain_integrity() {
        let log = setup_test_log().await;

        // Create a sequence of entries
        for i in 0..5 {
            log.record_event(format!("TEST_EVENT_{}", i), 1, json!({ "value": i }))
                .await
                .unwrap();
        }

        // Verify the chain
        assert!(log.verify_chain_integrity().await.unwrap());

        // Verify sequence numbers are correct
        for i in 1..=5 {
            let entry = log.get_entry(i).await.unwrap().unwrap();
            assert_eq!(entry.sequence, i);
        }
    }

    #[tokio::test]
    async fn test_concurrent_writes() {
        let log = Arc::new(setup_test_log().await);
        let mut handles = Vec::new();

        for i in 0..10 {
            let log = Arc::clone(&log);
            handles.push(tokio::spawn(async move {
                log.record_event(format!("CONCURRENT_EVENT_{}", i), 1, json!({ "value": i }))
                    .await
                    .unwrap()
            }));
        }

        let results = futures::future::join_all(handles).await;
        assert!(results.into_iter().all(|r| r.is_ok()));

        // Verify chain integrity after concurrent operations
        assert!(log.verify_chain_integrity().await.unwrap());

        // Verify all entries are present and properly sequenced
        let mut sequence_numbers = Vec::new();
        for i in 1..=10 {
            let entry = log.get_entry(i).await.unwrap().unwrap();
            sequence_numbers.push(entry.sequence);
        }

        // Verify sequence numbers are continuous and ordered
        assert_eq!(sequence_numbers, (1..=10).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn test_tampering_resistance() {
        let log = setup_test_log().await;

        // Create initial entries
        for i in 0..3 {
            log.record_event(format!("EVENT_{}", i), 1, json!({ "value": i }))
                .await
                .unwrap();
        }

        // Verify chain is valid before tampering
        assert!(log.verify_chain_integrity().await.unwrap());

        // Tamper with entry 2
        let write_txn = log.db.begin_write().unwrap();
        {
            let mut entries_table = write_txn.open_table(AUDIT_ENTRIES).unwrap();
            let entry_bytes = entries_table.get(2).unwrap().unwrap().value().to_vec();
            let mut entry: AuditChainEntry = from_slice(&entry_bytes).unwrap();

            // Change content but keep hashes
            let original_hash = entry.entry_hash;
            let original_prev = entry.previous_hash;
            entry.details = json!({ "value": "TAMPERED" });
            entry.entry_hash = original_hash;
            entry.previous_hash = original_prev;

            // Write tampered entry
            entries_table
                .insert(2, to_vec(&entry).unwrap().as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        // Should detect tampering
        assert!(!log.verify_chain_integrity().await.unwrap());
    }
}
