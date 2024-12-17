use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE as B64, Engine};
use blake3::{hash, Hash};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use super::rate_limit::RateLimit;
use crate::errors::{Error, Result};

const AUDIT_LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("audit_log");
const LAST_HASH_KEY: &[u8] = b"last_hash";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: time::OffsetDateTime,
    pub event: String,
    pub policy_generation: u32,
    pub details: serde_json::Value,
    pub operation_id: Hash,
    pub previous_operation: Option<Hash>,
}

pub struct AuditLog {
    db: Arc<Database>,
    rate_limiter: Arc<RateLimit>,
    operation_timeout: std::time::Duration,
}

impl AuditLog {
    pub fn new(
        db: Arc<Database>,
        rate_limiter: Arc<RateLimit>,
        timeout: std::time::Duration,
    ) -> Result<Self> {
        Ok(Self {
            db,
            rate_limiter,
            operation_timeout: timeout,
        })
    }

    pub async fn record_event(
        &self,
        event: String,
        policy_gen: u32,
        details: serde_json::Value,
    ) -> Result<Hash> {
        self.rate_limiter.check()?;

        let result = timeout(self.operation_timeout, async {
            let write_txn = self
                .db
                .begin_write()
                .map_err(|e| Error::database_error("Transaction failed", e.to_string()))?;

            let previous_operation = {
                let audit_table = write_txn.open_table(AUDIT_LOG).map_err(|e| {
                    Error::database_error("Failed to open audit log table", e.to_string())
                })?;

                let last_hash_bytes = audit_table.get(LAST_HASH_KEY.as_ref()).map_err(|e| {
                    Error::database_error("Failed to read last hash", e.to_string())
                })?;

                if let Some(bytes) = last_hash_bytes {
                    let bytes_value = bytes.value().to_vec();
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(&bytes_value);
                    Some(Hash::from(hash_bytes))
                } else {
                    None
                }
            };

            let operation_id = hash(
                serde_json::to_vec(&details)
                    .map_err(|e| {
                        Error::database_error("Failed to serialize details", e.to_string())
                    })?
                    .as_slice(),
            );

            let entry = AuditEntry {
                timestamp: time::OffsetDateTime::now_utc(),
                event,
                policy_generation: policy_gen,
                details,
                operation_id,
                previous_operation,
            };

            let entry_bytes = serde_json::to_vec(&entry)
                .map_err(|e| Error::database_error("Failed to serialize entry", e.to_string()))?;

            let key = B64.encode(entry.operation_id.as_bytes());

            {
                let mut audit_table = write_txn.open_table(AUDIT_LOG).map_err(|e| {
                    Error::database_error("Failed to open audit log table", e.to_string())
                })?;

                audit_table
                    .insert(key.as_bytes(), entry_bytes.as_slice())
                    .map_err(|e| Error::database_error("Failed to write entry", e.to_string()))?;

                audit_table
                    .insert(LAST_HASH_KEY.as_ref(), operation_id.as_bytes().as_ref())
                    .map_err(|e| {
                        Error::database_error("Failed to update last hash", e.to_string())
                    })?;
            }

            write_txn.commit().map_err(|e| {
                Error::database_error("Failed to commit transaction", e.to_string())
            })?;

            Ok(operation_id)
        })
        .await
        .map_err(|_| Error::database_error("Operation timeout", "Audit log write timed out"))??;

        Ok(result)
    }

    pub async fn verify_chain(&self) -> Result<bool> {
        self.rate_limiter.check()?;

        timeout(self.operation_timeout, async {
            let read_txn = self
                .db
                .begin_read()
                .map_err(|e| Error::database_error("Transaction failed", e.to_string()))?;

            let audit_table = read_txn
                .open_table(AUDIT_LOG)
                .map_err(|e| Error::database_error("Failed to open audit log", e.to_string()))?;

            let mut entries = Vec::new();
            let iter = audit_table
                .iter()
                .map_err(|e| Error::database_error("Failed to iterate table", e.to_string()))?;

            for result in iter {
                let (key, value) = result
                    .map_err(|e| Error::database_error("Failed to read entry", e.to_string()))?;

                if key.value() == LAST_HASH_KEY {
                    continue;
                }

                let entry: AuditEntry = serde_json::from_slice(value.value()).map_err(|e| {
                    Error::database_error("Failed to deserialize entry", e.to_string())
                })?;
                entries.push(entry);
            }

            entries.sort_by_key(|entry| entry.timestamp);

            let mut computed_last_hash = None;
            for entry in entries {
                if entry.previous_operation != computed_last_hash {
                    return Ok(false);
                }
                computed_last_hash = Some(entry.operation_id);
            }

            let stored_hash = {
                if let Some(stored_bytes) = audit_table
                    .get(LAST_HASH_KEY.as_ref())
                    .map_err(|e| Error::database_error("Failed to read last hash", e.to_string()))?
                {
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(stored_bytes.value());
                    Some(Hash::from(hash_bytes))
                } else {
                    None
                }
            };

            if let (Some(stored), Some(computed)) = (stored_hash, computed_last_hash) {
                if stored != computed {
                    return Ok(false);
                }
            }

            Ok(true)
        })
        .await
        .map_err(|_| {
            Error::database_error("Operation timeout", "Chain verification timed out")
        })??;

        Ok(true)
    }

    pub async fn get_events(
        &self,
        start_time: time::OffsetDateTime,
        end_time: time::OffsetDateTime,
    ) -> Result<Vec<AuditEntry>> {
        self.rate_limiter.check()?;

        let entries = timeout(self.operation_timeout, async {
            let read_txn = self
                .db
                .begin_read()
                .map_err(|e| Error::database_error("Transaction failed", e.to_string()))?;

            let audit_table = read_txn
                .open_table(AUDIT_LOG)
                .map_err(|e| Error::database_error("Failed to open audit log", e.to_string()))?;

            let mut entries = Vec::new();
            let iter = audit_table
                .iter()
                .map_err(|e| Error::database_error("Failed to iterate table", e.to_string()))?;

            for result in iter {
                let (key, value) = result
                    .map_err(|e| Error::database_error("Failed to read entry", e.to_string()))?;

                if key.value() == LAST_HASH_KEY {
                    continue;
                }

                let entry: AuditEntry = serde_json::from_slice(value.value()).map_err(|e| {
                    Error::database_error("Failed to deserialize entry", e.to_string())
                })?;

                if entry.timestamp >= start_time && entry.timestamp <= end_time {
                    entries.push(entry);
                }
            }

            entries.sort_by_key(|entry| entry.timestamp);
            Ok(entries)
        })
        .await
        .map_err(|_| Error::database_error("Operation timeout", "Event retrieval timed out"))??;

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn setup_test_log() -> AuditLog {
        let temp_dir = tempdir().unwrap();
        let db = Arc::new(Database::create(temp_dir.path().join("test.db")).unwrap());
        let rate_limiter = Arc::new(RateLimit::new(std::time::Duration::from_secs(1), 1000));
        AuditLog::new(db, rate_limiter, std::time::Duration::from_secs(30)).unwrap()
    }

    #[tokio::test]
    async fn test_audit_chain_integrity() {
        let log = setup_test_log().await;

        for i in 0..5 {
            let details = serde_json::json!({
                "operation": format!("test_operation_{}", i),
                "value": i
            });

            log.record_event(format!("TEST_EVENT_{}", i), 1, details)
                .await
                .unwrap();
        }

        assert!(log.verify_chain().await.unwrap());
    }

    #[tokio::test]
    async fn test_event_retrieval() {
        let log = setup_test_log().await;
        let start_time = time::OffsetDateTime::now_utc();

        for i in 0..3 {
            let details = serde_json::json!({
                "operation": format!("test_operation_{}", i),
                "value": i
            });

            log.record_event(format!("TEST_EVENT_{}", i), i as u32, details)
                .await
                .unwrap();
        }

        let end_time = time::OffsetDateTime::now_utc();
        let events = log.get_events(start_time, end_time).await.unwrap();
        assert_eq!(events.len(), 3);
    }
}
