use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    crypto::{serialize::SerializableG2, signatures::AggregateSignature, CircuitProof},
    errors::Error,
};

//-----------------------------------------------------------------------------
// Core Identifiers
//-----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(pub [u8; 32]);

impl EntryId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hash(data: &[u8]) -> Self {
        Self(blake3::hash(data).into())
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != 32 {
            return Err(Error::invalid_entry(
                "Invalid ID length",
                "Entry ID must be 32 bytes",
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(slice);
        Ok(Self(id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceId(pub String);

//-----------------------------------------------------------------------------
// Access Control Types
//-----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACLEntry {
    pub id: EntryId,
    pub service_id: ServiceId,
    pub policy_generation: u32,
    pub metadata: EntryMetadata,
    pub auth_proof: AuthProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProof {
    pub aggregate_signature: AggregateSignature,
    pub policy_generation: u32,
    pub threshold: u32,
    pub succession_proof: Option<CircuitProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub version: u32,
    pub service_specific: serde_json::Value,
    pub required_attributes: Option<Vec<u8>>,
    pub access_level: Option<u32>,
}

impl Default for EntryMetadata {
    fn default() -> Self {
        Self {
            created_at: OffsetDateTime::now_utc(),
            expires_at: None,
            version: 1,
            service_specific: serde_json::Value::Null,
            required_attributes: None,
            access_level: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccessRequest {
    pub service_id: ServiceId,
    pub public_key: SerializableG2,
    pub expires_at: Option<OffsetDateTime>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrant {
    pub request_id: EntryId,
    pub granter: SerializableG2,
    pub signature: AggregateSignature,
    pub timestamp: OffsetDateTime,
}

//-----------------------------------------------------------------------------
// Policy and Service Types
//-----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub id: ServiceId,
    pub name: String,
    pub requirements: ServiceRequirements,
    pub admin_policy: AdminPolicy,
    pub min_policy_age: time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRequirements {
    pub auth_type: AuthenticationType,
    pub required_proofs: Vec<ProofRequirement>,
    pub minimum_signatures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationType {
    SingleSignature,
    MultiSignature { threshold: u32 },
    Quorum { required: u32, total: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequirement {
    pub proof_type: String,
    pub parameters: serde_json::Value,
}

//-----------------------------------------------------------------------------
// Administrative Types
//-----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPolicy {
    pub administrators: Vec<SerializableG2>,
    pub threshold: u32,
    pub policy_generation: u32,
    pub succession_requirements: SuccessionPolicy,
    pub recovery_keys: Option<Vec<SerializableG2>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionPolicy {
    pub min_key_age: time::Duration,
    pub required_signatures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeySet {
    pub active_keys: Vec<SerializableG2>,
    pub policy_generation: u32,
    pub last_rotation: OffsetDateTime,
}

impl Default for AdminKeySet {
    fn default() -> Self {
        Self {
            active_keys: Vec::new(),
            policy_generation: 0,
            last_rotation: time::OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionRecord {
    pub old_keys: Vec<SerializableG2>,
    pub new_keys: Vec<SerializableG2>,
    pub generation: u32,
    pub timestamp: OffsetDateTime,
    pub affected_entries: Vec<EntryId>,
    pub auth_proof: AuthProof,
    pub request_metadata: Option<serde_json::Value>,
}
