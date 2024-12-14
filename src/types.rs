use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceId(pub String);

//-----------------------------------------------------------------------------
// Cryptographic Types
//-----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SerializableSignature(pub Signature);

impl Serialize for SerializableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.to_bytes();
        BASE64.encode(bytes).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let b64 = String::deserialize(deserializer)?;
        let bytes = BASE64
            .decode(b64.as_bytes())
            .map_err(serde::de::Error::custom)?;

        let sig_bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid signature length"))?;

        let sig = Signature::from_bytes(&sig_bytes);
        Ok(SerializableSignature(sig))
    }
}

#[derive(Debug)]
pub struct SigningKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl SigningKeyPair {
    pub fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> SerializableSignature {
        SerializableSignature(self.signing_key.sign(message))
    }
}

#[derive(Debug, Clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationProof {
    pub entry_id: EntryId,
    pub proof_data: Vec<u8>,
    pub generation: u32,
    pub transcript_bytes: Vec<u8>,
    pub commitment: [u8; 32],
}

impl ValidationProof {
    pub fn new(
        entry_id: EntryId,
        proof_data: Vec<u8>,
        generation: u32,
        transcript_bytes: Vec<u8>,
        commitment: [u8; 32],
    ) -> Self {
        Self {
            entry_id,
            proof_data,
            generation,
            transcript_bytes,
            commitment,
        }
    }

    pub fn create_transcript(&self) -> merlin::Transcript {
        let mut transcript = merlin::Transcript::new(b"theseus-entry-validation");
        transcript.append_message(b"transcript-data", &self.transcript_bytes);
        transcript.append_message(b"transcript-data", &self.commitment);
        transcript
    }
}

//-----------------------------------------------------------------------------
// Access Control Types
//-----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACLEntry {
    pub id: EntryId,
    pub service_id: ServiceId,
    pub policy_generation: u32,
    pub metadata: EntryMetadata,
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub version: u32,
    pub service_specific: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccessRequest {
    pub service_id: ServiceId,
    pub requester: VerifyingKey,
    pub expires_at: Option<OffsetDateTime>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrant {
    pub request_id: EntryId,
    pub granter: VerifyingKey,
    pub signature: SerializableSignature,
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
    pub administrators: [VerifyingKey; 2],
    pub policy_generation: u32,
    pub succession_requirements: SuccessionPolicy,
    pub recovery_keys: Option<[VerifyingKey; 2]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionPolicy {
    pub min_key_age: time::Duration,
    pub required_signatures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeySet {
    pub active_keys: [VerifyingKey; 2],
    pub policy_generation: u32,
    pub last_rotation: OffsetDateTime,
}

#[derive(Debug)]
pub struct SuccessionRequest {
    pub current_keys: [SigningKeyPair; 2],
    pub new_verifying_keys: [VerifyingKey; 2],
    pub affected_entries: Vec<EntryId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionRecord {
    pub old_keys: [VerifyingKey; 2],
    pub new_keys: [VerifyingKey; 2],
    pub generation: u32,
    pub timestamp: OffsetDateTime,
    pub affected_entries: Vec<EntryId>,
    pub signatures: [SerializableSignature; 2],
    pub request_metadata: Option<serde_json::Value>,
}
