use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::Verifier;
use merlin::Transcript;
use rand::thread_rng;
use serde::Serialize;

use crate::errors::{Error, Result};
use crate::types::{
    ACLEntry, AdminKeySet, SerializableSignature, SigningKeyPair, SuccessionRecord,
    SuccessionRequest, ValidationProof,
};

#[derive(Serialize)]
struct UnsignedEntry<'a> {
    id: &'a crate::types::EntryId,
    service_id: &'a crate::types::ServiceId,
    policy_generation: u32,
    metadata: &'a crate::types::EntryMetadata,
}

pub struct ProofSystem {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

impl Default for ProofSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofSystem {
    pub fn new() -> Self {
        Self {
            bp_gens: BulletproofGens::new(2048, 1),
            pc_gens: PedersenGens::default(),
        }
    }

    pub fn generate_validation_proof(
        &self,
        entry: &ACLEntry,
        current_admin: &AdminKeySet,
        succession: Option<&SuccessionRecord>,
    ) -> Result<ValidationProof> {
        let mut transcript = Transcript::new(b"theseus-entry-validation");

        transcript.append_message(b"entry-id", &entry.id.0);
        transcript.append_message(b"policy-gen", &entry.policy_generation.to_le_bytes());

        transcript.append_message(b"admin-gen", &current_admin.policy_generation.to_le_bytes());
        for key in &current_admin.active_keys {
            transcript.append_message(b"admin-key", key.as_bytes());
        }

        if let Some(succ) = succession {
            transcript.append_message(b"succession-gen", &succ.generation.to_le_bytes());
            for key in &succ.old_keys {
                transcript.append_message(b"old-key", key.as_bytes());
            }
            for key in &succ.new_keys {
                transcript.append_message(b"new-key", key.as_bytes());
            }
        }

        let v_blinding = Scalar::random(&mut thread_rng());
        let (proof, commitment) = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            entry.policy_generation as u64,
            &v_blinding,
            32,
        )
        .map_err(|e| {
            Error::crypto_error(
                "Range proof generation failed",
                format!("Failed to create range proof: {}", e),
            )
        })?;

        Ok(ValidationProof::new(
            entry.id,
            proof.to_bytes(),
            entry.policy_generation,
            commitment.to_bytes(),
        ))
    }

    pub fn verify_validation_proof(
        &self,
        proof: &ValidationProof,
        entry: &ACLEntry,
        current_admin: &AdminKeySet,
    ) -> Result<bool> {
        let message = self.create_entry_message(entry);
        let valid_signature = current_admin
            .active_keys
            .iter()
            .any(|key| key.verify(&message, &entry.signature.0).is_ok());

        if !valid_signature {
            return Ok(false);
        }

        let mut transcript = Transcript::new(b"theseus-entry-validation");
        transcript.append_message(b"entry-id", &entry.id.0);
        transcript.append_message(b"policy-gen", &entry.policy_generation.to_le_bytes());
        transcript.append_message(b"admin-gen", &current_admin.policy_generation.to_le_bytes());
        for key in &current_admin.active_keys {
            transcript.append_message(b"admin-key", key.as_bytes());
        }

        let range_proof = RangeProof::from_bytes(&proof.proof_data).map_err(|e| {
            Error::invalid_proof(
                "Access proof validation failed",
                format!("Invalid proof: {}", e),
            )
        })?;

        let compressed_point = CompressedRistretto::from_slice(&proof.commitment).map_err(|e| {
            Error::crypto_error(
                "Point decoding failed",
                format!("Failed to construct Ristretto point: {}", e),
            )
        })?;

        range_proof
            .verify_single(
                &self.bp_gens,
                &self.pc_gens,
                &mut transcript,
                &compressed_point,
                32,
            )
            .map_err(|e| Error::verification_failed("Verification failed", e.to_string()))?;

        Ok(true)
    }

    pub fn process_succession(
        &self,
        request: &SuccessionRequest,
        current_admin: &AdminKeySet,
    ) -> Result<SuccessionRecord> {
        for (req_pair, admin_key) in request.current_keys.iter().zip(&current_admin.active_keys) {
            if req_pair.verifying_key != *admin_key {
                return Err(Error::invalid_succession(
                    "Key succession validation failed",
                    "Invalid succession record",
                ));
            }
        }

        let message = self.create_succession_message(
            current_admin.policy_generation,
            &request.new_verifying_keys,
        );
        let signatures = [
            request.current_keys[0].sign(&message),
            request.current_keys[1].sign(&message),
        ];

        Ok(SuccessionRecord {
            old_keys: current_admin.active_keys,
            new_keys: request.new_verifying_keys,
            generation: current_admin.policy_generation + 1,
            timestamp: current_admin.last_rotation,
            affected_entries: request.affected_entries.clone(),
            signatures,
            request_metadata: None,
        })
    }

    pub fn verify_succession(
        &self,
        record: &SuccessionRecord,
        current_admin: &AdminKeySet,
    ) -> Result<bool> {
        if record.old_keys != current_admin.active_keys {
            return Ok(false);
        }

        if record.generation != current_admin.policy_generation + 1 {
            return Ok(false);
        }

        if record.timestamp != current_admin.last_rotation {
            return Ok(false);
        }

        let message =
            self.create_succession_message(current_admin.policy_generation, &record.new_keys);

        let valid_signatures = record.old_keys[0]
            .verify(&message, &record.signatures[0].0)
            .is_ok()
            && record.old_keys[1]
                .verify(&message, &record.signatures[1].0)
                .is_ok();

        Ok(valid_signatures)
    }

    pub fn sign_entry(
        &self,
        entry: &ACLEntry,
        key_pair: &SigningKeyPair,
    ) -> Result<SerializableSignature> {
        let message = self.create_entry_message(entry);
        Ok(key_pair.sign(&message))
    }

    pub fn create_entry_message(&self, entry: &ACLEntry) -> Vec<u8> {
        let unsigned = UnsignedEntry {
            id: &entry.id,
            service_id: &entry.service_id,
            policy_generation: entry.policy_generation,
            metadata: &entry.metadata,
        };

        serde_json::to_vec(&unsigned).expect("Entry serialization should never fail")
    }

    fn create_succession_message(
        &self,
        generation: u32,
        new_keys: &[ed25519_dalek::VerifyingKey; 2],
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(68);
        message.extend_from_slice(&generation.to_le_bytes());
        for key in new_keys {
            message.extend_from_slice(key.as_bytes());
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, SigningKey};
    use rand::{rngs::OsRng, RngCore};
    use time::OffsetDateTime;

    fn generate_test_keys() -> (SigningKeyPair, SigningKeyPair) {
        let mut rng = OsRng;
        let mut seed1 = [0u8; 32];
        let mut seed2 = [0u8; 32];
        rng.fill_bytes(&mut seed1);
        rng.fill_bytes(&mut seed2);

        let key1 = SigningKeyPair::new(SigningKey::from_bytes(&seed1));
        let key2 = SigningKeyPair::new(SigningKey::from_bytes(&seed2));
        (key1, key2)
    }

    fn create_test_admin_set(keys: &[SigningKeyPair; 2], timestamp: OffsetDateTime) -> AdminKeySet {
        AdminKeySet {
            active_keys: [keys[0].verifying_key, keys[1].verifying_key],
            policy_generation: 1,
            last_rotation: timestamp,
        }
    }

    #[test]
    fn test_validation_proof() {
        let proof_system = ProofSystem::new();
        let (key1, key2) = generate_test_keys();
        let admin_keys = [key1, key2];

        let fixed_time = OffsetDateTime::from_unix_timestamp(1640995200).unwrap();
        let admin_set = create_test_admin_set(&admin_keys, fixed_time);

        let metadata = crate::types::EntryMetadata {
            created_at: fixed_time,
            expires_at: None,
            version: 1,
            service_specific: serde_json::Value::Null,
        };

        let mut entry = ACLEntry {
            id: crate::types::EntryId::new([0; 32]),
            service_id: crate::types::ServiceId("test".into()),
            policy_generation: 1,
            metadata,
            signature: SerializableSignature(Signature::from_bytes(&[0; 64])),
        };

        entry.signature = proof_system.sign_entry(&entry, &admin_keys[0]).unwrap();

        let proof = proof_system
            .generate_validation_proof(&entry, &admin_set, None)
            .unwrap();

        assert!(proof_system
            .verify_validation_proof(&proof, &entry, &admin_set)
            .unwrap());

        let mut tampered_entry = entry.clone();
        tampered_entry.metadata.created_at += time::Duration::hours(1);
        tampered_entry.signature = proof_system.sign_entry(&entry, &admin_keys[0]).unwrap();
        assert!(!proof_system
            .verify_validation_proof(&proof, &tampered_entry, &admin_set)
            .unwrap());
    }

    #[test]
    fn test_succession() {
        let proof_system = ProofSystem::new();
        let (old_key1, old_key2) = generate_test_keys();
        let (new_key1, new_key2) = generate_test_keys();
        let old_keys = [old_key1, old_key2];

        let fixed_time = OffsetDateTime::from_unix_timestamp(1640995200).unwrap();
        let admin_set = create_test_admin_set(&old_keys, fixed_time);

        let request = SuccessionRequest {
            current_keys: old_keys,
            new_verifying_keys: [new_key1.verifying_key, new_key2.verifying_key],
            affected_entries: vec![],
        };

        let record = proof_system
            .process_succession(&request, &admin_set)
            .unwrap();

        assert!(proof_system.verify_succession(&record, &admin_set).unwrap());

        assert_eq!(record.timestamp, fixed_time);

        let mut tampered_record = record.clone();
        tampered_record.timestamp = fixed_time + time::Duration::hours(1);
        assert!(!proof_system
            .verify_succession(&tampered_record, &admin_set)
            .unwrap());
    }
}
