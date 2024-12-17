use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::Verifier;
use merlin::Transcript;
use rayon::prelude::*;
use serde::Serialize;

use crate::errors::{Error, Result};
use crate::types::{
    ACLEntry, AdminKeySet, EntryId, SerializableSignature, SigningKeyPair, SuccessionRecord,
    ValidationProof,
};

const TRANSCRIPT_LABEL: &[u8] = b"theseus-validation-v1";

#[derive(Serialize)]
struct UnsignedEntry<'a> {
    id: &'a EntryId,
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
        admin: &AdminKeySet,
        succession: Option<&SuccessionRecord>,
    ) -> Result<ValidationProof> {
        let mut transcript = self.create_initial_transcript();

        transcript.append_message(b"entry-id", &entry.id.0);
        transcript.append_message(b"policy-gen", &entry.policy_generation.to_le_bytes());
        transcript.append_message(b"admin-gen", &admin.policy_generation.to_le_bytes());

        for key in &admin.active_keys {
            transcript.append_message(b"admin-key", key.as_bytes());
        }

        if let Some(succ) = succession {
            self.append_succession_data(&mut transcript, succ);
        }

        let v_blinding = Scalar::random(&mut rand::thread_rng());
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

    pub fn batch_verify(
        &self,
        entries: &[ACLEntry],
        proofs: &[ValidationProof],
        admin: &AdminKeySet,
    ) -> Result<Vec<bool>> {
        if entries.len() != proofs.len() {
            return Err(Error::invalid_proof(
                "Batch verification failed",
                "Mismatched entry and proof counts",
            ));
        }

        entries
            .par_iter()
            .zip(proofs)
            .map(|(entry, proof)| self.verify_validation_proof(proof, entry, admin))
            .collect()
    }

    pub fn verify_validation_proof(
        &self,
        proof: &ValidationProof,
        entry: &ACLEntry,
        admin: &AdminKeySet,
    ) -> Result<bool> {
        if !self.verify_entry_signature(entry, admin)? {
            return Ok(false);
        }

        let mut transcript = self.create_initial_transcript();

        transcript.append_message(b"entry-id", &entry.id.0);
        transcript.append_message(b"policy-gen", &entry.policy_generation.to_le_bytes());
        transcript.append_message(b"admin-gen", &admin.policy_generation.to_le_bytes());

        for key in &admin.active_keys {
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

    pub fn verify_entry_signature(&self, entry: &ACLEntry, admin: &AdminKeySet) -> Result<bool> {
        let message = self.create_entry_message(entry);
        Ok(admin
            .active_keys
            .iter()
            .any(|key| key.verify(&message, &entry.signature.0).is_ok()))
    }

    pub fn batch_verify_succession(
        &self,
        records: &[SuccessionRecord],
        admin: &AdminKeySet,
    ) -> Result<Vec<bool>> {
        records
            .par_iter()
            .map(|record| self.verify_succession_record(record, admin))
            .collect()
    }

    pub fn verify_succession_record(
        &self,
        succession: &SuccessionRecord,
        admin: &AdminKeySet,
    ) -> Result<bool> {
        if succession.old_keys != admin.active_keys
            || succession.generation != admin.policy_generation + 1
            || succession.timestamp != admin.last_rotation
        {
            return Ok(false);
        }

        let message = self.create_succession_message(admin.policy_generation, &succession.new_keys);
        Ok(succession
            .signatures
            .iter()
            .zip(&admin.active_keys)
            .all(|(sig, key)| key.verify(&message, &sig.0).is_ok()))
    }

    pub fn sign_succession(
        &self,
        admin_gen: u32,
        new_keys: &[ed25519_dalek::VerifyingKey; 2],
        key_pair: &SigningKeyPair,
    ) -> Result<SerializableSignature> {
        let message = self.create_succession_message(admin_gen, new_keys);
        Ok(key_pair.sign(&message))
    }

    pub fn sign_entry(
        &self,
        entry: &ACLEntry,
        key_pair: &SigningKeyPair,
    ) -> Result<SerializableSignature> {
        let message = self.create_entry_message(entry);
        Ok(key_pair.sign(&message))
    }

    pub fn create_succession_message(
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

    pub fn create_entry_message(&self, entry: &ACLEntry) -> Vec<u8> {
        let unsigned = UnsignedEntry {
            id: &entry.id,
            service_id: &entry.service_id,
            policy_generation: entry.policy_generation,
            metadata: &entry.metadata,
        };

        serde_json::to_vec(&unsigned).expect("Entry serialization should never fail")
    }

    fn create_initial_transcript(&self) -> Transcript {
        Transcript::new(TRANSCRIPT_LABEL)
    }

    fn append_succession_data(&self, transcript: &mut Transcript, succession: &SuccessionRecord) {
        transcript.append_message(b"succession-gen", &succession.generation.to_le_bytes());
        for key in &succession.old_keys {
            transcript.append_message(b"old-key", key.as_bytes());
        }
        for key in &succession.new_keys {
            transcript.append_message(b"new-key", key.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EntryMetadata, ServiceId};
    use ed25519_dalek::SigningKey;
    use rand::{thread_rng, RngCore};
    use time::OffsetDateTime;

    fn create_test_keypair() -> SigningKeyPair {
        let mut rng = thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        SigningKeyPair::new(SigningKey::from_bytes(&seed))
    }

    fn create_test_admin(key_pair: &SigningKeyPair) -> AdminKeySet {
        AdminKeySet {
            active_keys: [key_pair.verifying_key; 2],
            policy_generation: 1,
            last_rotation: OffsetDateTime::now_utc(),
        }
    }

    fn create_test_entry(policy_gen: u32) -> ACLEntry {
        ACLEntry {
            id: EntryId::new([1u8; 32]),
            service_id: ServiceId("test".into()),
            policy_generation: policy_gen,
            metadata: EntryMetadata {
                created_at: OffsetDateTime::now_utc(),
                expires_at: None,
                version: 1,
                service_specific: serde_json::Value::Null,
            },
            signature: SerializableSignature(ed25519_dalek::Signature::from_bytes(&[0; 64])),
        }
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let proof_system = ProofSystem::new();
        let key_pair = create_test_keypair();
        let admin = create_test_admin(&key_pair);
        let mut entry = create_test_entry(1);

        entry.signature = proof_system.sign_entry(&entry, &key_pair).unwrap();

        let proof = proof_system
            .generate_validation_proof(&entry, &admin, None)
            .unwrap();
        assert!(proof_system
            .verify_validation_proof(&proof, &entry, &admin)
            .unwrap());
    }

    #[test]
    fn test_batch_verification() {
        let proof_system = ProofSystem::new();
        let key_pair = create_test_keypair();
        let admin = create_test_admin(&key_pair);

        let mut entries = Vec::new();
        let mut proofs = Vec::new();

        for _ in 0..5 {
            let mut entry = create_test_entry(1);
            entry.signature = proof_system.sign_entry(&entry, &key_pair).unwrap();
            let proof = proof_system
                .generate_validation_proof(&entry, &admin, None)
                .unwrap();
            entries.push(entry);
            proofs.push(proof);
        }

        let results = proof_system
            .batch_verify(&entries, &proofs, &admin)
            .unwrap();
        assert!(results.iter().all(|&r| r));
    }

    #[test]
    fn test_succession_verification() {
        let proof_system = ProofSystem::new();
        let key_pair = create_test_keypair();
        let admin = create_test_admin(&key_pair);

        let succession = SuccessionRecord {
            old_keys: admin.active_keys,
            new_keys: admin.active_keys,
            generation: admin.policy_generation + 1,
            timestamp: admin.last_rotation,
            affected_entries: vec![EntryId::new([1u8; 32])],
            signatures: [
                proof_system
                    .sign_succession(admin.policy_generation, &admin.active_keys, &key_pair)
                    .unwrap(),
                proof_system
                    .sign_succession(admin.policy_generation, &admin.active_keys, &key_pair)
                    .unwrap(),
            ],
            request_metadata: None,
        };

        assert!(proof_system
            .verify_succession_record(&succession, &admin)
            .unwrap());
    }

    #[test]
    fn test_invalid_succession() {
        let proof_system = ProofSystem::new();
        let key_pair = create_test_keypair();
        let admin = create_test_admin(&key_pair);

        // Create succession with wrong generation
        let invalid_succession = SuccessionRecord {
            old_keys: admin.active_keys,
            new_keys: admin.active_keys,
            generation: admin.policy_generation + 2,
            timestamp: admin.last_rotation,
            affected_entries: vec![EntryId::new([1u8; 32])],
            signatures: [
                proof_system
                    .sign_succession(admin.policy_generation, &admin.active_keys, &key_pair)
                    .unwrap(),
                proof_system
                    .sign_succession(admin.policy_generation, &admin.active_keys, &key_pair)
                    .unwrap(),
            ],
            request_metadata: None,
        };

        assert!(!proof_system
            .verify_succession_record(&invalid_succession, &admin)
            .unwrap());
    }

    #[test]
    fn test_batch_succession_verification() {
        let proof_system = ProofSystem::new();
        let key_pair = create_test_keypair();
        let admin = create_test_admin(&key_pair);

        let mut records = Vec::new();
        for i in 1..=3 {
            let record = SuccessionRecord {
                old_keys: admin.active_keys,
                new_keys: admin.active_keys,
                generation: admin.policy_generation + i,
                timestamp: admin.last_rotation,
                affected_entries: vec![EntryId::new([1u8; 32])],
                signatures: [
                    proof_system
                        .sign_succession(admin.policy_generation, &admin.active_keys, &key_pair)
                        .unwrap(),
                    proof_system
                        .sign_succession(admin.policy_generation, &admin.active_keys, &key_pair)
                        .unwrap(),
                ],
                request_metadata: None,
            };
            records.push(record);
        }

        // Only first succession should be valid since generations must increment by 1
        let results = proof_system
            .batch_verify_succession(&records, &admin)
            .unwrap();
        assert_eq!(results, vec![true, false, false]);
    }

    #[test]
    fn test_parallel_performance() {
        let proof_system = ProofSystem::new();
        let key_pair = create_test_keypair();
        let admin = create_test_admin(&key_pair);

        let mut entries = Vec::new();
        let mut proofs = Vec::new();

        for _ in 0..100 {
            let mut entry = create_test_entry(1);
            entry.signature = proof_system.sign_entry(&entry, &key_pair).unwrap();
            let proof = proof_system
                .generate_validation_proof(&entry, &admin, None)
                .unwrap();
            entries.push(entry);
            proofs.push(proof);
        }

        let start = std::time::Instant::now();
        let parallel_results = proof_system
            .batch_verify(&entries, &proofs, &admin)
            .unwrap();
        let parallel_duration = start.elapsed();

        let start = std::time::Instant::now();
        let sequential_results: Vec<bool> = entries
            .iter()
            .zip(&proofs)
            .map(|(entry, proof)| {
                proof_system
                    .verify_validation_proof(proof, entry, &admin)
                    .unwrap()
            })
            .collect();
        let sequential_duration = start.elapsed();

        assert_eq!(parallel_results, sequential_results);

        assert!(parallel_duration < sequential_duration / 2);
    }
}
