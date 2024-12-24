use crate::{
    crypto::{
        primitives::{CurveGroups, DomainSeparationTags, ProofTranscript, Scalar, G1},
        signatures::{AggregateSignature, BlsSignature},
    },
    errors::{Error, Result},
};
use ark_ec::CurveGroup;
use serde::{Deserialize, Serialize};

pub struct PedersenCommitment {
    groups: CurveGroups,
    g: G1,
    h: G1,
}

#[derive(Clone)]
pub struct StateMatrixCommitment {
    value: G1,
    blinding: Scalar,
    data: StateMatrixEntry,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateMatrixEntry {
    user_id: [u8; 32],
    service_id: [u8; 32],
    access_level: u32,
    required_attrs: Vec<u8>,
    policy_generation: u32,
    admin_keys: [[u8; 32]; 2],
    revocation_status: Option<RevocationStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RevocationStatus {
    timestamp: time::OffsetDateTime,
    admin_signature: AggregateSignature,
    metadata: Option<serde_json::Value>,
    #[serde(skip)]
    commitment: G1,
}

impl PedersenCommitment {
    pub fn new(groups: CurveGroups) -> Self {
        let g = groups.g1_generator;
        let h = groups
            .hash_to_g1(b"pedersen-blinding-base")
            .expect("Hash to curve should not fail with fixed input");

        Self { groups, g, h }
    }

    pub fn commit_state_entry(
        &mut self,
        entry: StateMatrixEntry,
        blinding: &Scalar,
        transcript: &mut ProofTranscript,
    ) -> Result<StateMatrixCommitment> {
        let serialized = serde_json::to_vec(&entry)
            .map_err(|e| Error::commitment_error("Failed to serialize entry", e.to_string()))?;

        transcript.append_message(DomainSeparationTags::COMMITMENT, &serialized);
        transcript.append_point(b"pedersen-g", &self.g);
        transcript.append_point(b"pedersen-h", &self.h);

        let value_point = self.groups.hash_to_g1(&serialized)?;

        let commitment = (value_point + self.h * blinding).into_affine();

        Ok(StateMatrixCommitment {
            value: commitment,
            blinding: *blinding,
            data: entry,
        })
    }

    pub fn verify_state_commitment(
        &mut self,
        commitment: &StateMatrixCommitment,
        transcript: &mut ProofTranscript,
    ) -> Result<bool> {
        let serialized = serde_json::to_vec(&commitment.data)
            .map_err(|e| Error::commitment_error("Failed to serialize entry", e.to_string()))?;

        transcript.append_message(DomainSeparationTags::COMMITMENT, &serialized);
        transcript.append_point(b"pedersen-g", &self.g);
        transcript.append_point(b"pedersen-h", &self.h);

        let value_point = self.groups.hash_to_g1(&serialized)?;

        let expected = (value_point + self.h * commitment.blinding).into_affine();

        Ok(commitment.value == expected)
    }
}

impl StateMatrixCommitment {
    pub fn value(&self) -> &G1 {
        &self.value
    }

    pub fn blinding(&self) -> &Scalar {
        &self.blinding
    }

    pub fn data(&self) -> &StateMatrixEntry {
        &self.data
    }

    pub fn revoke(
        &mut self,
        admin_signatures: Vec<BlsSignature>,
        metadata: Option<serde_json::Value>,
        groups: &CurveGroups,
    ) -> Result<()> {
        let aggregate = AggregateSignature::aggregate(&admin_signatures)?;

        let mut transcript = ProofTranscript::new(DomainSeparationTags::REVOCATION);
        let data = (&aggregate, &metadata);
        let serialized = serde_json::to_vec(&data).map_err(|e| {
            Error::commitment_error("Failed to serialize revocation", e.to_string())
        })?;
        transcript.append_message(DomainSeparationTags::REVOCATION, &serialized);
        let commitment = groups.hash_to_g1(&serialized)?;

        self.data.revocation_status = Some(RevocationStatus {
            timestamp: time::OffsetDateTime::now_utc(),
            admin_signature: aggregate,
            metadata,
            commitment,
        });

        Ok(())
    }

    pub fn is_revoked(&self) -> bool {
        self.data.revocation_status.is_some()
    }

    pub fn get_revocation_data(&self) -> G1 {
        match &self.data.revocation_status {
            Some(status) => status.commitment,
            None => self.value,
        }
    }
}

impl StateMatrixEntry {
    pub fn new(
        user_id: [u8; 32],
        service_id: [u8; 32],
        access_level: u32,
        required_attrs: Vec<u8>,
        policy_generation: u32,
        admin_keys: [[u8; 32]; 2],
    ) -> Self {
        Self {
            user_id,
            service_id,
            access_level,
            required_attrs,
            policy_generation,
            admin_keys,
            revocation_status: None,
        }
    }

    pub fn user_id(&self) -> &[u8; 32] {
        &self.user_id
    }

    pub fn service_id(&self) -> &[u8; 32] {
        &self.service_id
    }

    pub fn access_level(&self) -> u32 {
        self.access_level
    }

    pub fn required_attrs(&self) -> &[u8] {
        &self.required_attrs
    }

    pub fn policy_generation(&self) -> u32 {
        self.policy_generation
    }

    pub fn admin_keys(&self) -> &[[u8; 32]; 2] {
        &self.admin_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{primitives::RandomGenerator, SparseMerkleTree};
    use serde_json::json;
    use std::sync::Arc;

    fn create_test_commitment(groups: &Arc<CurveGroups>) -> StateMatrixCommitment {
        let mut pedersen = PedersenCommitment::new((**groups).clone());
        let rng = RandomGenerator::new();
        let entry = StateMatrixEntry::new(
            [1u8; 32],
            [2u8; 32],
            1,
            vec![1, 2, 3],
            1,
            [[3u8; 32], [4u8; 32]],
        );
        let mut transcript = ProofTranscript::new(DomainSeparationTags::COMMITMENT);
        pedersen
            .commit_state_entry(entry, &rng.random_scalar(), &mut transcript)
            .unwrap()
    }

    #[test]
    fn test_state_matrix() {
        let groups = Arc::new(CurveGroups::new());
        let tree = SparseMerkleTree::new(Arc::clone(&groups));
        let mut pedersen = PedersenCommitment::new((*groups).clone());
        let mut transcript = ProofTranscript::new(DomainSeparationTags::COMMITMENT);
        let rng = RandomGenerator::new();

        let entry = StateMatrixEntry {
            user_id: [1u8; 32],
            service_id: [2u8; 32],
            access_level: 1,
            required_attrs: vec![1, 2, 3],
            policy_generation: 1,
            admin_keys: [[3u8; 32], [4u8; 32]],
            revocation_status: None,
        };

        let blinding = rng.random_scalar();
        let commitment = pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .unwrap();

        let key = [5u8; 32];
        let proof = tree
            .insert_state_commitment(key, commitment.clone())
            .unwrap();

        assert!(tree
            .verify_state_commitment(&key, &commitment, &proof)
            .unwrap());
        assert!(pedersen
            .verify_state_commitment(&commitment, &mut transcript)
            .unwrap());
    }

    #[test]
    fn test_revocation() {
        let groups = Arc::new(CurveGroups::new());
        let rng = RandomGenerator::new();
        let mut pedersen = PedersenCommitment::new((*groups).clone());
        let mut transcript = ProofTranscript::new(DomainSeparationTags::COMMITMENT);

        let entry = StateMatrixEntry::new(
            [1u8; 32],
            [2u8; 32],
            1,
            vec![1, 2, 3],
            1,
            [[3u8; 32], [4u8; 32]],
        );

        let blinding = rng.random_scalar();
        let mut commitment = pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .expect("Failed to create commitment");

        // Initially not revoked - should return commitment value
        let unrevoked_data = commitment.value;
        assert!(!commitment.is_revoked());
        assert_eq!(commitment.get_revocation_data(), unrevoked_data);

        // Create and apply revocation
        let secret_key = rng.random_scalar();
        let signature = BlsSignature::sign(b"revoke", &secret_key, &groups).unwrap();
        commitment
            .revoke(vec![signature], Some(json!({"reason": "test"})), &groups)
            .unwrap();

        // After revocation - should return different value
        assert!(commitment.is_revoked());
        assert_ne!(commitment.get_revocation_data(), unrevoked_data);
    }

    #[test]
    fn test_revocation_serialization() {
        let groups = Arc::new(CurveGroups::new());
        let rng = RandomGenerator::new();
        let mut commitment = create_test_commitment(&groups);

        // Create BLS signature
        let secret_key = rng.random_scalar();
        let message = b"test";
        let signature = BlsSignature::sign(message, &secret_key, &groups).unwrap();

        // Revoke and serialize
        commitment.revoke(vec![signature], None, &groups).unwrap();
        let serialized = serde_json::to_vec(&commitment.data).unwrap();
        let deserialized: StateMatrixEntry = serde_json::from_slice(&serialized).unwrap();

        // Revocation status should persist
        assert!(deserialized.revocation_status.is_some());
    }
}
