use crate::{
    crypto::{
        primitives::{CurveGroups, DomainSeparationTags, G1},
        serialize::{IntoSerializable, SerializableG1},
        PedersenCommitment, ProofTranscript, StateMatrixCommitment,
    },
    errors::{Error, Result},
};
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub path: Vec<SerializableG1>,
    pub siblings: Vec<SerializableG1>,
    pub root: SerializableG1,
    pub value: SerializableG1,
    pub transcript_binding: Vec<u8>,
}

pub struct SparseMerkleTree {
    groups: Arc<CurveGroups>,
    nodes: DashMap<[u8; 32], G1>,
    proof_cache: DashMap<[u8; 32], MerkleProof>,
}

#[derive(Clone)]
pub struct BatchVerifyItem {
    pub key: [u8; 32],
    pub value: G1,
    pub proof: MerkleProof,
}

impl SparseMerkleTree {
    pub fn new(groups: Arc<CurveGroups>) -> Self {
        Self {
            groups,
            nodes: DashMap::new(),
            proof_cache: DashMap::new(),
        }
    }

    pub fn insert(&self, key: [u8; 32], value: G1) -> Result<MerkleProof> {
        if value.is_zero() || !value.is_on_curve() {
            return Err(Error::merkle_error(
                "Invalid input point",
                "Point must be non-zero and on the curve",
            ));
        }

        let mut path = Vec::with_capacity(256);
        let mut siblings = Vec::with_capacity(256);
        let mut current = value;

        for depth in 0..256 {
            let bit = (key[depth / 8] >> (7 - (depth % 8))) & 1;
            let node_key = self.compute_node_key(&key, depth);

            let sibling = self
                .nodes
                .get(&node_key)
                .map(|v| *v.value())
                .unwrap_or_else(|| self.compute_default_node(depth));

            siblings.push(sibling);

            current = if bit == 0 {
                self.hash_nodes(depth, &current, &sibling)?
            } else {
                self.hash_nodes(depth, &sibling, &current)?
            };

            path.push(current);
        }

        self.nodes.insert(key, value);

        let proof = MerkleProof {
            path: path.into_serializable(),
            siblings: siblings.into_serializable(),
            root: current.into(),
            value: value.into(),
            transcript_binding: Vec::new(),
        };

        self.proof_cache.insert(key, proof.clone());
        Ok(proof)
    }

    pub fn batch_insert(&self, entries: &[([u8; 32], G1)]) -> Result<Vec<MerkleProof>> {
        entries
            .par_iter()
            .map(|(key, value)| self.insert(*key, *value))
            .collect()
    }

    pub fn verify_proof(&self, key: &[u8; 32], value: &G1, proof: &MerkleProof) -> Result<bool> {
        let mut current = *value;

        for (depth, sibling) in proof.siblings.iter().enumerate() {
            if !sibling.is_on_curve() {
                return Ok(false);
            }

            let bit = (key[depth / 8] >> (7 - (depth % 8))) & 1;
            current = if bit == 0 {
                self.hash_nodes(depth, &current, sibling.inner())?
            } else {
                self.hash_nodes(depth, sibling.inner(), &current)?
            };

            if current != *proof.path[depth].inner() {
                return Ok(false);
            }
        }

        Ok(current == *proof.root.inner())
    }

    pub fn verify_batch(&self, items: &[BatchVerifyItem]) -> Result<Vec<bool>> {
        items
            .par_iter()
            .map(|item| self.verify_proof(&item.key, &item.value, &item.proof))
            .collect()
    }

    pub fn insert_state_commitment(
        &self,
        key: [u8; 32],
        commitment: StateMatrixCommitment,
        transcript: &mut ProofTranscript,
    ) -> Result<MerkleProof> {
        let mut proof = self.insert(key, *commitment.value())?;

        let binding_scalar = transcript.challenge_scalar(b"merkle-binding");
        let mut binding = Vec::new();
        binding_scalar
            .serialize_compressed(&mut binding)
            .expect("Serialization cannot fail");

        proof.transcript_binding = binding;
        Ok(proof)
    }

    pub fn verify_state_commitment(
        &self,
        key: &[u8; 32],
        commitment: &StateMatrixCommitment,
        proof: &MerkleProof,
    ) -> Result<bool> {
        let mut pedersen = PedersenCommitment::new(*self.groups);
        let mut transcript =
            ProofTranscript::new(DomainSeparationTags::COMMITMENT, Arc::clone(&self.groups));

        if !pedersen.verify_state_commitment(commitment, &mut transcript)? {
            return Ok(false);
        }

        self.verify_proof(key, commitment.value(), proof)
    }

    pub fn batch_verify_state(
        &self,
        items: &[(StateMatrixCommitment, [u8; 32], MerkleProof)],
    ) -> Result<Vec<bool>> {
        items
            .par_iter()
            .map(|(commitment, key, proof)| self.verify_state_commitment(key, commitment, proof))
            .collect()
    }

    fn hash_nodes(&self, depth: usize, left: &G1, right: &G1) -> Result<G1> {
        let mut buf = Vec::with_capacity(128);

        left.serialize_compressed(&mut buf)?;
        right.serialize_compressed(&mut buf)?;
        buf.extend_from_slice(&depth.to_le_bytes());

        self.groups.hash_to_g1(&buf)
    }

    pub fn compute_node_key(&self, key: &[u8; 32], depth: usize) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DomainSeparationTags::MERKLE_NODE);
        hasher.update(key);
        hasher.update(&(depth as u64).to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn compute_default_node(&self, depth: usize) -> G1 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DomainSeparationTags::MERKLE_NODE);
        hasher.update(&depth.to_le_bytes());
        self.groups
            .hash_to_g1(hasher.finalize().as_bytes())
            .expect("Default node computation should not fail")
    }

    pub fn compute_parent_hash(
        &self,
        left: &G1,
        right: &G1,
        depth: usize,
        transcript: &mut ProofTranscript,
    ) -> Result<G1> {
        let mut buf = Vec::with_capacity(256);
        transcript.append_point_g1(DomainSeparationTags::MERKLE_NODE, left);
        transcript.append_point_g1(DomainSeparationTags::MERKLE_NODE, right);
        transcript.append_message(b"depth", &depth.to_le_bytes());

        let binding_scalar = transcript.challenge_scalar(b"merkle-node-binding");
        let mut binding = Vec::new();
        binding_scalar
            .serialize_compressed(&mut binding)
            .expect("Serialization cannot fail");

        left.serialize_compressed(&mut buf)?;
        right.serialize_compressed(&mut buf)?;
        buf.extend_from_slice(&binding);

        self.groups.hash_to_g1(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        commitment::StateMatrixEntry, primitives::RandomGenerator, PedersenCommitment,
        ProofTranscript,
    };
    use std::time::Instant;

    fn setup_test_tree() -> SparseMerkleTree {
        let groups = Arc::new(CurveGroups::new());
        SparseMerkleTree::new(Arc::clone(&groups))
    }

    #[test]
    fn test_basic_tree_operations() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();
        let value = tree.groups.random_g1();
        let key = rng.random_bytes(32).try_into().unwrap();

        let proof = tree.insert(key, value).unwrap();
        assert!(tree.verify_proof(&key, &value, &proof).unwrap());
    }

    #[test]
    fn test_invalid_input() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();
        let key = rng.random_bytes(32).try_into().unwrap();
        let value = G1::zero();

        assert!(tree.insert(key, value).is_err());
    }

    #[test]
    fn test_parallel_insertions() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();

        let entries: Vec<_> = (0..100)
            .map(|_| {
                (
                    rng.random_bytes(32).try_into().unwrap(),
                    tree.groups.random_g1(),
                )
            })
            .collect();

        let proofs = tree.batch_insert(&entries).unwrap();

        let verify_items: Vec<BatchVerifyItem> = entries
            .iter()
            .zip(proofs.iter())
            .map(|((key, value), proof)| BatchVerifyItem {
                key: *key,
                value: *value,
                proof: proof.clone(),
            })
            .collect();

        let results = tree.verify_batch(&verify_items).unwrap();
        assert!(results.iter().all(|&r| r));
    }

    #[test]
    fn test_performance() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();
        let operation_count = 1000;

        // Sequential
        let start = Instant::now();
        for _ in 0..operation_count {
            let key = rng.random_bytes(32).try_into().unwrap();
            let value = tree.groups.random_g1();
            tree.insert(key, value).unwrap();
        }
        let sequential_time = start.elapsed();

        // Parallel
        let entries: Vec<_> = (0..operation_count)
            .map(|_| {
                (
                    rng.random_bytes(32).try_into().unwrap(),
                    tree.groups.random_g1(),
                )
            })
            .collect();

        let start = Instant::now();
        tree.batch_insert(&entries).unwrap();
        let parallel_time = start.elapsed();

        assert!(
            parallel_time < sequential_time / 2,
            "Parallel operations should be at least 2x faster"
        );
    }

    #[test]
    fn test_node_hashing() {
        let tree = setup_test_tree();
        let value1 = tree.groups.random_g1();
        let value2 = tree.groups.random_g1();

        let hash = tree.hash_nodes(0, &value1, &value2).unwrap();
        assert!(hash.is_on_curve());

        let hash2 = tree.hash_nodes(0, &value1, &value2).unwrap();
        assert_eq!(hash, hash2, "Node hashing should be deterministic");
    }

    #[test]
    fn test_sibling_computation() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();
        let key: &[u8; 32] = &rng.random_bytes(32).try_into().unwrap();

        let mut sibling_key = *key;
        let depth: usize = 0;
        sibling_key[depth / 8] ^= 1 << (7 - (depth % 8));

        assert_ne!(key, &sibling_key, "Sibling key should be different");

        let depth = 0;
        let default_node = tree.compute_default_node(depth);
        assert!(default_node.is_on_curve());
    }

    #[test]
    fn test_proof_verification_failure() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();
        let key = rng.random_bytes(32).try_into().unwrap();
        let value = tree.groups.random_g1();

        let mut proof = tree.insert(key, value).unwrap();
        proof.root = tree.groups.random_g1().into();

        assert!(!tree.verify_proof(&key, &value, &proof).unwrap());
    }

    #[test]
    fn test_tree_consistency() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();

        let mut known_entries = Vec::new();
        for _ in 0..10 {
            let key = rng.random_bytes(32).try_into().unwrap();
            let value = tree.groups.random_g1();
            let proof = tree.insert(key, value).unwrap();
            known_entries.push((key, value, proof));
        }

        for (key, value, proof) in known_entries {
            assert!(tree.verify_proof(&key, &value, &proof).unwrap());
        }
    }

    #[test]
    fn test_proof_cache() {
        let tree = setup_test_tree();
        let rng = RandomGenerator::new();
        let key = rng.random_bytes(32).try_into().unwrap();
        let value = tree.groups.random_g1();

        tree.insert(key, value).unwrap();
        let cached_value = tree.nodes.get(&key).unwrap();
        assert_eq!(*cached_value.value(), value);
    }

    #[test]
    fn test_state_commitment_verification() {
        let groups = Arc::new(CurveGroups::new());
        let tree = SparseMerkleTree::new(Arc::clone(&groups));
        let mut transcript =
            ProofTranscript::new(DomainSeparationTags::COMMITMENT, Arc::clone(&groups));
        let rng = RandomGenerator::new();

        let entry = StateMatrixEntry::new(
            rng.random_bytes(32).try_into().expect("Valid test bytes"),
            rng.random_bytes(32).try_into().expect("Valid test bytes"),
            1,
            vec![1, 2, 3],
            1,
            42,
            vec![],
        );

        let blinding = rng.random_scalar();
        let mut pedersen = PedersenCommitment::new(*groups);

        // Create commitment using transcript
        let commitment = pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .expect("Valid commitment");

        let key = rng.random_bytes(32).try_into().expect("Valid test bytes");

        // Insert with transcript state
        let proof = tree
            .insert_state_commitment(key, commitment.clone(), &mut transcript)
            .expect("Valid insertion");

        assert!(tree
            .verify_state_commitment(&key, &commitment, &proof)
            .expect("Valid verification"));
    }

    #[test]
    fn test_invalid_commitment() {
        let groups = Arc::new(CurveGroups::new());
        let tree = SparseMerkleTree::new(Arc::clone(&groups));
        let rng = RandomGenerator::new();

        // Create first entry and commitment
        let entry = StateMatrixEntry::new(
            rng.random_bytes(32).try_into().expect("Valid test bytes"),
            rng.random_bytes(32).try_into().expect("Valid test bytes"),
            1,
            vec![1, 2, 3],
            1,
            42,
            vec![],
        );

        let blinding = rng.random_scalar();
        let mut pedersen = PedersenCommitment::new(*groups);
        let mut transcript =
            ProofTranscript::new(DomainSeparationTags::COMMITMENT, Arc::clone(&groups));

        let commitment = pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .expect("Valid commitment");

        let key = rng.random_bytes(32).try_into().expect("Valid test bytes");
        let proof = tree
            .insert_state_commitment(key, commitment.clone(), &mut transcript)
            .expect("Valid insertion");

        // Create different entry with same key but different access level
        let different_entry = StateMatrixEntry::new(
            *commitment.data().user_id(),
            *commitment.data().service_id(),
            999,
            commitment.data().required_attrs().to_vec(),
            commitment.data().policy_generation(),
            42,
            vec![],
        );

        let different_commitment = pedersen
            .commit_state_entry(different_entry, &blinding, &mut transcript)
            .expect("Valid commitment");

        assert!(!tree
            .verify_state_commitment(&key, &different_commitment, &proof)
            .expect("Valid verification"));
    }
}
