use crate::{
    crypto::{
        commitment::StateMatrixCommitment,
        primitives::{CurveGroups, G1},
        serialize::{IntoSerializable, SerializableG1},
    },
    errors::{Error, Result},
};
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
}

pub struct SparseMerkleTree {
    groups: Arc<CurveGroups>,
    nodes: DashMap<[u8; 32], G1>,
    proof_cache: DashMap<[u8; 32], MerkleProof>,
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
        if !value.is_on_curve() {
            return Err(Error::merkle_error(
                "Invalid input point",
                "Point must be on the curve",
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
                .unwrap_or(self.groups.g1_generator);

            if !sibling.is_on_curve() {
                return Err(Error::merkle_error(
                    "Invalid sibling point",
                    "Node contains invalid curve point",
                ));
            }

            siblings.push(sibling);

            current = if bit == 0 {
                self.hash_points(depth, &current, &sibling)?
            } else {
                self.hash_points(depth, &sibling, &current)?
            };

            path.push(current);
        }

        self.nodes.insert(key, value);

        let proof = MerkleProof {
            path: path.into_serializable(),
            siblings: siblings.into_serializable(),
            root: current.into(),
            value: value.into(),
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
        if !value.is_on_curve() || !proof.root.is_on_curve() {
            return Ok(false);
        }

        let mut current = *value;

        for (depth, sibling) in proof.siblings.iter().enumerate() {
            if !sibling.is_on_curve() {
                return Ok(false);
            }

            let bit = (key[depth / 8] >> (7 - (depth % 8))) & 1;
            current = if bit == 0 {
                self.hash_points(depth, &current, sibling)?
            } else {
                self.hash_points(depth, sibling, &current)?
            };
        }

        Ok(current == *proof.root)
    }

    pub fn batch_verify(&self, proofs: &[(G1, [u8; 32], MerkleProof)]) -> Result<Vec<bool>> {
        proofs
            .par_iter()
            .map(|(value, key, proof)| self.verify_proof(key, value, proof))
            .collect()
    }

    fn hash_points(&self, depth: usize, left: &G1, right: &G1) -> Result<G1> {
        let mut buf = Vec::with_capacity(128);

        left.serialize_compressed(&mut buf)
            .map_err(|e| Error::merkle_error("Serialization failed", e.to_string()))?;
        right
            .serialize_compressed(&mut buf)
            .map_err(|e| Error::merkle_error("Serialization failed", e.to_string()))?;

        let depth_bytes = depth.to_le_bytes();
        buf.extend_from_slice(&depth_bytes);

        self.groups.hash_to_g1(&buf)
    }

    fn compute_node_key(&self, key: &[u8; 32], depth: usize) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(key);
        hasher.update(&(depth as u64).to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn insert_state_commitment(
        &self,
        key: [u8; 32],
        commitment: StateMatrixCommitment,
    ) -> Result<MerkleProof> {
        self.insert(key, *commitment.value())
    }

    pub fn verify_state_commitment(
        &self,
        key: &[u8; 32],
        commitment: &StateMatrixCommitment,
        proof: &MerkleProof,
    ) -> Result<bool> {
        if !commitment.value().is_on_curve() {
            return Ok(false);
        }

        self.verify_proof(key, commitment.value(), proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::RandomGenerator;
    use std::time::Instant;

    #[test]
    fn test_parallel_insertions() {
        let groups = Arc::new(CurveGroups::new());
        let tree = SparseMerkleTree::new(Arc::clone(&groups));
        let rng = RandomGenerator::new();

        let entries: Vec<_> = (0..100)
            .map(|_| (rng.random_bytes(32).try_into().unwrap(), groups.random_g1()))
            .collect();

        let proofs = tree
            .batch_insert(&entries)
            .expect("Batch insert should succeed");

        // Verify all proofs
        let results = tree
            .batch_verify(
                &entries
                    .iter()
                    .zip(proofs.iter())
                    .map(|((key, value), proof)| (*value, *key, proof.clone()))
                    .collect::<Vec<_>>(),
            )
            .expect("Batch verification should succeed");

        assert!(
            results.iter().all(|&r| r),
            "All verifications should succeed"
        );
    }

    #[test]
    fn test_parallel_performance() {
        let rng = RandomGenerator::new();
        let operation_count = 1000;

        // Sequential insertions with fresh tree
        let groups = Arc::new(CurveGroups::new());
        let sequential_tree = SparseMerkleTree::new(Arc::clone(&groups));
        let start = Instant::now();
        for _ in 0..operation_count {
            let key = rng.random_bytes(32).try_into().unwrap();
            let value = groups.random_g1();
            sequential_tree
                .insert(key, value)
                .expect("Insert should succeed");
        }
        let sequential_duration = start.elapsed();

        // Parallel insertions with fresh tree
        let parallel_tree = SparseMerkleTree::new(Arc::clone(&groups));
        let entries: Vec<_> = (0..operation_count)
            .map(|_| (rng.random_bytes(32).try_into().unwrap(), groups.random_g1()))
            .collect();

        let start = Instant::now();
        parallel_tree
            .batch_insert(&entries)
            .expect("Batch insert should succeed");
        let parallel_duration = start.elapsed();

        println!(
            "Sequential time ({} ops): {:?}",
            operation_count, sequential_duration
        );
        println!(
            "Parallel time ({} ops): {:?}",
            operation_count, parallel_duration
        );

        assert!(
            parallel_duration < sequential_duration / 2,
            "Parallel execution should be at least 2x faster\nSequential: {:?}\nParallel: {:?}",
            sequential_duration,
            parallel_duration
        );
    }
}
