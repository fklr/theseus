use std::sync::Arc;
use theseus::crypto::{
    circuits::Circuit,
    commitment::{PedersenCommitment, StateMatrixCommitment, StateMatrixEntry},
    merkle::SparseMerkleTree,
    primitives::{CurveGroups, DomainSeparationTags, ProofTranscript, RandomGenerator},
    proofs::ProofSystem,
    signatures::{AggregateSignature, BlsSignature, SignedStateCommitment},
};
use theseus::errors::Result;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use serde_json::json;
    use std::time::Instant;

    struct TestSystem {
        groups: Arc<CurveGroups>,
        merkle_tree: SparseMerkleTree,
        proof_system: ProofSystem,
        pedersen: PedersenCommitment,
        rng: RandomGenerator,
    }

    impl TestSystem {
        fn new() -> Self {
            let groups = Arc::new(CurveGroups::new());
            let merkle_tree = SparseMerkleTree::new(Arc::clone(&groups));
            let proof_system = ProofSystem::new(Arc::clone(&groups));
            let pedersen = PedersenCommitment::new((*groups).clone());
            let rng = RandomGenerator::new();

            Self {
                groups,
                merkle_tree,
                proof_system,
                pedersen,
                rng,
            }
        }

        fn create_test_commitment(&mut self) -> Result<StateMatrixCommitment> {
            let entry = StateMatrixEntry::new(
                [1u8; 32],
                [2u8; 32],
                1,
                vec![1, 2, 3],
                1,
                [[3u8; 32], [4u8; 32]],
            );
            let mut transcript = ProofTranscript::new(DomainSeparationTags::COMMITMENT);
            let blinding = self.rng.random_scalar();
            self.pedersen
                .commit_state_entry(entry, &blinding, &mut transcript)
        }

        fn generate_admin_signatures(
            &self,
            commitment: &StateMatrixCommitment,
            count: usize,
        ) -> Vec<BlsSignature> {
            let message = serde_json::to_vec(commitment.data()).unwrap();
            (0..count)
                .map(|_| {
                    let secret_key = self.rng.random_scalar();
                    BlsSignature::sign(&message, &secret_key, &self.groups).unwrap()
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn test_complete_access_workflow() -> Result<()> {
        let mut system = TestSystem::new();
        let commitment = system.create_test_commitment()?;
        let signatures = system.generate_admin_signatures(&commitment, 3);

        let signed_commitment =
            SignedStateCommitment::new(commitment.clone(), signatures, &system.groups)?;

        let merkle_proof = system.merkle_tree.insert_state_commitment(
            *signed_commitment.commitment().data().user_id(),
            signed_commitment.commitment().clone(),
        )?;

        let mut circuit = Circuit::new(Arc::clone(&system.groups));

        circuit.verify_access_grant(
            signed_commitment.commitment(),
            &merkle_proof,
            signed_commitment.aggregate_signature(),
        )?;

        let proof = system.proof_system.prove(&circuit)?;
        assert!(system.proof_system.verify(&circuit, &proof)?);

        Ok(())
    }

    #[tokio::test]
    async fn test_parallel_verification() -> Result<()> {
        let mut system = TestSystem::new();
        let test_count = 100;

        let mut commitments = Vec::with_capacity(test_count);
        let mut proofs = Vec::with_capacity(test_count);
        let mut circuits = Vec::with_capacity(test_count);

        let start = Instant::now();

        for i in 0..test_count {
            let entry = StateMatrixEntry::new(
                [i as u8; 32],
                [2u8; 32],
                1,
                vec![1, 2, 3],
                1,
                [[3u8; 32], [4u8; 32]],
            );

            let mut transcript = ProofTranscript::new(DomainSeparationTags::COMMITMENT);
            let commitment = system.pedersen.commit_state_entry(
                entry,
                &system.rng.random_scalar(),
                &mut transcript,
            )?;

            let admin_signatures = system.generate_admin_signatures(&commitment, 3);
            let signed =
                SignedStateCommitment::new(commitment.clone(), admin_signatures, &system.groups)?;

            let merkle_proof = system
                .merkle_tree
                .insert_state_commitment([i as u8; 32], commitment.clone())?;

            let mut circuit = Circuit::new(Arc::clone(&system.groups));
            circuit.verify_access_grant(
                &commitment,
                &merkle_proof,
                signed.aggregate_signature(),
            )?;

            let proof = system.proof_system.prove(&circuit)?;

            commitments.push(commitment);
            proofs.push(proof);
            circuits.push(circuit);
        }

        let gen_time = start.elapsed();
        let start = Instant::now();

        let results: Vec<_> = circuits
            .iter()
            .zip(proofs.iter())
            .map(|(circuit, proof)| system.proof_system.verify(circuit, proof))
            .collect::<Result<Vec<_>>>()?;

        let verify_time = start.elapsed();

        assert!(results.iter().all(|&r| r));
        assert!(verify_time < gen_time / 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_revocation() -> Result<()> {
        let mut system = TestSystem::new();
        let mut commitment = system.create_test_commitment()?;

        let secret_key = system.rng.random_scalar();
        let message = serde_json::to_vec(&commitment.data()).unwrap();
        let signature = BlsSignature::sign(&message, &secret_key, &system.groups)?;

        assert!(!commitment.is_revoked());

        commitment.revoke(
            vec![signature.clone()],
            Some(json!({"reason": "test revocation"})),
            &system.groups,
        )?;

        assert!(commitment.is_revoked());

        let merkle_proof = system
            .merkle_tree
            .insert_state_commitment(*commitment.data().user_id(), commitment.clone())?;

        let mut circuit = Circuit::new(Arc::clone(&system.groups));
        let aggregate_sig = AggregateSignature::aggregate(&[signature])?;

        let result = circuit.verify_access_grant(&commitment, &merkle_proof, &aggregate_sig);

        assert!(result.is_err());

        Ok(())
    }
}
