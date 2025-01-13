use std::sync::Arc;

use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        merkle::MerkleProof,
        primitives::{CurveGroups, DomainSeparationTags, ProofTranscript, Scalar, G1},
        serialize::{SerializableG1, SerializableScalar},
        signatures::AggregateSignature,
    },
    errors::Result,
    types::SuccessionRecord,
};

#[derive(Clone, Copy)]
pub struct BatchVerificationConfig {
    pub max_items: usize,
    pub parallelization_factor: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UnifiedProof {
    Circuit(CircuitProof),
    Succession(SuccessionProof),
    Merkle(MerkleProof),
    Aggregate(AggregateProof),
}

impl UnifiedProof {
    pub fn verify_in_parallel() -> bool {
        true
    }

    pub fn get_commitment(&self) -> G1 {
        match self {
            UnifiedProof::Circuit(p) => *p.evaluation.inner(),
            UnifiedProof::Succession(p) => *p.epoch_commitment.inner(),
            UnifiedProof::Merkle(p) => *p.root.inner(),
            UnifiedProof::Aggregate(p) => *p.final_evaluation.inner(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitProof {
    pub commitments: Vec<SerializableG1>,
    pub witnesses: Vec<SerializableScalar>,
    pub evaluation: SerializableG1,
    pub transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuccessionProof {
    epoch_commitment: SerializableG1,
    key_accumulator: SerializableG1,
    aggregate_signature: AggregateSignature,
    transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateProof {
    proof_commitments: Vec<SerializableG1>,
    cross_terms: Vec<SerializableScalar>,
    final_evaluation: SerializableG1,
    transcript_binding: Vec<u8>,
}

pub struct ProofSystem {
    groups: Arc<CurveGroups>,
    transcript: ProofTranscript,
    proof_cache: dashmap::DashMap<[u8; 32], UnifiedProof>,
}

impl ProofSystem {
    pub fn new(groups: Arc<CurveGroups>) -> Self {
        Self {
            groups: Arc::clone(&groups),
            transcript: ProofTranscript::new(
                DomainSeparationTags::ACCESS_PROOF,
                Arc::clone(&groups),
            ),
            proof_cache: dashmap::DashMap::new(),
        }
    }

    fn cache_proof(&self, key: [u8; 32], proof: UnifiedProof) -> Result<()> {
        let mut transcript = self.transcript.clone();
        transcript.append_message(b"proof_key", &key);

        self.proof_cache.insert(key, proof);
        Ok(())
    }

    pub fn verify_proof(&self, proof: &UnifiedProof, public_inputs: &[u8]) -> Result<bool> {
        let cache_key = self.compute_cache_key(public_inputs);
        if self.proof_cache.contains_key(&cache_key) {
            return Ok(true);
        }

        let mut transcript = self.transcript.clone();

        transcript.init_proof(DomainSeparationTags::ACCESS_PROOF);
        transcript.append_message(DomainSeparationTags::PUBLIC_INPUT, public_inputs);

        let result = match proof {
            UnifiedProof::Circuit(p) => self.verify_circuit_proof(p, &mut transcript),
            UnifiedProof::Succession(p) => self.verify_succession_proof(p, &mut transcript),
            UnifiedProof::Merkle(p) => self.verify_merkle_proof(p, &mut transcript),
            UnifiedProof::Aggregate(p) => self.verify_aggregate_proof(p, &mut transcript),
        }?;

        if result {
            self.cache_proof(cache_key, proof.clone())?;
        }

        Ok(result)
    }

    pub fn verify_batch(&self, proofs: &[(UnifiedProof, Vec<u8>)]) -> Result<Vec<bool>> {
        let chunk_size = (proofs.len() / rayon::current_num_threads()).max(1);

        proofs
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut transcript = self.transcript.clone();
                transcript.init_proof(DomainSeparationTags::ACCESS_PROOF);

                chunk
                    .iter()
                    .map(|(proof, inputs)| {
                        transcript.append_message(b"batch_item", inputs);
                        self.verify_proof(proof, inputs)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()
            .map(|nested| nested.into_iter().flatten().collect())
    }

    fn compute_cache_key(&self, inputs: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(inputs);
        *hasher.finalize().as_bytes()
    }

    pub fn accumulate_state_roots(&self, proofs: &[UnifiedProof]) -> Result<G1> {
        let mut transcript = self.transcript.clone();
        let mut accumulator = G1::zero();

        for proof in proofs {
            let commitment = proof.get_commitment();
            transcript.append_point_g1(DomainSeparationTags::ACCUMULATOR, &commitment);
            let challenge = transcript.challenge_scalar(DomainSeparationTags::HISTORICAL);
            accumulator = (accumulator + commitment.into_group() * challenge).into_affine();
        }

        Ok(accumulator)
    }

    pub fn accumulate_epochs(
        &self,
        current_epoch: &UnifiedProof,
        next_epoch: &UnifiedProof,
        transition_data: &[u8],
    ) -> Result<G1> {
        let mut transcript = self.transcript.clone();

        let current_commitment = current_epoch.get_commitment();
        let next_commitment = next_epoch.get_commitment();

        transcript.append_message(DomainSeparationTags::STATE_TRANSITION, transition_data);
        transcript.append_point_g1(DomainSeparationTags::HISTORICAL, &current_commitment);
        transcript.append_point_g1(DomainSeparationTags::HISTORICAL, &next_commitment);

        let challenge = transcript.challenge_scalar(DomainSeparationTags::HISTORICAL);

        let accumulator = (current_commitment.into_group()
            + next_commitment.into_group() * challenge)
            .into_affine();

        Ok(accumulator)
    }

    pub fn verify_historical_chain(
        &self,
        succession: &SuccessionRecord,
        proof_chain: &[UnifiedProof],
    ) -> Result<bool> {
        let mut transcript = self.transcript.clone();
        let mut accumulator = G1::zero();

        for (proof, entry) in proof_chain.iter().zip(&succession.affected_entries) {
            transcript.append_message(DomainSeparationTags::HISTORICAL, &entry.0);
            let challenge = transcript.challenge_scalar(DomainSeparationTags::ACCUMULATOR);

            let commitment = match proof {
                UnifiedProof::Circuit(p) => p.evaluation.inner(),
                UnifiedProof::Succession(p) => p.epoch_commitment.inner(),
                UnifiedProof::Merkle(p) => p.root.inner(),
                UnifiedProof::Aggregate(p) => p.final_evaluation.inner(),
            };

            accumulator = (accumulator + commitment.into_group() * challenge).into_affine();

            if !self.verify_proof(proof, &entry.0)? {
                return Ok(false);
            }
        }

        self.verify_final_state(&accumulator, succession, &mut transcript)
    }

    fn verify_final_state(
        &self,
        accumulator: &G1,
        succession: &SuccessionRecord,
        transcript: &mut ProofTranscript,
    ) -> Result<bool> {
        transcript.append_point_g1(DomainSeparationTags::FINAL_STATE, accumulator);
        let challenge = transcript.challenge_scalar(DomainSeparationTags::FINAL_STATE);

        let mut final_evaluation = G1::zero();
        for (_key, entry) in succession.new_keys.iter().zip(&succession.affected_entries) {
            transcript.append_message(DomainSeparationTags::STATE_TRANSITION, &entry.0);
            let entry_challenge = transcript.challenge_scalar(DomainSeparationTags::PUBLIC_INPUT);
            let point = (accumulator.into_group() * entry_challenge).into_affine();
            final_evaluation = (final_evaluation + point.into_group()).into_affine();
        }

        let expected = (accumulator.into_group() * challenge).into_affine();
        Ok(final_evaluation == expected)
    }

    pub fn precompute_proof_data(&self, proof: &UnifiedProof) -> Result<G1> {
        let mut transcript = self.transcript.clone();
        let commitment = proof.get_commitment();

        transcript.append_point_g1(DomainSeparationTags::COMMITMENT, &commitment);
        let precomputed = transcript.challenge_point_g1(DomainSeparationTags::COMMITMENT)?;

        let initial_accumulator =
            (commitment.into_group() + precomputed.into_group()).into_affine();

        Ok(initial_accumulator)
    }

    fn get_binding_commitment(transcript: &mut ProofTranscript) -> Vec<u8> {
        let challenge = transcript.challenge_scalar(b"binding");
        let mut bytes = Vec::new();
        challenge
            .serialize_compressed(&mut bytes)
            .expect("Serialization cannot fail");
        bytes
    }

    fn verify_transcript_binding(transcript: &mut ProofTranscript, binding: &[u8]) -> Result<bool> {
        let current_binding = Self::get_binding_commitment(transcript);
        Ok(binding == current_binding)
    }

    pub fn generate_delegated_proof(
        &self,
        base_proof: &UnifiedProof,
        delegate_data: &[u8],
    ) -> Result<UnifiedProof> {
        let mut transcript = self.transcript.clone();
        let base_commitment = base_proof.get_commitment();

        transcript.append_message(DomainSeparationTags::PUBLIC_INPUT, delegate_data);
        transcript.append_point_g1(DomainSeparationTags::COMMITMENT, &base_commitment);

        let challenge = transcript.challenge_scalar(DomainSeparationTags::ACCESS_PROOF);
        let delegated_commitment = (base_commitment.into_group() * challenge).into_affine();

        let binding = Self::get_binding_commitment(&mut transcript);

        let delegated = CircuitProof {
            commitments: vec![SerializableG1::from(base_commitment)],
            witnesses: vec![SerializableScalar::from(challenge)],
            evaluation: SerializableG1::from(delegated_commitment),
            transcript_binding: binding,
        };

        Ok(UnifiedProof::Circuit(delegated))
    }

    pub fn compose_proofs(&self, proofs: &[UnifiedProof]) -> Result<AggregateProof> {
        let mut transcript = self.transcript.clone();

        let commitments: Vec<_> = proofs
            .iter()
            .map(|proof| match proof {
                UnifiedProof::Circuit(p) => p.evaluation.inner().into_group(),
                UnifiedProof::Succession(p) => p.epoch_commitment.inner().into_group(),
                UnifiedProof::Merkle(p) => p.root.inner().into_group(),
                UnifiedProof::Aggregate(p) => p.final_evaluation.inner().into_group(),
            })
            .map(|g| g.into_affine())
            .collect();

        let cross_terms: Vec<_> = commitments
            .par_iter()
            .enumerate()
            .map(|(i, commitment)| {
                let mut term_transcript = transcript.clone();
                term_transcript.append_point_g1(DomainSeparationTags::COMMITMENT, commitment);
                term_transcript.append_scalar(b"index", &Scalar::from(i as u64));
                term_transcript.challenge_scalar(DomainSeparationTags::CROSS_TERM)
            })
            .collect();

        let final_evaluation = commitments
            .par_iter()
            .zip(&cross_terms)
            .map(|(comm, term)| comm.into_group() * term)
            .reduce(|| G1::zero().into(), |acc, x| acc + x)
            .into_affine();

        let binding = Self::get_binding_commitment(&mut transcript);

        Ok(AggregateProof {
            proof_commitments: commitments.into_iter().map(SerializableG1::from).collect(),
            cross_terms: cross_terms
                .into_iter()
                .map(SerializableScalar::from)
                .collect(),
            final_evaluation: SerializableG1::from(final_evaluation),
            transcript_binding: binding,
        })
    }

    fn verify_circuit_proof(
        &self,
        proof: &CircuitProof,
        transcript: &mut ProofTranscript,
    ) -> Result<bool> {
        transcript.init_proof(DomainSeparationTags::ACCESS_PROOF);
        transcript.append_point_g1(DomainSeparationTags::COMMITMENT, proof.evaluation.inner());

        let challenge = transcript.challenge_scalar(DomainSeparationTags::ACCESS_PROOF);

        let mut computed_evaluation = G1::zero();
        for witness in &proof.witnesses {
            computed_evaluation = (computed_evaluation +
                self.groups.g1_generator.into_group() * witness.inner() *
                challenge).into_affine();
        }

        if computed_evaluation != *proof.evaluation.inner() {
            return Ok(false);
        }

        let binding = Self::get_binding_commitment(transcript);
        if binding != proof.transcript_binding {
            return Ok(false);
        }

        Ok(true)
    }

    fn verify_succession_proof(
        &self,
        proof: &SuccessionProof,
        transcript: &mut ProofTranscript,
    ) -> Result<bool> {
        transcript.append_point_g1(
            DomainSeparationTags::SUCCESSION_PROOF,
            proof.epoch_commitment.inner(),
        );
        transcript.append_point_g1(
            DomainSeparationTags::SUCCESSION_PROOF,
            proof.key_accumulator.inner(),
        );

        let challenge = transcript.challenge_scalar(DomainSeparationTags::SUCCESSION_PROOF);

        let epoch_valid = proof
            .aggregate_signature
            .verify(&proof.transcript_binding, &self.groups)?;

        let accumulator_valid = self.verify_accumulator_consistency(
            proof.key_accumulator.inner(),
            proof.epoch_commitment.inner(),
            &challenge,
        )?;

        Ok(epoch_valid && accumulator_valid)
    }

    fn verify_merkle_proof(
        &self,
        proof: &MerkleProof,
        transcript: &mut ProofTranscript,
    ) -> Result<bool> {
        let mut current = *proof.value.inner();

        for (depth, sibling) in proof.siblings.iter().enumerate() {
            let bit = (depth / 8) & 1;
            transcript.append_message(b"depth", &[bit as u8]);

            current = if bit == 0 {
                self.hash_nodes(depth, &current, sibling.inner(), transcript)?
            } else {
                self.hash_nodes(depth, sibling.inner(), &current, transcript)?
            };

            if current != *proof.path[depth].inner() {
                return Ok(false);
            }
        }

        let binding_valid = Self::verify_transcript_binding(transcript, &proof.transcript_binding)?;
        Ok(current == *proof.root.inner() && binding_valid)
    }

    fn verify_aggregate_proof(
        &self,
        proof: &AggregateProof,
        transcript: &mut ProofTranscript,
    ) -> Result<bool> {
        transcript.append_point_g1(
            DomainSeparationTags::ACCESS_PROOF,
            proof.final_evaluation.inner(),
        );

        for commitment in &proof.proof_commitments {
            transcript.append_point_g1(DomainSeparationTags::COMMITMENT, commitment.inner());
        }

        let challenges = transcript.batch_challenges(proof.cross_terms.len());

        let mut evaluation = G1::zero();
        for ((commitment, cross_term), challenge) in proof
            .proof_commitments
            .iter()
            .zip(&proof.cross_terms)
            .zip(&challenges)
        {
            evaluation = (evaluation
                + commitment.inner().into_group() * cross_term.inner() * challenge)
                .into_affine();
        }

        if evaluation != *proof.final_evaluation.inner() {
            return Ok(false);
        }

        if !Self::verify_transcript_binding(transcript, &proof.transcript_binding)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn hash_nodes(
        &self,
        depth: usize,
        left: &G1,
        right: &G1,
        transcript: &mut ProofTranscript,
    ) -> Result<G1> {
        let mut buf = Vec::new();
        let binding = Self::get_binding_commitment(transcript);
        buf.extend_from_slice(&binding);
        left.serialize_compressed(&mut buf)?;
        right.serialize_compressed(&mut buf)?;
        buf.extend_from_slice(&depth.to_le_bytes());
        self.groups.hash_to_g1(&buf)
    }

    fn verify_accumulator_consistency(
        &self,
        accumulator: &G1,
        commitment: &G1,
        challenge: &Scalar,
    ) -> Result<bool> {
        let contribution = (commitment.into_group() * challenge).into_affine();
        Ok(accumulator == &contribution)
    }

    pub fn accumulate_batch_proofs(
        &self,
        proof_batch: &[UnifiedProof],
        public_inputs: &[Vec<u8>],
    ) -> Result<G1> {
        let mut transcript = self.transcript.clone();
        let mut batch_accumulator = G1::zero();

        for (proof, inputs) in proof_batch.iter().zip(public_inputs) {
            let commitment = proof.get_commitment();
            transcript.append_message(DomainSeparationTags::PUBLIC_INPUT, inputs);
            transcript.append_point_g1(DomainSeparationTags::COMMITMENT, &commitment);

            let challenge = transcript.challenge_scalar(DomainSeparationTags::ACCUMULATOR);
            batch_accumulator =
                (batch_accumulator + commitment.into_group() * challenge).into_affine();
        }

        Ok(batch_accumulator)
    }

    pub fn verify_historical_state(
        &self,
        start_proof: &UnifiedProof,
        end_proof: &UnifiedProof,
        chain_data: &[Vec<u8>],
    ) -> Result<bool> {
        let mut transcript = self.transcript.clone();
        let start_commitment = start_proof.get_commitment();
        let end_commitment = end_proof.get_commitment();

        for data in chain_data {
            transcript.append_message(DomainSeparationTags::HISTORICAL, data);
        }

        let start_challenge = transcript.challenge_scalar(DomainSeparationTags::HISTORICAL);
        let end_challenge = transcript.challenge_scalar(DomainSeparationTags::HISTORICAL);

        let chain_valid = (start_commitment.into_group() * start_challenge
            + end_commitment.into_group() * end_challenge)
            .into_affine();

        let start_valid = self.verify_proof(start_proof, &chain_data[0])?;
        let end_valid = self.verify_proof(end_proof, &chain_data[chain_data.len() - 1])?;

        Ok(chain_valid.is_on_curve() && start_valid && end_valid)
    }

    pub fn accumulate_state_transition(
        &self,
        old_state: &UnifiedProof,
        new_state: &UnifiedProof,
        transition_data: &[u8],
    ) -> Result<G1> {
        let mut transcript = self.transcript.clone();

        let old_commitment = old_state.get_commitment();
        let new_commitment = new_state.get_commitment();

        transcript.append_message(DomainSeparationTags::STATE_TRANSITION, transition_data);
        transcript.append_point_g1(DomainSeparationTags::COMMITMENT, &old_commitment);
        transcript.append_point_g1(DomainSeparationTags::COMMITMENT, &new_commitment);

        let transition_challenge =
            transcript.challenge_scalar(DomainSeparationTags::STATE_TRANSITION);

        let transition_accumulator = (old_commitment.into_group()
            + new_commitment.into_group() * transition_challenge)
            .into_affine();

        Ok(transition_accumulator)
    }

    pub fn verify_accumulated_proofs(
        &self,
        proofs: &[UnifiedProof],
        accumulator: &G1,
        public_data: &[Vec<u8>],
    ) -> Result<bool> {
        let mut transcript = self.transcript.clone();

        for (proof, data) in proofs.iter().zip(public_data) {
            let commitment = proof.get_commitment();
            transcript.append_message(DomainSeparationTags::PUBLIC_INPUT, data);
            transcript.append_point_g1(DomainSeparationTags::COMMITMENT, &commitment);
        }

        let challenge = transcript.challenge_scalar(DomainSeparationTags::ACCESS_PROOF);

        let mut expected = G1::zero();
        for proof in proofs {
            let commitment = proof.get_commitment();
            expected = (expected + commitment.into_group() * challenge).into_affine();
        }

        Ok(*accumulator == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        circuits::{Circuit, Constraint},
        primitives::RandomGenerator,
    };
    use ark_ff::{BigInteger, One, PrimeField};
    use std::sync::Arc;

    fn setup_test_environment() -> (ProofSystem, Circuit, RandomGenerator) {
        let groups = Arc::new(CurveGroups::new());
        let system = ProofSystem::new(groups.clone());
        let circuit = Circuit::new(groups);
        let rng = RandomGenerator::new();
        (system, circuit, rng)
    }

    fn create_test_circuit_proof(
        system: &ProofSystem,
        circuit: &mut Circuit,
        value: &Scalar,
    ) -> CircuitProof {
        let var = circuit.allocate_scalar(value);

        let constraint = Constraint {
            constraint_a: vec![(Scalar::one(), var)],
            constraint_b: vec![(Scalar::one(), var)],
            constraint_c: vec![(Scalar::one(), var)], // Simple equality constraint
        };
        circuit.constraints.push(constraint.clone());

        let commitment = circuit.compute_constraint_commitment(&constraint).unwrap();

        let mut transcript = system.transcript.clone();
        transcript.init_proof(DomainSeparationTags::ACCESS_PROOF);
        transcript.append_point_g1(DomainSeparationTags::COMMITMENT, &commitment);

        CircuitProof {
            commitments: vec![SerializableG1::from(commitment)],
            witnesses: vec![SerializableScalar::from(*value)],
            evaluation: SerializableG1::from(commitment),
            transcript_binding: ProofSystem::get_binding_commitment(&mut transcript),
        }
    }

    #[test]
    fn test_basic_proof_verification() {
        let (system, mut circuit, rng) = setup_test_environment();
        let value = rng.random_scalar();

        let proof = create_test_circuit_proof(&system, &mut circuit, &value);
        assert!(system
            .verify_circuit_proof(&proof, &mut system.transcript.clone())
            .unwrap());
    }

    #[test]
    fn test_proof_caching() {
        let (system, mut circuit, rng) = setup_test_environment();
        let value = rng.random_scalar();
        let input = b"test_input";

        let proof = create_test_circuit_proof(&system, &mut circuit, &value);
        let unified = UnifiedProof::Circuit(proof);
        assert!(system.verify_proof(&unified, input).unwrap());

        let cache_key = system.compute_cache_key(input);
        assert!(system.proof_cache.contains_key(&cache_key));

        assert!(system.verify_proof(&unified, input).unwrap());
    }

    #[test]
    fn test_batch_verification() {
        let (system, mut circuit, rng) = setup_test_environment();

        let proofs: Vec<_> = (0..3)
            .map(|i| {
                let value = rng.random_scalar();
                let proof = create_test_circuit_proof(&system, &mut circuit, &value);
                (UnifiedProof::Circuit(proof), Vec::from([i as u8]))
            })
            .collect();

        let results = system.verify_batch(&proofs).unwrap();
        assert!(results.iter().all(|&x| x));
    }

    #[test]
    fn test_historical_state_verification() {
        let (system, mut circuit, rng) = setup_test_environment();

        let start_value = rng.random_scalar();
        let start_proof = create_test_circuit_proof(&system, &mut circuit, &start_value);

        let end_value = rng.random_scalar();
        let end_proof = create_test_circuit_proof(&system, &mut circuit, &end_value);

        let chain_data = vec![
            start_value.into_bigint().to_bytes_le(),
            end_value.into_bigint().to_bytes_le(),
        ];

        assert!(system
            .verify_historical_state(
                &UnifiedProof::Circuit(start_proof),
                &UnifiedProof::Circuit(end_proof),
                &chain_data
            )
            .unwrap());
    }

    #[test]
    fn test_state_transition() {
        let (system, mut circuit, rng) = setup_test_environment();

        let old_value = rng.random_scalar();
        let old_proof = create_test_circuit_proof(&system, &mut circuit, &old_value);

        let new_value = rng.random_scalar();
        let new_proof = create_test_circuit_proof(&system, &mut circuit, &new_value);

        let transition_data = b"state_transition";
        let accumulator = system
            .accumulate_state_transition(
                &UnifiedProof::Circuit(old_proof),
                &UnifiedProof::Circuit(new_proof),
                transition_data,
            )
            .unwrap();

        assert!(accumulator.is_on_curve());
    }

    #[test]
    fn test_proof_composition() {
        let (system, mut circuit, rng) = setup_test_environment();

        let proofs: Vec<_> = (0..3)
            .map(|_| {
                let value = rng.random_scalar();
                let proof = create_test_circuit_proof(&system, &mut circuit, &value);
                UnifiedProof::Circuit(proof)
            })
            .collect();

        let composed = system.compose_proofs(&proofs).unwrap();
        let unified = UnifiedProof::Aggregate(composed);

        assert!(system.verify_proof(&unified, b"test_input").unwrap());
    }

    #[test]
    fn test_proof_accumulation() {
        let (system, mut circuit, rng) = setup_test_environment();

        let proofs: Vec<_> = (0..3)
            .map(|_| {
                let value = rng.random_scalar();
                let proof = create_test_circuit_proof(&system, &mut circuit, &value);
                UnifiedProof::Circuit(proof)
            })
            .collect();

        let public_data: Vec<_> = (0..3).map(|i| Vec::from([i as u8])).collect();

        let accumulator = system
            .accumulate_batch_proofs(&proofs, &public_data)
            .unwrap();

        assert!(system
            .verify_accumulated_proofs(&proofs, &accumulator, &public_data)
            .unwrap());
    }

    #[test]
    fn test_invalid_proof_rejection() {
        let (system, mut circuit, rng) = setup_test_environment();
        let value = rng.random_scalar();

        let mut proof = create_test_circuit_proof(&system, &mut circuit, &value);

        // Corrupt the proof
        proof.transcript_binding = vec![0u8; 32];

        assert!(!system
            .verify_circuit_proof(&proof, &mut system.transcript.clone())
            .unwrap());
    }
}
