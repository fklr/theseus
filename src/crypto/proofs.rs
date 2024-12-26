use crate::{
    crypto::{
        circuits::{Circuit, Constraint, Variable},
        primitives::{
            CurveGroups, DomainSeparationTags, ProofTranscript, RandomGenerator, Scalar, G1,
        },
        serialize::{IntoSerializable, SerializableG1, SerializableScalar},
    },
    errors::Result,
    types::{AdminKeySet, SuccessionRecord},
};
use ark_ec::{AffineRepr, CurveGroup};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitProof {
    pub commitments: Vec<SerializableG1>,
    pub responses: Vec<SerializableScalar>,
    pub evaluation_proof: SerializableG1,
}

impl CircuitProof {
    pub fn new(commitments: Vec<G1>, responses: Vec<Scalar>, evaluation_proof: G1) -> Self {
        Self {
            commitments: commitments.into_serializable(),
            responses: responses.into_serializable(),
            evaluation_proof: evaluation_proof.into(),
        }
    }

    pub fn commitments(&self) -> impl Iterator<Item = &G1> {
        self.commitments.iter().map(|c| c.inner())
    }

    pub fn responses(&self) -> impl Iterator<Item = &Scalar> {
        self.responses.iter().map(|r| r.inner())
    }

    pub fn evaluation_proof(&self) -> &G1 {
        self.evaluation_proof.inner()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub path: Vec<SerializableG1>,
    pub siblings: Vec<SerializableG1>,
    pub root: SerializableG1,
    pub value: SerializableG1,
}

impl MerkleProof {
    pub fn new(path: Vec<G1>, siblings: Vec<G1>, root: G1, value: G1) -> Self {
        Self {
            path: path.into_serializable(),
            siblings: siblings.into_serializable(),
            root: root.into(),
            value: value.into(),
        }
    }

    pub fn path(&self) -> impl Iterator<Item = &G1> {
        self.path.iter().map(|p| p.inner())
    }

    pub fn siblings(&self) -> impl Iterator<Item = &G1> {
        self.siblings.iter().map(|s| s.inner())
    }

    pub fn root(&self) -> &G1 {
        self.root.inner()
    }

    pub fn value(&self) -> &G1 {
        self.value.inner()
    }
}

#[derive(Clone, Debug)]
pub struct SuccessionProof {
    pub commitments: Vec<G1>,
    pub responses: Vec<Scalar>,
    pub evaluation_proof: G1,
}

pub struct ProofSystem {
    groups: Arc<CurveGroups>,
    rng: RandomGenerator,
}

impl ProofSystem {
    pub fn new(groups: Arc<CurveGroups>) -> Self {
        Self {
            groups,
            rng: RandomGenerator::new(),
        }
    }

    pub fn groups(&self) -> Arc<CurveGroups> {
        Arc::clone(&self.groups)
    }

    pub fn prove(&self, circuit: &Circuit) -> Result<CircuitProof> {
        let mut transcript =
            ProofTranscript::new(DomainSeparationTags::ACCESS_PROOF, Arc::clone(&self.groups));

        let blindings: Vec<_> = (0..circuit.next_var)
            .into_par_iter()
            .map(|_| self.rng.random_scalar())
            .collect();

        let commitments: Vec<_> = blindings
            .par_iter()
            .map(|blinding| (self.groups.g1_generator * blinding).into_affine())
            .collect();

        for commitment in &commitments {
            transcript.append_point_g1(DomainSeparationTags::COMMITMENT, commitment);
        }

        transcript.append_message(
            DomainSeparationTags::ACCESS_PROOF,
            &circuit.serialize_constraints()?,
        );
        let challenge = transcript.challenge_scalar(DomainSeparationTags::ACCESS_PROOF);

        // Evaluate constraints and generate evaluation proof
        let evaluations: Vec<_> = circuit
            .constraints
            .par_iter()
            .map(|constraint| evaluate_constraint(constraint, &blindings, &challenge, &self.groups))
            .collect();

        let evaluation_proof = evaluations.iter().fold(G1::zero(), |acc, eval| {
            (acc + self.groups.g1_generator * eval).into_affine()
        });

        Ok(CircuitProof {
            commitments: commitments.into_serializable(),
            responses: blindings.into_serializable(),
            evaluation_proof: evaluation_proof.into(),
        })
    }

    pub fn verify(&self, circuit: &Circuit, proof: &CircuitProof) -> Result<bool> {
        if proof.commitments.len() != circuit.next_var {
            return Ok(false);
        }

        let mut transcript =
            ProofTranscript::new(DomainSeparationTags::ACCESS_PROOF, Arc::clone(&self.groups));

        for commitment in &proof.commitments {
            transcript.append_point_g1(DomainSeparationTags::COMMITMENT, commitment);
        }

        transcript.append_message(
            DomainSeparationTags::ACCESS_PROOF,
            &circuit.serialize_constraints()?,
        );
        let challenge = transcript.challenge_scalar(DomainSeparationTags::ACCESS_PROOF);

        let batch_size = (circuit.constraints.len() / rayon::current_num_threads()).max(1);

        let evaluation_valid = circuit
            .constraints
            .par_chunks(batch_size)
            .map(|constraint_batch| {
                constraint_batch.iter().all(|constraint| {
                    let commitments: Vec<G1> = proof.commitments().cloned().collect();
                    let left = verify_terms(&constraint.left, &commitments, &challenge);
                    let right = verify_terms(&constraint.right, &commitments, &challenge);
                    let output = verify_terms(&constraint.output, &commitments, &challenge);

                    let constraint_eval = (left + right - output).into_affine();
                    let expected = (self.groups.g1_generator
                        * evaluate_constraint(
                            constraint,
                            &proof.responses().cloned().collect::<Vec<_>>(),
                            &challenge,
                            &self.groups,
                        ))
                    .into_affine();

                    constraint_eval == expected
                })
            })
            .all(|batch_valid| batch_valid);

        Ok(evaluation_valid && self.verify_evaluation_proof(circuit, proof, &challenge))
    }

    fn verify_evaluation_proof(
        &self,
        circuit: &Circuit,
        proof: &CircuitProof,
        challenge: &Scalar,
    ) -> bool {
        let responses: Vec<_> = proof.responses().cloned().collect();
        let expected = circuit
            .constraints
            .par_iter()
            .map(|constraint| evaluate_constraint(constraint, &responses, challenge, &self.groups))
            .reduce_with(|acc, eval| acc + eval)
            .map(|total| (self.groups.g1_generator * total).into_affine())
            .unwrap_or(G1::zero());

        proof.evaluation_proof == expected
    }

    pub fn verify_succession(
        &self,
        succession: &SuccessionRecord,
        current_admin: &AdminKeySet,
    ) -> Result<bool> {
        let message = serde_json::to_vec(&succession.auth_proof.succession_proof)?;
        if !succession
            .auth_proof
            .aggregate_signature
            .verify(&message, &self.groups)?
        {
            return Ok(false);
        }

        if let Some(proof) = &succession.auth_proof.succession_proof {
            let mut circuit = Circuit::new(Arc::clone(&self.groups));

            let old_policy_var =
                circuit.allocate_scalar(&Scalar::from(current_admin.policy_generation as u64));
            let new_policy_var =
                circuit.allocate_scalar(&Scalar::from(succession.generation as u64));

            circuit.enforce_policy_transition(old_policy_var, new_policy_var);

            for (old_key, new_key) in current_admin
                .active_keys
                .iter()
                .zip(succession.new_keys.iter())
            {
                let old_key_point = circuit.allocate_g2_point(old_key.inner());
                let new_key_point = circuit.allocate_g2_point(new_key.inner());
                circuit.enforce_key_succession(old_key_point, new_key_point);
            }

            self.verify(&circuit, proof)
        } else {
            Ok(false)
        }
    }
}

fn evaluate_constraint(
    constraint: &Constraint,
    values: &[Scalar],
    challenge: &Scalar,
    _groups: &CurveGroups,
) -> Scalar {
    let left = evaluate_terms(&constraint.left, values, challenge);
    let right = evaluate_terms(&constraint.right, values, challenge);
    let output = evaluate_terms(&constraint.output, values, challenge);
    left + right - output
}

fn evaluate_terms(terms: &[(Scalar, Variable)], values: &[Scalar], challenge: &Scalar) -> Scalar {
    terms
        .iter()
        .map(|(coeff, var)| values[var.0] * (coeff * challenge))
        .sum()
}

fn verify_terms(terms: &[(Scalar, Variable)], commitments: &[G1], challenge: &Scalar) -> G1 {
    let sum = terms
        .iter()
        .map(|(coeff, var)| commitments[var.0].into_group() * (coeff * challenge))
        .sum::<ark_ec::short_weierstrass::Projective<ark_bls12_377::g1::Config>>();
    sum.into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use std::time::Instant;

    #[test]
    fn test_proof_generation_and_verification() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let proof_system = ProofSystem::new(Arc::clone(&groups));

        // Create simple test circuit
        let var1 = circuit.allocate_variable();
        let var2 = circuit.allocate_variable();
        circuit.enforce_equal(var1, var2);

        // Generate and verify proof
        let proof = proof_system
            .prove(&circuit)
            .expect("Proof generation should succeed");

        assert!(proof_system
            .verify(&circuit, &proof)
            .expect("Verification should complete"));
    }

    #[test]
    fn test_parallel_proof_performance() {
        let groups = Arc::new(CurveGroups::new());
        let proof_system = ProofSystem::new(Arc::clone(&groups));
        let proof_count = 100;

        // Create test circuits
        let circuits: Vec<_> = (0..proof_count)
            .map(|_| {
                let mut circuit = Circuit::new(Arc::clone(&groups));
                let var1 = circuit.allocate_variable();
                let var2 = circuit.allocate_variable();
                circuit.enforce_equal(var1, var2);
                circuit
            })
            .collect();

        // Sequential execution
        let start = Instant::now();
        for circuit in circuits.iter() {
            let _ = proof_system
                .prove(circuit)
                .expect("Proof generation should succeed");
        }
        let sequential_time = start.elapsed();

        // Parallel execution
        let start = Instant::now();
        let proofs: Vec<_> = circuits
            .par_iter()
            .map(|circuit| {
                proof_system
                    .prove(circuit)
                    .expect("Proof generation should succeed")
            })
            .collect();
        let parallel_time = start.elapsed();

        println!("Sequential time: {:?}", sequential_time);
        println!("Parallel time: {:?}", parallel_time);

        assert!(parallel_time < sequential_time / 2);

        // Verify all proofs
        for (circuit, proof) in circuits.iter().zip(proofs.iter()) {
            assert!(proof_system
                .verify(circuit, proof)
                .expect("Verification should complete"));
        }
    }

    #[test]
    fn test_invalid_proof() {
        let groups = Arc::new(CurveGroups::new());
        let rng = RandomGenerator::new();
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let proof_system = ProofSystem::new(Arc::clone(&groups));

        // Create test circuit
        let var1 = circuit.allocate_variable();
        let var2 = circuit.allocate_variable();
        circuit.enforce_equal(var1, var2);

        // Generate valid proof
        let mut proof = proof_system
            .prove(&circuit)
            .expect("Proof generation should succeed");

        // Corrupt the proof by modifying a response
        if let Some(response) = proof.responses.get_mut(0) {
            *response = rng.random_scalar().into();
        }

        // Verify corrupted proof fails
        assert!(!proof_system
            .verify(&circuit, &proof)
            .expect("Verification should complete"));
    }

    #[test]
    fn test_constraint_satisfaction() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let proof_system = ProofSystem::new(Arc::clone(&groups));

        // Create circuit with multiple constraints
        let var1 = circuit.allocate_variable();
        let var2 = circuit.allocate_variable();
        let var3 = circuit.allocate_variable();

        // Add constraints: var1 + var2 = var3
        circuit.constraints.push(Constraint {
            left: vec![(Scalar::one(), var1)],
            right: vec![(Scalar::one(), var2)],
            output: vec![(Scalar::one(), var3)],
        });

        // Generate and verify proof
        let proof = proof_system
            .prove(&circuit)
            .expect("Proof generation should succeed");

        assert!(proof_system
            .verify(&circuit, &proof)
            .expect("Verification should complete"));
    }

    #[test]
    fn test_large_circuit() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let proof_system = ProofSystem::new(Arc::clone(&groups));

        // Create circuit with many variables and constraints
        let var_count = 1000;
        let mut vars = Vec::with_capacity(var_count);

        for _ in 0..var_count {
            vars.push(circuit.allocate_variable());
        }

        // Add chain of equality constraints
        for i in 0..var_count - 1 {
            circuit.enforce_equal(vars[i], vars[i + 1]);
        }

        let start = Instant::now();
        let proof = proof_system
            .prove(&circuit)
            .expect("Proof generation should succeed");
        let prove_time = start.elapsed();

        let start = Instant::now();
        let valid = proof_system
            .verify(&circuit, &proof)
            .expect("Verification should complete");
        let verify_time = start.elapsed();

        println!("Large circuit prove time: {:?}", prove_time);
        println!("Large circuit verify time: {:?}", verify_time);

        assert!(valid);
        assert!(
            verify_time < prove_time,
            "Verification should be faster than proving"
        );
    }
}
