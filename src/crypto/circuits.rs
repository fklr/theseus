use crate::{
    crypto::commitment::StateMatrixCommitment,
    crypto::merkle::MerkleProof,
    crypto::primitives::{CurveGroups, Scalar, G1, G2},
    crypto::signatures::AggregateSignature,
    errors::{Error, Result},
};
use ark_bls12_377::{Fq, Fr};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Variable(pub(crate) usize);

#[derive(Clone, Debug)]
pub struct Constraint {
    pub(crate) left: Vec<(Scalar, Variable)>,
    pub(crate) right: Vec<(Scalar, Variable)>,
    pub(crate) output: Vec<(Scalar, Variable)>,
}

pub struct Circuit {
    groups: Arc<CurveGroups>,
    pub(crate) constraints: Vec<Constraint>,
    pub(crate) next_var: usize,
}

impl Circuit {
    pub fn new(groups: Arc<CurveGroups>) -> Self {
        Self {
            groups,
            constraints: Vec::new(),
            next_var: 0,
        }
    }

    pub fn allocate_variable(&mut self) -> Variable {
        let var = Variable(self.next_var);
        self.next_var += 1;
        var
    }

    pub fn allocate_g1_point(&mut self, point: &G1) -> Variable {
        let var = self.allocate_variable();
        self.enforce_g1_point_on_curve(point, var);
        var
    }

    pub fn allocate_g2_point(&mut self, point: &G2) -> Variable {
        let var = self.allocate_variable();
        self.enforce_g2_point_on_curve(point, var);
        var
    }

    pub fn allocate_scalar(&mut self, value: &Scalar) -> Variable {
        let var = self.allocate_variable();
        self.enforce_scalar_range(value, var);
        var
    }

    pub fn enforce_equal(&mut self, left: Variable, right: Variable) {
        let constraint = Constraint {
            left: vec![(Scalar::one(), left)],
            right: vec![(Scalar::one(), right)],
            output: vec![(Scalar::zero(), self.allocate_variable())],
        };
        self.constraints.push(constraint);
    }

    pub fn enforce_merkle_membership(
        &mut self,
        proof: &MerkleProof,
        root: &G1,
        leaf: &StateMatrixCommitment,
    ) -> Result<()> {
        let leaf_var = self.allocate_g1_point(leaf.value());
        let mut current = leaf_var;

        for (idx, sibling) in proof.siblings.iter().enumerate() {
            let sibling_var = self.allocate_g1_point(sibling);
            let output_var = self.allocate_variable();

            let is_right = (idx & 1) == 1;

            let hash_constraint = if is_right {
                Constraint {
                    left: vec![(Scalar::one(), current)],
                    right: vec![(Scalar::one(), sibling_var)],
                    output: vec![(Scalar::one(), output_var)],
                }
            } else {
                Constraint {
                    left: vec![(Scalar::one(), sibling_var)],
                    right: vec![(Scalar::one(), current)],
                    output: vec![(Scalar::one(), output_var)],
                }
            };

            self.constraints.push(hash_constraint);
            current = output_var;
        }

        let root_var = self.allocate_g1_point(root);
        self.enforce_equal(current, root_var);
        Ok(())
    }

    pub fn enforce_state_transition(
        &mut self,
        old_state: &StateMatrixCommitment,
        new_state: &StateMatrixCommitment,
        aggregate_signature: &AggregateSignature,
        policy_generation: u32,
    ) -> Result<()> {
        let old_var = self.allocate_g1_point(old_state.value());
        let new_var = self.allocate_g1_point(new_state.value());

        let state_transition = Constraint {
            left: vec![(Scalar::one(), old_var)],
            right: vec![(Scalar::one(), new_var)],
            output: vec![(Scalar::one(), self.allocate_variable())],
        };
        self.constraints.push(state_transition);

        self.enforce_commitment_structure(old_state)?;
        self.enforce_commitment_structure(new_state)?;

        let old_gen = Scalar::from(old_state.data().policy_generation() as u64);
        let new_gen = Scalar::from(policy_generation as u64);
        let gen_var = self.allocate_scalar(&new_gen);

        let policy_constraint = Constraint {
            left: vec![(Scalar::one(), gen_var)],
            right: vec![(old_gen, self.allocate_variable())],
            output: vec![(new_gen, self.allocate_variable())],
        };
        self.constraints.push(policy_constraint);

        self.enforce_signature_validity(aggregate_signature, new_state)?;

        self.enforce_policy_requirements(new_state)?;

        Ok(())
    }

    fn enforce_commitment_structure(&mut self, commitment: &StateMatrixCommitment) -> Result<()> {
        let value_var = self.allocate_g1_point(commitment.value());
        let data_point = self.groups.hash_to_g1(
            &serde_json::to_vec(commitment.data())
                .map_err(|e| Error::circuit_error("Serialization failed", e.to_string()))?,
        )?;

        let data_var = self.allocate_g1_point(&data_point);
        let blinding_var = self.allocate_scalar(commitment.blinding());

        let comm_constraint = Constraint {
            left: vec![(Scalar::one(), data_var)],
            right: vec![(Scalar::one(), blinding_var)],
            output: vec![(Scalar::one(), value_var)],
        };
        self.constraints.push(comm_constraint);
        Ok(())
    }

    fn enforce_signature_validity(
        &mut self,
        aggregate_sig: &AggregateSignature,
        commitment: &StateMatrixCommitment,
    ) -> Result<()> {
        let sig_var = self.allocate_g1_point(&aggregate_sig.aggregate);

        let mut pk_vars = Vec::new();
        for pubkey in &aggregate_sig.public_keys {
            let mut pk_bytes = Vec::new();
            pubkey
                .serialize_compressed(&mut pk_bytes)
                .map_err(|e| Error::circuit_error("Serialization failed", e.to_string()))?;
            let pk_point = self.groups.hash_to_g1(&pk_bytes)?;
            pk_vars.push(self.allocate_g1_point(&pk_point));
        }

        self.enforce_aggregate_equation(sig_var, &pk_vars, commitment)?;

        Ok(())
    }

    fn enforce_policy_requirements(&mut self, commitment: &StateMatrixCommitment) -> Result<()> {
        let admin_count =
            self.allocate_scalar(&Scalar::from(commitment.data().signing_keys().len() as u64));

        let threshold_constraint = Constraint {
            left: vec![(Scalar::one(), admin_count)],
            right: vec![(Scalar::from(2u64), self.allocate_variable())],
            output: vec![(Scalar::zero(), self.allocate_variable())],
        };
        self.constraints.push(threshold_constraint);

        Ok(())
    }

    fn enforce_g1_point_on_curve(&mut self, point: &G1, var: Variable) {
        let (x, y) = match point.xy() {
            Some((x, y)) => (x, y),
            None => panic!("Point must not be at infinity"),
        };

        let x_scalar = fq_to_fr(x);
        let y_scalar = fq_to_fr(y);

        let curve_constraint = Constraint {
            left: vec![(Scalar::one(), var)],
            right: vec![(y_scalar, var)],
            output: vec![(x_scalar, var)],
        };
        self.constraints.push(curve_constraint);
    }

    fn enforce_g2_point_on_curve(&mut self, point: &G2, var: Variable) {
        let (x, y) = match point.xy() {
            Some((x, y)) => (x, y),
            None => panic!("G2 point must not be at infinity"),
        };

        let x_c0 = fq_to_fr(x.c0);
        let x_c1 = fq_to_fr(x.c1);
        let y_c0 = fq_to_fr(y.c0);
        let y_c1 = fq_to_fr(y.c1);

        let curve_constraint_real = Constraint {
            left: vec![(x_c0, var)],
            right: vec![(y_c0, var)],
            output: vec![(Scalar::zero(), self.allocate_variable())],
        };
        let curve_constraint_imag = Constraint {
            left: vec![(x_c1, var)],
            right: vec![(y_c1, var)],
            output: vec![(Scalar::zero(), self.allocate_variable())],
        };

        self.constraints.push(curve_constraint_real);
        self.constraints.push(curve_constraint_imag);
    }

    fn enforce_scalar_range(&mut self, value: &Scalar, var: Variable) {
        let range_constraint = Constraint {
            left: vec![(Scalar::one(), var)],
            right: vec![(*value, var)],
            output: vec![(Scalar::zero(), self.allocate_variable())],
        };
        self.constraints.push(range_constraint);
    }

    pub(crate) fn serialize_constraints(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        for constraint in &self.constraints {
            serialize_terms(&mut buf, &constraint.left)?;
            serialize_terms(&mut buf, &constraint.right)?;
            serialize_terms(&mut buf, &constraint.output)?;
        }
        Ok(buf)
    }

    fn enforce_aggregate_equation(
        &mut self,
        sig_var: Variable,
        pk_vars: &[Variable],
        commitment: &StateMatrixCommitment,
    ) -> Result<()> {
        let message_point = self.groups.hash_to_g1(
            &serde_json::to_vec(commitment.data())
                .map_err(|e| Error::circuit_error("Serialization failed", e.to_string()))?,
        )?;
        let message_var = self.allocate_g1_point(&message_point);

        let g2_var = self.allocate_variable();
        let agg_pk_var = self.allocate_variable();

        let pk_sum_constraint = Constraint {
            left: pk_vars.iter().map(|&pk| (Scalar::one(), pk)).collect(),
            right: vec![],
            output: vec![(Scalar::one(), agg_pk_var)],
        };
        self.constraints.push(pk_sum_constraint);

        let pairing_constraint = Constraint {
            left: vec![(Scalar::one(), sig_var), (Scalar::one(), g2_var)],
            right: vec![(Scalar::one(), message_var), (Scalar::one(), agg_pk_var)],
            output: vec![(Scalar::zero(), self.allocate_variable())],
        };
        self.constraints.push(pairing_constraint);

        Ok(())
    }

    pub fn verify_access_grant(
        &mut self,
        commitment: &StateMatrixCommitment,
        proof: &MerkleProof,
        signature: &AggregateSignature,
    ) -> Result<()> {
        // Verify Merkle inclusion
        self.enforce_merkle_membership(proof, &proof.root, commitment)?;

        // Verify commitment structure
        self.enforce_commitment_structure(commitment)?;

        // Verify authorization
        self.enforce_signature_validity(signature, commitment)?;

        // Verify policy compliance
        self.enforce_policy_requirements(commitment)?;

        // Verify not revoked
        self.enforce_not_revoked(commitment)?;

        Ok(())
    }

    fn enforce_not_revoked(&mut self, commitment: &StateMatrixCommitment) -> Result<()> {
        if commitment.is_revoked() {
            return Err(Error::validation_failed(
                "Grant is revoked",
                "Cannot verify revoked access grant",
            ));
        }

        let revocation_point = commitment.get_revocation_data();
        let revocation_var = self.allocate_g1_point(&revocation_point);

        let expected_var = self.allocate_g1_point(commitment.value());

        self.enforce_equal(revocation_var, expected_var);

        Ok(())
    }

    pub fn enforce_policy_transition(&mut self, old_policy: Variable, new_policy: Variable) {
        let intermediate_var = self.allocate_variable();
        self.constraints.push(Constraint {
            left: vec![(Scalar::one(), old_policy)],
            right: vec![(Scalar::one(), intermediate_var)],
            output: vec![(Scalar::one(), new_policy)],
        });
    }

    pub fn enforce_key_succession(&mut self, old_key: Variable, new_key: Variable) {
        let intermediate_var = self.allocate_variable();
        self.constraints.push(Constraint {
            left: vec![(Scalar::one(), old_key)],
            right: vec![(Scalar::one(), intermediate_var)],
            output: vec![(Scalar::one(), new_key)],
        });
    }
}

fn fq_to_fr(fq: Fq) -> Fr {
    let bytes = fq.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

fn serialize_terms(buf: &mut Vec<u8>, terms: &[(Scalar, Variable)]) -> Result<()> {
    for (coeff, var) in terms {
        coeff
            .serialize_compressed(&mut *buf)
            .map_err(|e| Error::circuit_error("Serialization failed", e.to_string()))?;
        var.0
            .serialize_compressed(&mut *buf)
            .map_err(|e| Error::circuit_error("Serialization failed", e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        commitment::StateMatrixEntry,
        primitives::{DomainSeparationTags, RandomGenerator},
        BlsSignature, PedersenCommitment, ProofTranscript, G2,
    };
    use ark_ec::CurveGroup;
    use serde_json::json;

    fn create_test_commitment(
        groups: &Arc<CurveGroups>,
        rng: &RandomGenerator,
    ) -> StateMatrixCommitment {
        let entry = StateMatrixEntry::new(
            rng.random_bytes(32).try_into().unwrap(),
            rng.random_bytes(32).try_into().unwrap(),
            1,
            vec![1, 2, 3],
            1,
            42u32,
            vec![G2::zero().into()],
        );

        let mut pedersen = PedersenCommitment::new(**groups);
        let blinding = rng.random_scalar();
        let mut transcript = ProofTranscript::new(DomainSeparationTags::COMMITMENT, groups.clone());

        pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .expect("Failed to create commitment")
    }

    fn create_test_proof(groups: &Arc<CurveGroups>) -> MerkleProof {
        MerkleProof {
            siblings: vec![groups.random_g1().into(), groups.random_g1().into()],
            path: vec![groups.random_g1().into(), groups.random_g1().into()],
            root: groups.random_g1().into(),
            value: groups.random_g1().into(),
        }
    }

    fn create_test_signature(
        commitment: &StateMatrixCommitment,
        groups: &Arc<CurveGroups>,
        rng: &RandomGenerator,
    ) -> AggregateSignature {
        let secret_key = rng.random_scalar();
        let message = serde_json::to_vec(commitment.data()).unwrap();
        let signature =
            BlsSignature::sign(&message, &secret_key, groups).expect("Failed to create signature");

        AggregateSignature::aggregate(&[signature]).expect("Failed to aggregate signature")
    }

    #[test]
    fn test_circuit_construction() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));

        let var1 = circuit.allocate_variable();
        let var2 = circuit.allocate_variable();
        assert_ne!(var1, var2);
        assert_eq!(circuit.next_var, 2);

        circuit.enforce_equal(var1, var2);
        assert_eq!(circuit.constraints.len(), 1);
    }

    #[test]
    fn test_merkle_constraints() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let mut pedersen = PedersenCommitment::new(*groups);
        let rng = RandomGenerator::new();

        let entry = StateMatrixEntry::new(
            [1u8; 32],
            [2u8; 32],
            1,
            vec![1, 2, 3],
            1,
            42u32,
            vec![G2::zero().into()],
        );
        let blinding = rng.random_scalar();
        let mut transcript = ProofTranscript::new(b"test-commitment", groups.clone());
        let commitment = pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .expect("Failed to create commitment");

        let proof = MerkleProof {
            siblings: vec![groups.random_g1().into(), groups.random_g1().into()],
            path: vec![groups.random_g1().into(), groups.random_g1().into()],
            root: groups.random_g1().into(),
            value: (*commitment.value()).into(),
        };

        circuit
            .enforce_merkle_membership(&proof, &proof.root, &commitment)
            .expect("Should create Merkle constraints");

        assert!(!circuit.constraints.is_empty());
    }

    #[test]
    fn test_state_transition() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let mut pedersen = PedersenCommitment::new(*groups);
        let rng = RandomGenerator::new();

        // Create old and new states
        let old_entry = StateMatrixEntry::new(
            [1u8; 32],
            [2u8; 32],
            1,
            vec![1, 2, 3],
            1,
            42u32,
            vec![G2::zero().into()],
        );
        let new_entry = StateMatrixEntry::new(
            [1u8; 32],
            [2u8; 32],
            1,
            vec![1, 2, 3],
            2, // Different policy generation
            42u32,
            vec![G2::zero().into()],
        );

        let mut transcript = ProofTranscript::new(b"test-commitment", groups.clone());
        let old_state = pedersen
            .commit_state_entry(old_entry, &rng.random_scalar(), &mut transcript)
            .unwrap();
        let new_state = pedersen
            .commit_state_entry(new_entry, &rng.random_scalar(), &mut transcript)
            .unwrap();

        // Create admin signatures
        let secret_key = rng.random_scalar();
        let signature = BlsSignature::sign(
            &serde_json::to_vec(&new_state.data()).unwrap(),
            &secret_key,
            &groups,
        )
        .unwrap();
        let aggregate = AggregateSignature::aggregate(&[signature]).unwrap();

        // Enforce state transition
        circuit
            .enforce_state_transition(&old_state, &new_state, &aggregate, 2)
            .expect("Should create state transition constraints");

        assert!(!circuit.constraints.is_empty());
    }

    #[test]
    fn test_access_verification() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let rng = RandomGenerator::new();

        // Create test commitment
        let entry = StateMatrixEntry::new(
            [1u8; 32],
            [2u8; 32],
            1,
            vec![1, 2, 3],
            1,
            42u32,
            vec![G2::zero().into()],
        );

        let mut pedersen = PedersenCommitment::new(*groups);
        let blinding = rng.random_scalar();
        let mut transcript =
            ProofTranscript::new(DomainSeparationTags::ACCESS_PROOF, groups.clone());
        let commitment = pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .expect("Failed to create commitment");

        // Generate valid Merkle proof with non-zero points
        let merkle_path = (0..2)
            .map(|_| {
                (groups.g1_generator * rng.random_scalar())
                    .into_affine()
                    .into()
            })
            .collect();

        let merkle_siblings = (0..2)
            .map(|_| {
                (groups.g1_generator * rng.random_scalar())
                    .into_affine()
                    .into()
            })
            .collect();

        let proof = MerkleProof {
            siblings: merkle_siblings,
            path: merkle_path,
            root: (groups.g1_generator * rng.random_scalar())
                .into_affine()
                .into(),
            value: (*commitment.value()).into(),
        };

        // Create valid BLS signature
        let secret_key = rng.random_scalar();
        let data = serde_json::to_vec(&commitment.data()).unwrap();
        let signature = BlsSignature::sign(&data, &secret_key, &groups).unwrap();
        let aggregate = AggregateSignature::aggregate(&[signature]).unwrap();

        // Verify access grant
        circuit
            .verify_access_grant(&commitment, &proof, &aggregate)
            .expect("Access verification should succeed");

        assert!(!circuit.constraints.is_empty());
    }

    #[test]
    fn test_revoked_access() {
        let groups = Arc::new(CurveGroups::new());
        let mut circuit = Circuit::new(Arc::clone(&groups));
        let rng = RandomGenerator::new();

        let mut commitment = create_test_commitment(&groups, &rng);

        // Create valid signature for revocation
        let secret_key = rng.random_scalar();
        let revocation_data = b"revocation";
        let signature = BlsSignature::sign(revocation_data, &secret_key, &groups).unwrap();

        // Revoke with valid signature
        commitment
            .revoke(
                vec![signature],
                Some(json!({"reason": "test revocation"})),
                &groups,
            )
            .unwrap();

        let proof = create_test_proof(&groups);
        let access_signature = create_test_signature(&commitment, &groups, &rng);

        // Verification should fail for revoked grant
        assert!(circuit
            .verify_access_grant(&commitment, &proof, &access_signature)
            .is_err());
    }
}
