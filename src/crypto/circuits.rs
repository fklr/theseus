use crate::{
    crypto::primitives::{CurveGroups, Scalar, G1, G2},
    errors::{Error, Result},
};
use ark_bls12_377::{Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Variable(pub(crate) usize);

#[derive(Clone, Debug)]
pub struct Constraint {
    // ax * bx = cx where x is the witness vector
    pub(crate) constraint_a: Vec<(Scalar, Variable)>,
    pub(crate) constraint_b: Vec<(Scalar, Variable)>,
    pub(crate) constraint_c: Vec<(Scalar, Variable)>,
}

#[derive(Clone, Debug)]
pub struct TimeConstraint {
    pub(crate) start_time: u64,
    pub(crate) end_time: Option<u64>,
    pub(crate) units: TimeUnits,
}

#[derive(Clone, Copy, Debug)]
pub enum TimeUnits {
    Seconds,
    Epochs,
    Blocks,
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

    pub fn enforce_equal(&mut self, constraint_a: Variable, constraint_b: Variable) {
        let constraint = Constraint {
            constraint_a: vec![(Scalar::one(), constraint_a)],
            constraint_b: vec![(Scalar::one(), constraint_b)],
            constraint_c: vec![(Scalar::zero(), self.allocate_variable())],
        };
        self.constraints.push(constraint);
    }

    pub fn enforce_policy_transition(&mut self, old_policy: Variable, new_policy: Variable) {
        let intermediate_var = self.allocate_variable();
        self.constraints.push(Constraint {
            constraint_a: vec![(Scalar::one(), old_policy)],
            constraint_b: vec![(Scalar::one(), intermediate_var)],
            constraint_c: vec![(Scalar::one(), new_policy)],
        });
    }

    pub fn enforce_key_succession(&mut self, old_key: Variable, new_key: Variable) {
        let intermediate_var = self.allocate_variable();
        self.constraints.push(Constraint {
            constraint_a: vec![(Scalar::one(), old_key)],
            constraint_b: vec![(Scalar::one(), intermediate_var)],
            constraint_c: vec![(Scalar::one(), new_key)],
        });
    }

    pub fn enforce_constraint(
        &mut self,
        constraint_a: Vec<(Scalar, Variable)>,
        constraint_b: Vec<(Scalar, Variable)>,
        constraint_c: Vec<(Scalar, Variable)>,
    ) {
        self.constraints.push(Constraint {
            constraint_a,
            constraint_b,
            constraint_c,
        });
    }

    pub fn verify_constraint(&self, constraint: &Constraint, values: &[Scalar]) -> bool {
        let a_eval = self.evaluate_terms(&constraint.constraint_a, values);
        let b_eval = self.evaluate_terms(&constraint.constraint_b, values);
        let c_eval = self.evaluate_terms(&constraint.constraint_c, values);

        a_eval * b_eval == c_eval
    }

    pub fn compute_constraint_commitment(&self, constraint: &Constraint) -> Result<G1> {
        let mut point = G1::zero().into_group();

        for (coeff, var) in &constraint.constraint_a {
            point += self.groups.g1_generator.into_group() * coeff * Scalar::from(var.0 as u64);
        }

        for (coeff, var) in &constraint.constraint_b {
            point += self.groups.g1_generator.into_group() * coeff * Scalar::from(var.0 as u64);
        }

        Ok(point.into_affine())
    }

    fn evaluate_terms(&self, terms: &[(Scalar, Variable)], values: &[Scalar]) -> Scalar {
        terms.iter().map(|(coeff, var)| values[var.0] * coeff).sum()
    }

    fn enforce_g1_point_on_curve(&mut self, point: &G1, var: Variable) {
        let (x, y) = match point.xy() {
            Some((x, y)) => (x, y),
            None => panic!("Point must not be at infinity"),
        };

        let x_scalar = fq_to_fr(x);
        let y_scalar = fq_to_fr(y);

        let curve_constraint = Constraint {
            constraint_a: vec![(Scalar::one(), var)],
            constraint_b: vec![(y_scalar, var)],
            constraint_c: vec![(x_scalar, var)],
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
            constraint_a: vec![(x_c0, var)],
            constraint_b: vec![(y_c0, var)],
            constraint_c: vec![(Scalar::zero(), self.allocate_variable())],
        };
        let curve_constraint_imag = Constraint {
            constraint_a: vec![(x_c1, var)],
            constraint_b: vec![(y_c1, var)],
            constraint_c: vec![(Scalar::zero(), self.allocate_variable())],
        };

        self.constraints.push(curve_constraint_real);
        self.constraints.push(curve_constraint_imag);
    }

    fn enforce_scalar_range(&mut self, value: &Scalar, var: Variable) {
        let range_constraint = Constraint {
            constraint_a: vec![(Scalar::one(), var)],
            constraint_b: vec![(*value, var)],
            constraint_c: vec![(Scalar::zero(), self.allocate_variable())],
        };
        self.constraints.push(range_constraint);
    }

    pub fn enforce_time_constraint(
        &mut self,
        constraint: &TimeConstraint,
        timestamp_var: Variable,
    ) -> Result<()> {
        let start = Scalar::from(constraint.start_time);
        let start_var = self.allocate_scalar(&start);
        let zero_var = self.allocate_variable();

        self.enforce_constraint(
            vec![(Scalar::one(), timestamp_var)],
            vec![(Scalar::one(), start_var)],
            vec![(Scalar::zero(), zero_var)],
        );

        if let Some(end_time) = constraint.end_time {
            let end = Scalar::from(end_time);
            let end_var = self.allocate_scalar(&end);
            let zero_var = self.allocate_variable();

            self.enforce_constraint(
                vec![(Scalar::one(), end_var)],
                vec![(Scalar::one(), timestamp_var)],
                vec![(Scalar::zero(), zero_var)],
            );
        }

        Ok(())
    }

    pub fn create_epoch_binding(
        &mut self,
        prev_epoch: Variable,
        next_epoch: Variable,
        units: TimeUnits,
    ) -> Result<()> {
        match units {
            TimeUnits::Epochs => {
                // Enforce epochs increment by 1
                let one = Scalar::from(1u64);
                let one_var = self.allocate_scalar(&one);
                let intermediate = self.allocate_variable();

                self.enforce_constraint(
                    vec![(Scalar::one(), prev_epoch), (Scalar::one(), one_var)],
                    vec![(Scalar::one(), intermediate)],
                    vec![(Scalar::one(), next_epoch)],
                );
            }
            _ => {
                return Err(Error::validation_failed(
                    "Invalid time units",
                    "Epoch binding requires TimeUnits::Epochs",
                ))
            }
        }
        Ok(())
    }

    pub fn enforce_epoch_binding(
        &mut self,
        prev_commitment: Variable,
        next_commitment: Variable,
        units: TimeUnits,
    ) -> Result<()> {
        match units {
            TimeUnits::Epochs => {
                let one = Scalar::from(1u64);
                let one_var = self.allocate_scalar(&one);
                let intermediate_var = self.allocate_variable();
                let sum_var = self.allocate_variable();

                // First constraint: prev_commitment + 1 = sum_var
                self.enforce_constraint(
                    vec![(Scalar::one(), prev_commitment), (Scalar::one(), one_var)],
                    vec![(Scalar::one(), intermediate_var)],
                    vec![(Scalar::one(), sum_var)],
                );

                // Second constraint: sum_var = next_commitment
                self.enforce_constraint(
                    vec![(Scalar::one(), sum_var)],
                    vec![(Scalar::one(), intermediate_var)],
                    vec![(Scalar::one(), next_commitment)],
                );

                // Additional constraint for epoch ordering
                self.enforce_constraint(
                    vec![(Scalar::one(), next_commitment)],
                    vec![(Scalar::one(), intermediate_var)],
                    vec![(Scalar::one(), sum_var)],
                );

                Ok(())
            }
            _ => Err(Error::validation_failed(
                "Invalid time units",
                "Epoch binding requires TimeUnits::Epochs",
            )),
        }
    }

    pub fn enforce_witness_sequence(
        &mut self,
        witnesses: &[Variable],
        time_step: u64,
    ) -> Result<()> {
        let step = Scalar::from(time_step);
        let step_var = self.allocate_scalar(&step);

        for window in witnesses.windows(2) {
            let prev = window[0];
            let next = window[1];
            let intermediate = self.allocate_variable();

            self.enforce_constraint(
                vec![(Scalar::one(), prev), (Scalar::one(), step_var)],
                vec![(Scalar::one(), intermediate)],
                vec![(Scalar::one(), next)],
            );
        }

        Ok(())
    }

    pub fn commit_time_locked_value(
        &mut self,
        value: &Scalar,
        unlock_time: u64,
        witness: Variable,
    ) -> Result<G1> {
        let time = Scalar::from(unlock_time);
        let time_var = self.allocate_scalar(&time);
        let value_var = self.allocate_scalar(value);
        let intermediate = self.allocate_variable();
        let zero = self.allocate_variable();

        self.enforce_constraint(
            vec![(Scalar::one(), witness)],
            vec![(Scalar::one(), time_var)],
            vec![(Scalar::one(), intermediate)],
        );

        self.enforce_constraint(
            vec![(Scalar::one(), intermediate)],
            vec![(Scalar::one(), value_var)],
            vec![(Scalar::zero(), zero)],
        );

        let mut point = G1::zero().into_group();
        point += self.groups.g1_generator.into_group() * value;
        point += self.groups.g1_generator.into_group() * time;

        Ok(point.into_affine())
    }

    pub fn verify_temporal_proof_chain(
        &self,
        proofs: &[Variable],
        start_time: u64,
        time_step: u64,
    ) -> Result<bool> {
        if proofs.len() < 2 {
            return Ok(true);
        }

        let mut values = vec![Scalar::zero(); self.next_var];
        let step = Scalar::from(time_step);

        values[proofs[0].0] = Scalar::from(start_time);

        // Initialize subsequent values
        for i in 1..proofs.len() {
            values[proofs[i].0] = values[proofs[i - 1].0] + step;
        }

        for window in proofs.windows(2) {
            let constraint = Constraint {
                constraint_a: vec![(Scalar::one(), window[0])],
                constraint_b: vec![(Scalar::one(), window[0])],
                constraint_c: vec![(Scalar::one(), window[1])],
            };

            if !self.verify_constraint(&constraint, &values) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn fq_to_fr(fq: Fq) -> Fr {
    let bytes = fq.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::RandomGenerator;
    use ark_ff::One;

    fn setup_test_circuit() -> Circuit {
        let groups = Arc::new(CurveGroups::new());
        Circuit::new(groups)
    }

    #[test]
    fn test_variable_allocation() {
        let mut circuit = setup_test_circuit();
        let var1 = circuit.allocate_variable();
        let var2 = circuit.allocate_variable();
        assert_eq!(var1.0 + 1, var2.0);
        assert_eq!(circuit.next_var, 2);
    }

    #[test]
    fn test_g1_point_allocation() {
        let mut circuit = setup_test_circuit();
        let point = circuit.groups.random_g1();
        circuit.allocate_g1_point(&point);

        // Verify the curve point constraint was added correctly
        let constraint = &circuit.constraints[0];
        assert_eq!(constraint.constraint_a.len(), 1);
        assert_eq!(constraint.constraint_b.len(), 1);
        assert_eq!(constraint.constraint_c.len(), 1);
    }

    #[test]
    fn test_g2_point_allocation() {
        let mut circuit = setup_test_circuit();
        let point = circuit.groups.random_g2();
        circuit.allocate_g2_point(&point);

        assert_eq!(circuit.constraints.len(), 2);
        let real_constraint = &circuit.constraints[0];
        let imag_constraint = &circuit.constraints[1];

        assert_eq!(real_constraint.constraint_a.len(), 1);
        assert_eq!(imag_constraint.constraint_a.len(), 1);
    }

    #[test]
    fn test_scalar_allocation() {
        let mut circuit = setup_test_circuit();
        let rng = RandomGenerator::new();
        let scalar = rng.random_scalar();
        circuit.allocate_scalar(&scalar);

        let constraint = &circuit.constraints[0];
        assert_eq!(constraint.constraint_b.len(), 1);
        assert_eq!(constraint.constraint_b[0].0, scalar);
    }

    #[test]
    fn test_equality_constraint() {
        let mut circuit = setup_test_circuit();
        let var1 = circuit.allocate_variable();
        let var2 = circuit.allocate_variable();
        circuit.enforce_equal(var1, var2);

        let constraint = &circuit.constraints[0];
        assert_eq!(constraint.constraint_a.len(), 1);
        assert_eq!(constraint.constraint_b.len(), 1);
        assert_eq!(constraint.constraint_a[0].0, Scalar::one());
    }

    #[test]
    fn test_policy_transition() {
        let mut circuit = setup_test_circuit();
        let old_policy = circuit.allocate_variable();
        let new_policy = circuit.allocate_variable();
        circuit.enforce_policy_transition(old_policy, new_policy);

        let constraint = &circuit.constraints[0];
        assert_eq!(constraint.constraint_c.len(), 1);
        assert_eq!(constraint.constraint_c[0].0, Scalar::one());
    }

    #[test]
    fn test_key_succession() {
        let mut circuit = setup_test_circuit();
        let old_key = circuit.allocate_variable();
        let new_key = circuit.allocate_variable();
        circuit.enforce_key_succession(old_key, new_key);

        let constraint = &circuit.constraints[0];
        assert!(!constraint.constraint_a.is_empty());
        assert!(!constraint.constraint_b.is_empty());
    }

    #[test]
    fn test_constraint_evaluation() {
        let mut circuit = setup_test_circuit();
        let var = circuit.allocate_variable();
        let value = Scalar::one();

        let constraint = Constraint {
            constraint_a: vec![(value, var)],
            constraint_b: vec![(value, var)],
            constraint_c: vec![(value * value, var)], // c = a * b for R1CS
        };

        let values = vec![value];
        let result = circuit.verify_constraint(&constraint, &values);
        assert!(result, "R1CS constraint should be satisfied");
    }

    #[test]
    fn test_constraint_verification() {
        let mut circuit = setup_test_circuit();
        let rng = RandomGenerator::new();
        let var = circuit.allocate_variable();
        let value = rng.random_scalar();

        // Create an R1CS constraint of the form: value * 1 = value
        let constraint = Constraint {
            constraint_a: vec![(Scalar::one(), var)],
            constraint_b: vec![(value, var)],
            constraint_c: vec![(value, var)],
        };

        let values = vec![Scalar::one()];
        let result = circuit.verify_constraint(&constraint, &values);
        assert!(result, "Constraint verification should succeed");
    }

    #[test]
    fn test_constraint_commitment() {
        let mut circuit = setup_test_circuit();
        let var = circuit.allocate_variable();

        let constraint = Constraint {
            constraint_a: vec![(Scalar::one(), var)],
            constraint_b: Vec::new(),
            constraint_c: Vec::new(),
        };

        let commitment = circuit.compute_constraint_commitment(&constraint).unwrap();
        assert!(commitment.is_on_curve());
    }

    #[test]
    fn test_curve_point_constraints() {
        let mut circuit = setup_test_circuit();
        let point = circuit.groups.random_g1();
        let var = circuit.allocate_variable();

        circuit.enforce_g1_point_on_curve(&point, var);
        assert!(!circuit.constraints.is_empty());

        let g2_point = circuit.groups.random_g2();
        let g2_var = circuit.allocate_variable();

        circuit.enforce_g2_point_on_curve(&g2_point, g2_var);
        assert_eq!(circuit.constraints.len(), 3); // G1 + G2 real + G2 imaginary
    }

    #[test]
    fn test_scalar_range_constraint() {
        let mut circuit = setup_test_circuit();
        let rng = RandomGenerator::new();
        let value = rng.random_scalar();
        let var = circuit.allocate_variable();

        circuit.enforce_scalar_range(&value, var);
        let constraint = circuit.constraints.last().unwrap();
        assert_eq!(constraint.constraint_b[0].0, value);
    }

    #[test]
    fn test_time_constraint() {
        let mut circuit = setup_test_circuit();
        let timestamp = circuit.allocate_variable();

        let constraint = TimeConstraint {
            start_time: 100,
            end_time: Some(200),
            units: TimeUnits::Seconds,
        };

        assert!(circuit
            .enforce_time_constraint(&constraint, timestamp)
            .is_ok());
    }

    #[test]
    fn test_epoch_binding() {
        let mut circuit = setup_test_circuit();
        let prev = circuit.allocate_variable();
        let next = circuit.allocate_variable();

        assert!(circuit
            .create_epoch_binding(prev, next, TimeUnits::Epochs)
            .is_ok());
    }

    #[test]
    fn test_epoch_binding_constraints() {
        let mut circuit = setup_test_circuit();

        // Create two sequential epoch values
        let prev_value = Scalar::from(5u64);
        let next_value = Scalar::from(6u64);

        // Allocate variables for the epoch values
        let prev_var = circuit.allocate_scalar(&prev_value);
        let next_var = circuit.allocate_scalar(&next_value);

        // Test successful binding
        assert!(circuit
            .enforce_epoch_binding(prev_var, next_var, TimeUnits::Epochs)
            .is_ok());

        // Verify constraints were created
        assert!(circuit.constraints.len() >= 3);

        // Verify constraint satisfaction
        let mut test_values = vec![Scalar::zero(); circuit.next_var];
        test_values[prev_var.0] = prev_value;
        test_values[next_var.0] = next_value;

        for constraint in &circuit.constraints {
            assert!(circuit.verify_constraint(constraint, &test_values));
        }
    }

    #[test]
    fn test_epoch_binding_invalid_units() {
        let mut circuit = setup_test_circuit();
        let rng = RandomGenerator::new();

        let prev_var = circuit.allocate_scalar(&rng.random_scalar());
        let next_var = circuit.allocate_scalar(&rng.random_scalar());

        // Test that non-epoch units are rejected
        assert!(circuit
            .enforce_epoch_binding(prev_var, next_var, TimeUnits::Seconds)
            .is_err());
        assert!(circuit
            .enforce_epoch_binding(prev_var, next_var, TimeUnits::Blocks)
            .is_err());
    }

    #[test]
    fn test_epoch_binding_non_sequential() {
        let mut circuit = setup_test_circuit();

        // Create non-sequential epoch values
        let prev_value = Scalar::from(5u64);
        let next_value = Scalar::from(7u64); // Gap of 2 instead of 1

        let prev_var = circuit.allocate_scalar(&prev_value);
        let next_var = circuit.allocate_scalar(&next_value);

        // Binding should be created successfully
        assert!(circuit
            .enforce_epoch_binding(prev_var, next_var, TimeUnits::Epochs)
            .is_ok());

        // But constraint verification should fail
        let mut test_values = vec![Scalar::zero(); circuit.next_var];
        test_values[prev_var.0] = prev_value;
        test_values[next_var.0] = next_value;

        let constraint_satisfied = circuit
            .constraints
            .iter()
            .all(|c| circuit.verify_constraint(c, &test_values));
        assert!(!constraint_satisfied);
    }

    #[test]
    fn test_witness_sequence() {
        let mut circuit = setup_test_circuit();
        let witnesses: Vec<_> = (0..3).map(|_| circuit.allocate_variable()).collect();

        assert!(circuit.enforce_witness_sequence(&witnesses, 3600).is_ok());
    }

    #[test]
    fn test_time_locked_commitment() {
        let mut circuit = setup_test_circuit();
        let rng = RandomGenerator::new();
        let value = rng.random_scalar();
        let witness = circuit.allocate_variable();

        let commitment = circuit.commit_time_locked_value(&value, 1000, witness);
        assert!(commitment.is_ok());
        assert!(commitment.unwrap().is_on_curve());
    }

    #[test]
    fn test_temporal_proof_chain() {
        let mut circuit = setup_test_circuit();
        let mut values = vec![];
        let mut vars = vec![];
        let step = 100u64;

        for i in 0..3 {
            let var = circuit.allocate_variable();
            values.push(Scalar::from(i * step));
            vars.push(var);
        }

        let result = circuit.verify_temporal_proof_chain(&vars, 0, step);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
