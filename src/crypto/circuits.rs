use crate::{
    crypto::primitives::{CurveGroups, Scalar, G1, G2},
    errors::Result,
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
}
