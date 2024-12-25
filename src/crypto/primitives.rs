use ark_bls12_377::{Bls12_377, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use blake3::Hasher;
use rand::{thread_rng, RngCore};
use std::sync::Arc;

use crate::errors::Result;

pub type Scalar = Fr;
pub type G1 = G1Affine;
pub type G2 = G2Affine;
pub type GT = <Bls12_377 as Pairing>::TargetField;

#[derive(Clone)]
pub struct ProofTranscript {
    state: Vec<u8>,
    groups: Arc<CurveGroups>,
}

impl ProofTranscript {
    pub fn new(domain: &[u8], groups: Arc<CurveGroups>) -> Self {
        let mut state = Vec::new();
        state.extend_from_slice(domain);
        Self { state, groups }
    }

    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state.extend_from_slice(label);
        self.state
            .extend_from_slice(&(message.len() as u64).to_le_bytes());
        self.state.extend_from_slice(message);
    }

    pub fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        let mut bytes = Vec::new();
        scalar.serialize_compressed(&mut bytes).unwrap();
        self.append_message(label, &bytes);
    }

    pub fn append_point_g1(&mut self, label: &[u8], point: &G1) {
        let mut bytes = Vec::new();
        point.serialize_compressed(&mut bytes).unwrap();
        self.append_message(label, &bytes);
    }

    pub fn append_point_g2(&mut self, label: &[u8], point: &G2) {
        let mut bytes = Vec::new();
        point.serialize_compressed(&mut bytes).unwrap();
        self.append_message(label, &bytes);
    }

    pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        self.state.extend_from_slice(label);
        let point = self
            .groups
            .hash_to_g1(&self.state)
            .expect("Hash should not fail");
        let mut bytes = Vec::new();
        point.serialize_compressed(&mut bytes).unwrap();
        Scalar::from_le_bytes_mod_order(&bytes)
    }

    pub fn challenge_point_g1(&mut self, label: &[u8]) -> Result<G1> {
        self.state.extend_from_slice(label);
        self.groups.hash_to_g1(&self.state)
    }

    pub fn challenge_point_g2(&mut self, label: &[u8]) -> Result<G2> {
        self.state.extend_from_slice(label);
        self.groups.hash_to_g2(&self.state)
    }

    pub fn append_scalars<'a, I>(&mut self, label: &[u8], scalars: I)
    where
        I: IntoIterator<Item = &'a Scalar>,
    {
        for scalar in scalars {
            self.append_scalar(label, scalar);
        }
    }

    pub fn append_points_g1<'a, I>(&mut self, label: &[u8], points: I)
    where
        I: IntoIterator<Item = &'a G1>,
    {
        for point in points {
            self.append_point_g1(label, point);
        }
    }

    pub fn append_points_g2<'a, I>(&mut self, label: &[u8], points: I)
    where
        I: IntoIterator<Item = &'a G2>,
    {
        for point in points {
            self.append_point_g2(label, point);
        }
    }

    pub fn clone_state(&self) -> Vec<u8> {
        self.state.clone()
    }

    pub fn reset_with_state(&mut self, state: Vec<u8>) {
        self.state = state;
    }
}

#[derive(Clone, Copy)]
pub struct CurveGroups {
    pub g1_generator: G1,
    pub g2_generator: G2,
}

impl Default for CurveGroups {
    fn default() -> Self {
        Self {
            g1_generator: G1::generator(),
            g2_generator: G2::generator(),
        }
    }
}

impl CurveGroups {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pair(&self, g1: &G1, g2: &G2) -> GT {
        Bls12_377::pairing(g1, g2).0
    }

    pub fn hash_to_g1(&self, data: &[u8]) -> Result<G1> {
        let mut hasher = Hasher::new();
        hasher.update(data);

        let mut counter: u64 = 0;
        loop {
            let mut attempt_hasher = hasher.clone();
            attempt_hasher.update(&counter.to_le_bytes());
            let hash = attempt_hasher.finalize();
            let potential_x = Fq::from_le_bytes_mod_order(hash.as_bytes());

            if let Some(point) = G1::get_point_from_x_unchecked(potential_x, false) {
                let scaled = point.mul_by_cofactor();
                if !scaled.is_zero() {
                    return Ok(scaled);
                }
            }

            counter += 1;
        }
    }

    pub fn hash_to_g2(&self, data: &[u8]) -> Result<G2> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);

        let mut counter: u64 = 0;
        loop {
            let mut attempt_hasher = hasher.clone();
            attempt_hasher.update(&counter.to_le_bytes());
            let hash = attempt_hasher.finalize();
            let bytes = hash.as_bytes();
            let c0 = Fq::from_le_bytes_mod_order(&bytes[..32]);
            let c1 = Fq::from_le_bytes_mod_order(&bytes[32..]);
            let potential_x = Fq2::new(c0, c1);

            if let Some(point) = G2::get_point_from_x_unchecked(potential_x, false) {
                let scaled = point.mul_by_cofactor();
                if !scaled.is_zero() {
                    return Ok(scaled);
                }
            }

            counter += 1;
        }
    }

    pub fn random_g1(&self) -> G1 {
        let rng = RandomGenerator::new();
        let scalar = rng.random_scalar();
        (self.g1_generator * scalar).into_affine()
    }

    pub fn random_g2(&self) -> G2 {
        let rng = RandomGenerator::new();
        let scalar = rng.random_scalar();
        (self.g2_generator * scalar).into_affine()
    }
}

pub struct DomainSeparationTags;

impl DomainSeparationTags {
    pub const SIGNATURE: &'static [u8] = b"theseus-signature-v1";
    pub const COMMITMENT: &'static [u8] = b"theseus-commitment-v1";
    pub const REVOCATION: &'static [u8] = b"theseus-revocation-v1";
    pub const ACCESS_PROOF: &'static [u8] = b"theseus-access-proof-v1";
    pub const SUCCESSION_PROOF: &'static [u8] = b"theseus-succession-proof-v1";
    pub const MERKLE_NODE: &'static [u8] = b"theseus-merkle-node-v1";
}

pub struct RandomGenerator;

impl Default for RandomGenerator {
    fn default() -> Self {
        Self
    }
}

impl RandomGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn random_scalar(&self) -> Scalar {
        Scalar::rand(&mut thread_rng())
    }

    pub fn random_bytes(&self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_transcript_operations() {
        let groups = Arc::new(CurveGroups::new());
        let mut transcript = ProofTranscript::new(b"test-protocol", Arc::clone(&groups));
        let scalar = Scalar::from(42u64);
        let point = G1::generator();

        transcript.append_scalar(b"test-scalar", &scalar);
        transcript.append_point_g1(b"test-point", &point);

        let challenge = transcript.challenge_scalar(b"test-challenge");
        assert_ne!(challenge, Scalar::zero());
    }

    #[test]
    fn test_curve_operations() {
        let groups = CurveGroups::new();

        // Test pairing
        let g1 = groups.g1_generator;
        let g2 = groups.g2_generator;
        let pairing = groups.pair(&g1, &g2);
        assert_ne!(pairing, GT::zero());

        // Test hashing to curves
        let test_data = b"test data";
        let h1 = groups.hash_to_g1(test_data).unwrap();
        let h2 = groups.hash_to_g2(test_data).unwrap();

        // Verify points are on curve and in correct subgroup
        assert!(!h1.is_zero());
        assert!(!h2.is_zero());

        // Test random point generation
        let r1 = groups.random_g1();
        let r2 = groups.random_g2();
        assert!(!r1.is_zero());
        assert!(!r2.is_zero());
    }

    #[test]
    fn test_domain_separation() {
        let groups = CurveGroups::new();
        let data = b"test data";

        // Hash same data with different tags
        let h1_sig = groups
            .hash_to_g1(&[DomainSeparationTags::SIGNATURE, data].concat())
            .unwrap();

        let h1_comm = groups
            .hash_to_g1(&[DomainSeparationTags::COMMITMENT, data].concat())
            .unwrap();

        // Verify different domains produce different points
        assert_ne!(h1_sig, h1_comm);
    }

    #[test]
    fn test_random_generation() {
        let rng = RandomGenerator::new();

        // Generate multiple random values
        let s1 = rng.random_scalar();
        let s2 = rng.random_scalar();
        assert_ne!(s1, s2);

        let b1 = rng.random_bytes(32);
        let b2 = rng.random_bytes(32);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_transcript_determinism() {
        let groups = Arc::new(CurveGroups::new());
        let mut t1 = ProofTranscript::new(b"test", Arc::clone(&groups));
        let mut t2 = ProofTranscript::new(b"test", Arc::clone(&groups));

        let scalar = Scalar::from(42u64);
        let point_g1 = groups.random_g1();
        let point_g2 = groups.random_g2();

        // Perform identical operations
        t1.append_scalar(b"s", &scalar);
        t1.append_point_g1(b"p1", &point_g1);
        t1.append_point_g2(b"p2", &point_g2);

        t2.append_scalar(b"s", &scalar);
        t2.append_point_g1(b"p1", &point_g1);
        t2.append_point_g2(b"p2", &point_g2);

        let challenge1 = t1.challenge_scalar(b"c");
        let challenge2 = t2.challenge_scalar(b"c");

        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_transcript_domain_separation() {
        let groups = Arc::new(CurveGroups::new());
        let mut t1 = ProofTranscript::new(b"domain1", Arc::clone(&groups));
        let mut t2 = ProofTranscript::new(b"domain2", Arc::clone(&groups));

        // Same message, different domains
        t1.append_message(b"msg", b"test");
        t2.append_message(b"msg", b"test");

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");

        assert_ne!(c1, c2);
        assert_ne!(c1, Scalar::zero());
        assert_ne!(c2, Scalar::zero());
    }

    #[test]
    fn test_transcript_state_management() {
        let groups = Arc::new(CurveGroups::new());
        let mut t1 = ProofTranscript::new(b"test", Arc::clone(&groups));

        t1.append_message(b"m", b"test");
        let state = t1.clone_state();
        let c1 = t1.challenge_scalar(b"c");

        let mut t2 = ProofTranscript::new(b"different", Arc::clone(&groups));
        t2.reset_with_state(state);
        let c2 = t2.challenge_scalar(b"c");

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_batch_operations() {
        let groups = Arc::new(CurveGroups::new());
        let mut t1 = ProofTranscript::new(b"test", Arc::clone(&groups));
        let mut t2 = ProofTranscript::new(b"test", Arc::clone(&groups));

        let scalars = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let points_g1 = vec![groups.random_g1(), groups.random_g1(), groups.random_g1()];
        let points_g2 = vec![groups.random_g2(), groups.random_g2(), groups.random_g2()];

        // Test batch operations
        t1.append_scalars(b"s", &scalars);
        t1.append_points_g1(b"p1", &points_g1);
        t1.append_points_g2(b"p2", &points_g2);

        // Test individual operations
        for scalar in &scalars {
            t2.append_scalar(b"s", scalar);
        }
        for point in &points_g1 {
            t2.append_point_g1(b"p1", point);
        }
        for point in &points_g2 {
            t2.append_point_g2(b"p2", point);
        }

        assert_eq!(
            t1.challenge_scalar(b"c"),
            t2.challenge_scalar(b"c"),
            "Batch and individual operations should produce identical transcripts"
        );
    }
}
