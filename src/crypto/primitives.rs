use crate::errors::Result;
use ark_bls12_377::{Bls12_377, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use blake3::Hasher;
use merlin::Transcript;
use rand::{thread_rng, RngCore};

pub type Scalar = Fr;
pub type G1 = G1Affine;
pub type G2 = G2Affine;
pub type GT = <Bls12_377 as Pairing>::TargetField;

#[derive(Clone)]
pub struct ProofTranscript {
    inner: Transcript,
}

impl ProofTranscript {
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            inner: Transcript::new(label),
        }
    }

    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.inner.append_message(label, message);
    }

    pub fn append_point(&mut self, label: &'static [u8], point: &G1) {
        let mut buf = Vec::new();
        point.serialize_compressed(&mut buf).unwrap();
        self.inner.append_message(label, &buf);
    }

    pub fn append_g2_point(&mut self, label: &'static [u8], point: &G2) {
        let mut buf = Vec::new();
        point.serialize_compressed(&mut buf).unwrap();
        self.inner.append_message(label, &buf);
    }

    pub fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.inner
            .append_message(label, &scalar.into_bigint().to_bytes_le());
    }

    pub fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.inner.challenge_bytes(label, &mut buf);
        Scalar::from_le_bytes_mod_order(&buf)
    }

    pub fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.inner.challenge_bytes(label, dest);
    }
}

#[derive(Clone)]
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

/// Domain separation tags for different protocol components
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
        let mut transcript = ProofTranscript::new(b"test-protocol");
        let scalar = Scalar::from(42u64);
        let point = G1::generator();

        transcript.append_scalar(b"test-scalar", &scalar);
        transcript.append_point(b"test-point", &point);

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
}
