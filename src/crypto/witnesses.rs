use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    crypto::{
        circuits::TimeUnits,
        primitives::{CurveGroups, DomainSeparationTags, ProofTranscript, Scalar, G1},
        Circuit, SerializableG1, TimeConstraint,
    },
    errors::{Error, Result},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessCommitment {
    pub value: SerializableG1,
    pub epoch: u64,
    pub nonce: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HistoricalWitness {
    pub commitment: WitnessCommitment,
    pub value: Scalar,
    pub precomputed: Vec<G1>,
}

#[derive(Clone, Debug)]
pub struct ChainWitness {
    pub witnesses: Vec<HistoricalWitness>,
    pub transcript_binding: Vec<u8>,
    pub start_epoch: u64,
    pub end_epoch: u64,
}

pub struct WitnessSystem {
    groups: Arc<CurveGroups>,
    transcript: ProofTranscript,
    witness_cache: DashMap<[u8; 32], HistoricalWitness>,
    chain_cache: DashMap<[u8; 32], ChainWitness>,
    current_epoch: u64,
}

impl WitnessSystem {
    pub fn new(groups: Arc<CurveGroups>) -> Self {
        Self {
            groups: Arc::clone(&groups),
            transcript: ProofTranscript::new(DomainSeparationTags::WITNESS, Arc::clone(&groups)),
            witness_cache: DashMap::new(),
            chain_cache: DashMap::new(),
            current_epoch: 0,
        }
    }

    pub fn create_witness(
        &mut self,
        value: &Scalar,
        epoch: u64,
        constraint: &TimeConstraint,
    ) -> Result<HistoricalWitness> {
        if epoch < constraint.start_time || constraint.end_time.map_or(false, |end| epoch >= end) {
            return Err(Error::validation_failed(
                "Invalid epoch for constraint",
                "Epoch must be within constraint window",
            ));
        }

        let mut transcript = self.transcript.clone();
        let nonce = self.generate_nonce(&mut transcript)?;

        transcript.append_message(b"constraint", &constraint.start_time.to_le_bytes());
        if let Some(end) = constraint.end_time {
            transcript.append_message(b"end_time", &end.to_le_bytes());
        }

        let commitment = self.commit_witness(value, epoch, &nonce)?;
        let precomputed = self.precompute_witness_values(value, &commitment)?;

        let witness = HistoricalWitness {
            commitment: WitnessCommitment {
                value: commitment.into(),
                epoch,
                nonce,
            },
            value: *value,
            precomputed,
        };

        let key = self.compute_witness_key(&witness);
        self.witness_cache.insert(key, witness.clone());

        Ok(witness)
    }

    pub fn create_witness_chain(
        &mut self,
        values: &[Scalar],
        start_epoch: u64,
        step: u64,
    ) -> Result<ChainWitness> {
        if values.is_empty() {
            return Err(Error::validation_failed(
                "Empty witness chain",
                "At least one witness required",
            ));
        }

        let mut witnesses = Vec::with_capacity(values.len());
        let mut current_epoch = start_epoch;

        for value in values {
            let constraint = TimeConstraint {
                start_time: current_epoch,
                end_time: Some(current_epoch + step),
                units: TimeUnits::Epochs,
            };

            let witness = self.create_witness(value, current_epoch, &constraint)?;
            witnesses.push(witness);
            current_epoch += step;
        }

        let mut transcript = self.transcript.clone();
        transcript.append_message(b"chain-start", &start_epoch.to_le_bytes());
        transcript.append_message(b"chain-end", &current_epoch.to_le_bytes());

        let binding_scalar = transcript.challenge_scalar(b"chain-binding");
        let mut binding = Vec::new();
        binding_scalar
            .serialize_compressed(&mut binding)
            .expect("Serialization cannot fail");

        let chain = ChainWitness {
            witnesses,
            transcript_binding: binding,
            start_epoch,
            end_epoch: current_epoch,
        };

        let key = self.compute_chain_key(&chain);
        self.chain_cache.insert(key, chain.clone());

        Ok(chain)
    }

    pub fn verify_witness(
        &self,
        witness: &HistoricalWitness,
        circuit: &mut Circuit,
    ) -> Result<bool> {
        if witness.commitment.epoch > self.current_epoch {
            return Ok(false);
        }

        let recomputed = self.commit_witness(
            &witness.value,
            witness.commitment.epoch,
            &witness.commitment.nonce,
        )?;

        if recomputed != *witness.commitment.value {
            return Ok(false);
        }

        let value_var = circuit.allocate_scalar(&witness.value);

        let time_constraint = TimeConstraint {
            start_time: witness.commitment.epoch,
            end_time: Some(witness.commitment.epoch + 1),
            units: TimeUnits::Epochs,
        };

        circuit.enforce_time_constraint(&time_constraint, value_var)?;

        for (i, precomputed) in witness.precomputed.iter().enumerate() {
            let expected = (recomputed.into_group() * witness.value.pow([i as u64])).into_affine();
            if *precomputed != expected {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn verify_witness_chain(
        &self,
        chain: &ChainWitness,
        circuit: &mut Circuit,
    ) -> Result<bool> {
        if chain.witnesses.is_empty() || chain.start_epoch > self.current_epoch {
            return Ok(false);
        }

        for (i, witness) in chain.witnesses.iter().enumerate() {
            if witness.commitment.epoch != chain.start_epoch + i as u64 {
                return Ok(false);
            }

            if !self.verify_witness(witness, circuit)? {
                return Ok(false);
            }

            let expected_value = Scalar::from((i + 1) as u64);
            let value_var = circuit.allocate_scalar(&witness.value);
            let expected_var = circuit.allocate_scalar(&expected_value);

            circuit.enforce_equal(value_var, expected_var);
        }

        Ok(chain.end_epoch == chain.start_epoch + chain.witnesses.len() as u64)
    }

    pub fn update_epoch(&mut self, new_epoch: u64) -> Result<()> {
        if new_epoch <= self.current_epoch {
            return Err(Error::validation_failed(
                "Invalid epoch update",
                "New epoch must be greater than current",
            ));
        }

        self.witness_cache
            .retain(|_, witness| witness.commitment.epoch + WITNESS_EXPIRY > new_epoch);

        self.chain_cache
            .retain(|_, chain| chain.end_epoch + WITNESS_EXPIRY > new_epoch);

        self.current_epoch = new_epoch;
        Ok(())
    }

    pub fn get_cached_witness(&self, key: &[u8; 32]) -> Option<HistoricalWitness> {
        self.witness_cache.get(key).map(|w| w.clone())
    }

    pub fn get_cached_chain(&self, key: &[u8; 32]) -> Option<ChainWitness> {
        self.chain_cache.get(key).map(|c| c.clone())
    }
    fn generate_nonce(&self, transcript: &mut ProofTranscript) -> Result<Vec<u8>> {
        let challenge = transcript.challenge_scalar(DomainSeparationTags::WITNESS);
        let mut nonce = Vec::new();
        challenge.serialize_compressed(&mut nonce)?;
        Ok(nonce)
    }

    fn commit_witness(&self, value: &Scalar, epoch: u64, nonce: &[u8]) -> Result<G1> {
        let mut point = G1::zero().into_group();
        point += self.groups.g1_generator.into_group() * value;
        point += self
            .groups
            .hash_to_g1(&[&epoch.to_le_bytes(), nonce].concat())?;
        Ok(point.into_affine())
    }

    fn precompute_witness_values(&self, value: &Scalar, commitment: &G1) -> Result<Vec<G1>> {
        let powers: Vec<_> = (0..PRECOMPUTE_DEPTH)
            .into_par_iter()
            .map(|i| value.pow([i as u64]))
            .collect();

        let values: Vec<_> = powers
            .into_par_iter()
            .map(|power| (commitment.into_group() * power).into_affine())
            .collect();

        Ok(values)
    }

    fn compute_witness_key(&self, witness: &HistoricalWitness) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&witness.commitment.epoch.to_le_bytes());
        hasher.update(&witness.commitment.nonce);
        *hasher.finalize().as_bytes()
    }

    fn compute_chain_key(&self, chain: &ChainWitness) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&chain.start_epoch.to_le_bytes());
        hasher.update(&chain.end_epoch.to_le_bytes());
        hasher.update(&chain.transcript_binding);
        *hasher.finalize().as_bytes()
    }
}

const WITNESS_EXPIRY: u64 = 1000;
const PRECOMPUTE_DEPTH: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::RandomGenerator;

    fn setup_test_system() -> WitnessSystem {
        let groups = Arc::new(CurveGroups::new());
        WitnessSystem::new(groups)
    }

    #[test]
    fn test_witness_creation() {
        let mut system = setup_test_system();
        let rng = RandomGenerator::new();
        let value = rng.random_scalar();

        let constraint = TimeConstraint {
            start_time: 0,
            end_time: Some(100),
            units: TimeUnits::Epochs,
        };

        let witness = system.create_witness(&value, 0, &constraint).unwrap();
        assert_eq!(witness.value, value);
        assert_eq!(witness.commitment.epoch, 0);
        assert!(!witness.precomputed.is_empty());
    }

    #[test]
    fn test_witness_chain() {
        let mut system = setup_test_system();
        let rng = RandomGenerator::new();
        let values: Vec<_> = (0..3).map(|_| rng.random_scalar()).collect();

        let chain = system.create_witness_chain(&values, 0, 1).unwrap();
        assert_eq!(chain.witnesses.len(), 3);
        assert_eq!(chain.start_epoch, 0);
        assert_eq!(chain.end_epoch, 3);
    }

    #[test]
    fn test_witness_verification() {
        let mut system = setup_test_system();
        let rng = RandomGenerator::new();
        let value = rng.random_scalar();
        let mut circuit = Circuit::new(Arc::clone(&system.groups));

        let constraint = TimeConstraint {
            start_time: 0,
            end_time: Some(100),
            units: TimeUnits::Epochs,
        };

        let witness = system.create_witness(&value, 0, &constraint).unwrap();
        assert!(system.verify_witness(&witness, &mut circuit).unwrap());
    }

    #[test]
    fn test_chain_verification() {
        let mut system = setup_test_system();

        // Create sequential values for better testing
        let values: Vec<_> = (0..3).map(|i| Scalar::from((i + 1) as u64)).collect();

        // Create witness chain with proper epoch sequencing
        let chain = system.create_witness_chain(&values, 0, 1).unwrap();

        // Update system epoch so that all witness epochs (0..=2) are valid
        system.update_epoch(chain.end_epoch).unwrap();

        let mut circuit = Circuit::new(Arc::clone(&system.groups));

        // Verify chain properties
        assert_eq!(chain.witnesses.len(), 3);
        assert_eq!(chain.start_epoch, 0);
        assert_eq!(chain.end_epoch, 3);

        // Verify sequential epochs
        for (i, witness) in chain.witnesses.iter().enumerate() {
            assert_eq!(witness.commitment.epoch, i as u64);
        }

        // Verify complete chain
        assert!(system.verify_witness_chain(&chain, &mut circuit).unwrap());

        // Verify chain fails with incorrect epoch sequence
        let mut bad_chain = chain.clone();
        bad_chain.witnesses[1].commitment.epoch += 1;
        assert!(!system
            .verify_witness_chain(&bad_chain, &mut circuit)
            .unwrap());
    }

    #[test]
    fn test_epoch_update() {
        let mut system = setup_test_system();
        let rng = RandomGenerator::new();
        let value = rng.random_scalar();

        let constraint = TimeConstraint {
            start_time: 0,
            end_time: Some(100),
            units: TimeUnits::Epochs,
        };

        let witness = system.create_witness(&value, 0, &constraint).unwrap();
        let key = system.compute_witness_key(&witness);

        assert!(system.get_cached_witness(&key).is_some());

        system.update_epoch(WITNESS_EXPIRY + 1).unwrap();
        assert!(system.get_cached_witness(&key).is_none());
    }

    #[test]
    fn test_witness_caching() {
        let mut system = setup_test_system();
        let rng = RandomGenerator::new();
        let value = rng.random_scalar();

        let constraint = TimeConstraint {
            start_time: 0,
            end_time: Some(100),
            units: TimeUnits::Epochs,
        };

        let witness = system.create_witness(&value, 0, &constraint).unwrap();
        let key = system.compute_witness_key(&witness);

        let cached = system.get_cached_witness(&key).unwrap();
        assert_eq!(cached.value, value);
        assert_eq!(cached.commitment.epoch, 0);
    }
}
