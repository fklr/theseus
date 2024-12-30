use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use crossbeam::queue::SegQueue;
use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;

use crate::{
    crypto::{
        commitment::{PedersenCommitment, StateMatrixCommitment, StateMatrixEntry},
        merkle::SparseMerkleTree,
        primitives::{CurveGroups, DomainSeparationTags, ProofTranscript, Scalar, G1, G2},
        proofs::{CircuitProof, ProofSystem, UnifiedProof},
        serialize::{SerializableG1, SerializableG2},
        signatures::{AggregateSignature, BlsSignature},
        Circuit, TimeConstraint, TimeUnits,
    },
    errors::{Error, Result},
    types::{ACLEntry, AdminKeySet, EntryId},
};

const RECOVERY_DOMAIN_THRESHOLD: usize = 3;
const CHECKPOINT_INTERVAL: u64 = 1000;

#[derive(Clone, Debug)]
pub struct RecoveryCheckpoint {
    pub state_root: SerializableG1,
    pub epoch: u64,
    pub admin_keys: Vec<SerializableG2>,
    pub commitment: StateMatrixCommitment,
}

#[derive(Clone, Debug)]
pub struct RecoveryDomain {
    pub domain_id: [u8; 32],
    pub authorities: Vec<SerializableG2>,
    pub threshold: usize,
    pub parent_domain: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub enum RecoveryPhase {
    Initiation {
        proof_of_compromise: CircuitProof,
        authority_signatures: Vec<BlsSignature>,
        affected_entries: Vec<EntryId>,
    },
    TrustEstablishment {
        new_admin_keys: Vec<SerializableG2>,
        succession_proof: CircuitProof,
        recovery_witness: RecoveryWitness,
    },
    StateReconstruction {
        state_proofs: Vec<CircuitProof>,
        grant_commitments: Vec<StateMatrixCommitment>,
        checkpoint_proof: CircuitProof,
    },
}

#[derive(Clone, Debug)]
pub struct RecoveryWitness {
    pub commitment: StateMatrixCommitment,
    pub nullifier: G1,
    pub epoch_proof: CircuitProof,
}

pub struct RecoverySystem {
    groups: Arc<CurveGroups>,
    proof_system: Arc<ProofSystem>,
    merkle_tree: Arc<SparseMerkleTree>,

    active_recoveries: DashMap<[u8; 32], RecoveryPhase>,
    recovery_domains: DashMap<[u8; 32], RecoveryDomain>,
    checkpoints: SegQueue<RecoveryCheckpoint>,
    current_admin: AtomicCell<AdminKeySet>,

    witness_cache: DashMap<EntryId, RecoveryWitness>,
    proof_cache: DashMap<[u8; 32], UnifiedProof>,
}

impl RecoverySystem {
    pub fn new(
        groups: Arc<CurveGroups>,
        proof_system: Arc<ProofSystem>,
        merkle_tree: Arc<SparseMerkleTree>,
        root_domain: RecoveryDomain,
    ) -> Self {
        let system = Self {
            groups,
            proof_system,
            merkle_tree,
            active_recoveries: DashMap::new(),
            recovery_domains: DashMap::new(),
            checkpoints: SegQueue::new(),
            current_admin: AtomicCell::new(AdminKeySet::default()),
            witness_cache: DashMap::new(),
            proof_cache: DashMap::new(),
        };

        system.recovery_domains.insert(root_domain.domain_id, root_domain);
        system
    }

    pub fn initiate_recovery(
        &self,
        domain_id: [u8; 32],
        compromised_entries: &[ACLEntry],
        authority_signatures: Vec<BlsSignature>,
    ) -> Result<UnifiedProof> {
        let domain = self.recovery_domains.get(&domain_id).ok_or_else(|| {
            Error::validation_failed("Invalid domain", "Recovery domain not found")
        })?;

        if authority_signatures.len() < domain.threshold {
            return Err(Error::validation_failed(
                "Insufficient signatures",
                "Must meet domain threshold",
            ));
        }

        let mut circuit = Circuit::new(Arc::clone(&self.groups));
        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::SUCCESSION_PROOF,
            Arc::clone(&self.groups),
        );

        let state_vars: Vec<_> = compromised_entries
            .iter()
            .map(|entry| {
                let var = circuit.allocate_scalar(&Scalar::from(entry.policy_generation as u64));
                circuit.enforce_time_constraint(
                    &TimeConstraint {
                        start_time: 0,
                        end_time: None,
                        units: TimeUnits::Epochs,
                    },
                    var,
                ).unwrap();
                var
            })
            .collect();

        let affected_entries: Vec<_> = compromised_entries
            .iter()
            .map(|entry| entry.id)
            .collect();

        let proof_of_compromise = CircuitProof::from(circuit);

        let phase = RecoveryPhase::Initiation {
            proof_of_compromise,
            authority_signatures,
            affected_entries,
        };

        self.active_recoveries.insert(domain_id, phase);

        let recovery_proof = UnifiedProof::Circuit(CircuitProof::from(circuit));
        self.proof_cache.insert(domain_id, recovery_proof.clone());

        Ok(recovery_proof)
    }

    pub fn establish_trust(
        &self,
        domain_id: [u8; 32],
        new_admin_keys: Vec<SerializableG2>,
    ) -> Result<UnifiedProof> {
        let phase = self.active_recoveries.get(&domain_id).ok_or_else(|| {
            Error::validation_failed("Invalid recovery", "No active recovery found")
        })?;

        let (proof_of_compromise, authority_sigs, affected_entries) = match phase.value() {
            RecoveryPhase::Initiation {
                proof_of_compromise,
                authority_signatures,
                affected_entries,
            } => (proof_of_compromise, authority_signatures, affected_entries),
            _ => return Err(Error::validation_failed(
                "Invalid phase",
                "Recovery not in initiation phase",
            )),
        };

        let mut circuit = Circuit::new(Arc::clone(&self.groups));

        let old_admin = self.current_admin.load();
        let old_key_vars: Vec<_> = old_admin.active_keys.iter()
            .map(|key| circuit.allocate_g2_point(key.inner()))
            .collect();

        let new_key_vars: Vec<_> = new_admin_keys.iter()
            .map(|key| circuit.allocate_g2_point(key.inner()))
            .collect();

        for (old, new) in old_key_vars.iter().zip(&new_key_vars) {
            circuit.enforce_key_succession(*old, *new);
        }

        let witness = self.generate_recovery_witness(affected_entries, &circuit)?;

        let phase = RecoveryPhase::TrustEstablishment {
            new_admin_keys,
            succession_proof: CircuitProof::from(circuit.clone()),
            recovery_witness: witness,
        };

        self.active_recoveries.insert(domain_id, phase);

        Ok(UnifiedProof::Circuit(CircuitProof::from(circuit)))
    }

    pub fn reconstruct_state(
        &self,
        domain_id: [u8; 32],
    ) -> Result<UnifiedProof> {
        let phase = self.active_recoveries.get(&domain_id).ok_or_else(|| {
            Error::validation_failed("Invalid recovery", "No active recovery found")
        })?;

        let (new_admin_keys, succession_proof, witness) = match phase.value() {
            RecoveryPhase::TrustEstablishment {
                new_admin_keys,
                succession_proof,
                recovery_witness,
            } => (new_admin_keys, succession_proof, recovery_witness),
            _ => return Err(Error::validation_failed(
                "Invalid phase",
                "Recovery not in trust establishment phase",
            )),
        };

        let mut checkpoint = None;
        while let Some(cp) = self.checkpoints.pop() {
            if self.verify_checkpoint(&cp)? {
                checkpoint = Some(cp);
                break;
            }
        }

        let checkpoint = checkpoint.ok_or_else(|| {
            Error::validation_failed("No checkpoint", "No valid checkpoint found")
        })?;

        let mut circuit = Circuit::new(Arc::clone(&self.groups));

        let checkpoint_var = circuit.allocate_g1_point(&checkpoint.state_root.inner());
        circuit.enforce_constraint(
            vec![(Scalar::one(), checkpoint_var)],
            vec![(Scalar::one(), checkpoint_var)],
            vec![(Scalar::one(), checkpoint_var)],
        );

        let mut state_proofs = Vec::new();
        let mut grant_commitments = Vec::new();

        let grants = self.merkle_tree.get_grants_since(checkpoint.epoch)?;
        for grant in grants {
            let proof = self.prove_grant_preservation(&grant, &circuit)?;
            state_proofs.push(proof);

            let commitment = StateMatrixCommitment::from_entry(&grant, &self.groups)?;
            grant_commitments.push(commitment);
        }

        let phase = RecoveryPhase::StateReconstruction {
            state_proofs,
            grant_commitments,
            checkpoint_proof: CircuitProof::from(circuit.clone()),
        };

        self.active_recoveries.insert(domain_id, phase);

        Ok(UnifiedProof::Circuit(CircuitProof::from(circuit)))
    }

    pub fn verify_recovery(
        &self,
        domain_id: [u8; 32],
        proof: &UnifiedProof,
    ) -> Result<bool> {
        let domain = self.recovery_domains.get(&domain_id).ok_or_else(|| {
            Error::validation_failed("Invalid domain", "Recovery domain not found")
        })?;

        let phase = self.active_recoveries.get(&domain_id).ok_or_else(|| {
            Error::validation_failed("Invalid recovery", "No active recovery found")
        })?;

        match phase.value() {
            RecoveryPhase::Initiation { .. } => {
                self.verify_initiation(proof, &domain)
            }
            RecoveryPhase::TrustEstablishment { .. } => {
                self.verify_trust_establishment(proof, &domain)
            }
            RecoveryPhase::StateReconstruction { .. } => {
                self.verify_state_reconstruction(proof, &domain)
            }
        }
    }

    fn verify_initiation(
        &self,
        proof: &UnifiedProof,
        domain: &RecoveryDomain,
    ) -> Result<bool> {
        let circuit_proof = match proof {
            UnifiedProof::Circuit(p) => p,
            _ => return Ok(false),
        };

        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::SUCCESSION_PROOF,
            Arc::clone(&self.groups),
        );

        Ok(self.proof_system.verify_proof(proof, &transcript.clone_state())?)
    }

    fn verify_trust_establishment(
        &self,
        proof: &UnifiedProof,
        domain: &RecoveryDomain,
    ) -> Result<bool> {
        let circuit_proof = match proof {
            UnifiedProof::Circuit(p) => p,
            _ => return Ok(false),
        };

        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::SUCCESSION_PROOF,
            Arc::clone(&self.groups),
        );

        Ok(self.proof_system.verify_proof(proof, &transcript.clone_state())?)
    }

    fn verify_state_reconstruction(
        &self,
        proof: &UnifiedProof,
        domain: &RecoveryDomain,
    ) -> Result<bool> {
        let circuit_proof = match proof {
            UnifiedProof::Circuit(p) => p,
            _ => return Ok(false),
        };

        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::SUCCESSION_PROOF,
            Arc::clone(&self.groups),
        );

        Ok(self.proof_system.verify_proof(proof, &transcript.clone_state())?)
    }

    fn verify_checkpoint(&self, checkpoint: &RecoveryCheckpoint) -> Result<bool> {
        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::SUCCESSION_PROOF,
            Arc::clone(&self.groups),
        );

        transcript.append_point_g1(
            DomainSeparationTags::COMMITMENT,
            checkpoint.state_root.inner(),
        );

        let state_root = self.groups.hash_to_g1(&transcript.clone_state())?;

        Ok(*checkpoint.state_root.inner() == state_root)
    }

    fn generate_recovery_witness(
        &self,
        affected_entries: &[EntryId],
        circuit: &Circuit,
    ) -> Result<RecoveryWitness> {
        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::WITNESS,
            Arc::clone(&self.groups),
        );

        let nullifier = self.groups.hash_to_g1(&transcript.clone_state())?;

        let entry = self.merkle_tree.get_latest_entry(affected_entries[0])?;
        let commitment = StateMatrixCommitment::from_entry(&entry, &self.groups)?;

        let epoch_proof = CircuitProof::from(circuit.clone());

        Ok(RecoveryWitness {
            commitment,
            nullifier,
            epoch_proof,
        })
    }

    fn prove_grant_preservation(
        &self,
        grant: &ACLEntry,
        circuit: &Circuit,
    ) -> Result<CircuitProof> {
        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::SUCCESSION_PROOF,
            Arc::clone(&self.groups),
        );

        let policy_var = circuit.allocate_scalar(&Scalar::from(grant.policy_generation as u64));
        let service_var = circuit.allocate_variable();

        circuit.enforce_constraint(
            vec![(Scalar::one(), policy_var)],
            vec![(Scalar::one(), service_var)],
            vec![(Scalar::one(), service_var)],
        );

        transcript.append_scalar(b"policy", &Scalar::from(grant.policy_generation as u64));
        let serialized = serde_json::to_vec(&grant)?;
        transcript.append_message(b"grant", &serialized);

        Ok(CircuitProof::from(circuit.clone()))
    }

    pub fn create_checkpoint(&self) -> Result<RecoveryCheckpoint> {
        let mut transcript = ProofTranscript::new(
            DomainSeparationTags::HISTORICAL,
            Arc::clone(&self.groups),
        );

        let current_admin = self.current_admin.load();
        let state_root = self.merkle_tree.get_current_root()?;

        let mut pedersen = PedersenCommitment::new(*self.groups);
        let state_matrix = StateMatrixEntry::new(
            [0u8; 32], // Checkpoint entry
            [0u8; 32],
            0,
            vec![],
            current_admin.policy_generation,
            current_admin.active_keys.len() as u32,
            current_admin.active_keys.clone(),
        );

        let blinding = transcript.challenge_scalar(b"checkpoint");
        let commitment = pedersen.commit_state_entry(
            state_matrix,
            &blinding,
            &mut transcript,
        )?;

        let checkpoint = RecoveryCheckpoint {
            state_root: state_root.into(),
            epoch: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            admin_keys: current_admin.active_keys,
            commitment,
        };

        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn get_latest_checkpoint(&self) -> Option<RecoveryCheckpoint> {
        self.checkpoints.pop()
    }

    pub fn get_recovery_proof(
        &self,
        domain_id: [u8; 32],
    ) -> Option<UnifiedProof> {
        self.proof_cache.get(&domain_id).map(|p| p.clone())
    }

    pub fn create_recovery_domain(
        &self,
        domain_id: [u8; 32],
        authorities: Vec<SerializableG2>,
        threshold: usize,
        parent_domain: Option<[u8; 32]>,
    ) -> Result<()> {
        if let Some(parent) = parent_domain {
            if !self.recovery_domains.contains_key(&parent) {
                return Err(Error::validation_failed(
                    "Invalid parent domain",
                    "Parent recovery domain not found",
                ));
            }
        }

        let domain = RecoveryDomain {
            domain_id,
            authorities,
            threshold,
            parent_domain,
        };

        self.recovery_domains.insert(domain_id, domain);
        Ok(())
    }

    pub fn verify_domain_authority(
        &self,
        domain_id: [u8; 32],
        signatures: &[BlsSignature],
    ) -> Result<bool> {
        let domain = self.recovery_domains.get(&domain_id).ok_or_else(|| {
            Error::validation_failed("Invalid domain", "Recovery domain not found")
        })?;

        if signatures.len() < domain.threshold {
            return Ok(false);
        }

        for sig in signatures {
            let message = domain_id.as_ref();
            if !sig.verify(message, &self.groups)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::RandomGenerator;

    async fn setup_test_recovery() -> (RecoverySystem, Vec<Scalar>) {
        let groups = Arc::new(CurveGroups::new());
        let proof_system = Arc::new(ProofSystem::new(Arc::clone(&groups)));
        let merkle_tree = Arc::new(SparseMerkleTree::new(Arc::clone(&groups)));
        let rng = RandomGenerator::new();

        // Generate authority keys
        let authority_keys: Vec<_> = (0..RECOVERY_DOMAIN_THRESHOLD)
            .map(|_| rng.random_scalar())
            .collect();
        let authority_pubkeys: Vec<_> = authority_keys
            .iter()
            .map(|sk| {
                SerializableG2::from(
                    (groups.g2_generator * sk).into_affine()
                )
            })
            .collect();

        // Create root domain
        let root_domain = RecoveryDomain {
            domain_id: [0u8; 32],
            authorities: authority_pubkeys,
            threshold: RECOVERY_DOMAIN_THRESHOLD,
            parent_domain: None,
        };

        let system = RecoverySystem::new(
            groups,
            proof_system,
            merkle_tree,
            root_domain,
        );

        (system, authority_keys)
    }

    #[test]
    fn test_complete_recovery_flow() {
        let (system, authority_keys) = setup_test_recovery().await;
        let rng = RandomGenerator::new();

        // Create test entry
        let entry = ACLEntry {
            id: EntryId([1u8; 32]),
            service_id: "test".to_string().into(),
            policy_generation: 1,
            metadata: Default::default(),
            auth_proof: Default::default(),
        };

        // Create recovery signatures
        let signatures: Vec<_> = authority_keys
            .iter()
            .map(|sk| {
                BlsSignature::sign(
                    b"recovery",
                    sk,
                    &system.groups,
                ).unwrap()
            })
            .collect();

        // Phase 1: Initiate Recovery
        let initiation_proof = system.initiate_recovery(
            [0u8; 32],
            &[entry.clone()],
            signatures,
        ).unwrap();

        assert!(system.verify_recovery([0u8; 32], &initiation_proof).unwrap());

        // Phase 2: Establish Trust
        let new_admin_keys = vec![
            SerializableG2::from(system.groups.random_g2()),
            SerializableG2::from(system.groups.random_g2()),
        ];

        let trust_proof = system.establish_trust(
            [0u8; 32],
            new_admin_keys,
        ).unwrap();

        assert!(system.verify_recovery([0u8; 32], &trust_proof).unwrap());

        // Phase 3: Reconstruct State
        let reconstruction_proof = system.reconstruct_state([0u8; 32]).unwrap();

        assert!(system.verify_recovery([0u8; 32], &reconstruction_proof).unwrap());
    }

    #[test]
    fn test_checkpoint_management() {
        let (system, _) = setup_test_recovery().await;

        // Create checkpoint
        let checkpoint = system.create_checkpoint().unwrap();
        assert!(system.verify_checkpoint(&checkpoint).unwrap());

        // Verify checkpoint retrieval
        let latest = system.get_latest_checkpoint().unwrap();
        assert_eq!(latest.epoch, checkpoint.epoch);
    }

    #[test]
    fn test_hierarchical_domains() {
        let (system, authority_keys) = setup_test_recovery().await;
        let rng = RandomGenerator::new();

        // Create child domain
        let child_authorities: Vec<_> = (0..RECOVERY_DOMAIN_THRESHOLD)
            .map(|_| SerializableG2::from(system.groups.random_g2()))
            .collect();

        system.create_recovery_domain(
            [1u8; 32],
            child_authorities.clone(),
            RECOVERY_DOMAIN_THRESHOLD,
            Some([0u8; 32]),
        ).unwrap();

        // Verify domain authority
        let signatures: Vec<_> = authority_keys
            .iter()
            .map(|sk| {
                BlsSignature::sign(
                    &[1u8; 32],
                    sk,
                    &system.groups,
                ).unwrap()
            })
            .collect();

        assert!(system.verify_domain_authority([0u8; 32], &signatures).unwrap());
    }
}
