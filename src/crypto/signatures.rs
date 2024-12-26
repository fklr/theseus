use std::sync::Arc;

use crate::{
    crypto::{
        commitment::StateMatrixCommitment,
        primitives::{CurveGroups, ProofTranscript, Scalar, G1, G2},
    },
    errors::{Error, Result},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct BlsSignature {
    pub(crate) signature: G1,
    pub(crate) public_key: G2,
}

#[derive(Clone, Debug)]
pub struct AggregateSignature {
    pub(crate) aggregate: G1,
    pub(crate) public_keys: Vec<G2>,
}

impl Default for AggregateSignature {
    fn default() -> Self {
        Self {
            aggregate: G1::zero(),
            public_keys: Vec::new(),
        }
    }
}

impl Serialize for AggregateSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut aggregate_bytes = Vec::new();
        self.aggregate
            .serialize_compressed(&mut aggregate_bytes)
            .map_err(serde::ser::Error::custom)?;

        let mut key_bytes: Vec<Vec<u8>> = Vec::new();
        for key in &self.public_keys {
            let mut bytes = Vec::new();
            key.serialize_compressed(&mut bytes)
                .map_err(serde::ser::Error::custom)?;
            key_bytes.push(bytes);
        }

        let serializable = (
            BASE64.encode(aggregate_bytes),
            key_bytes
                .iter()
                .map(|b| BASE64.encode(b))
                .collect::<Vec<_>>(),
        );
        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AggregateSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (aggregate_b64, key_b64s): (String, Vec<String>) =
            Deserialize::deserialize(deserializer)?;

        let aggregate_bytes = BASE64
            .decode(aggregate_b64.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let aggregate =
            G1::deserialize_compressed(&aggregate_bytes[..]).map_err(serde::de::Error::custom)?;

        let mut public_keys = Vec::new();
        for key_b64 in key_b64s {
            let key_bytes = BASE64
                .decode(key_b64.as_bytes())
                .map_err(serde::de::Error::custom)?;
            let key =
                G2::deserialize_compressed(&key_bytes[..]).map_err(serde::de::Error::custom)?;
            public_keys.push(key);
        }

        Ok(Self {
            aggregate,
            public_keys,
        })
    }
}

#[derive(Clone)]
pub struct SignedStateCommitment {
    pub(crate) commitment: StateMatrixCommitment,
    pub(crate) signatures: AggregateSignature,
}

impl BlsSignature {
    pub fn sign(message: &[u8], secret_key: &Scalar, groups: &CurveGroups) -> Result<Self> {
        let mut transcript = ProofTranscript::new(b"theseus-bls-signature", Arc::new(*groups));
        transcript.append_message(b"message", message);

        let message_point = groups
            .hash_to_g1(message)
            .map_err(|e| Error::signature_error("Failed to hash message to G1", e.to_string()))?;

        let signature = message_point * secret_key;
        let public_key = groups.g2_generator * secret_key;

        Ok(Self {
            signature: signature.into_affine(),
            public_key: public_key.into_affine(),
        })
    }

    pub fn verify(&self, message: &[u8], groups: &CurveGroups) -> Result<bool> {
        let message_point = groups
            .hash_to_g1(message)
            .map_err(|e| Error::signature_error("Failed to hash message to G1", e.to_string()))?;

        // e(signature, g2) == e(H(m), pubkey)
        let lhs = groups.pair(&self.signature, &groups.g2_generator);
        let rhs = groups.pair(&message_point, &self.public_key);

        Ok(lhs == rhs)
    }
}

impl AggregateSignature {
    pub fn aggregate(signatures: &[BlsSignature]) -> Result<Self> {
        if signatures.is_empty() {
            return Err(Error::signature_error(
                "Cannot aggregate empty signature set",
                "At least one signature required",
            ));
        }

        let aggregate = signatures
            .iter()
            .fold(G1::zero(), |acc, sig| (acc + sig.signature).into());

        let public_keys = signatures.iter().map(|sig| sig.public_key).collect();

        Ok(Self {
            aggregate,
            public_keys,
        })
    }

    pub fn verify(&self, message: &[u8], groups: &CurveGroups) -> Result<bool> {
        let message_point = groups
            .hash_to_g1(message)
            .map_err(|e| Error::signature_error("Failed to hash message to G1", e.to_string()))?;

        let aggregate_pubkey = self
            .public_keys
            .iter()
            .fold(G2::zero(), |acc, pk| (acc + pk).into());

        // Verify e(aggregate, g2) == e(H(m), aggregate_pubkey)
        let lhs = groups.pair(&self.aggregate, &groups.g2_generator);
        let rhs = groups.pair(&message_point, &aggregate_pubkey);

        Ok(lhs == rhs)
    }
}

impl SignedStateCommitment {
    pub fn new(
        commitment: StateMatrixCommitment,
        admin_signatures: Vec<BlsSignature>,
        groups: &CurveGroups,
    ) -> Result<Self> {
        let serialized = serde_json::to_vec(&(commitment.data())).map_err(|e| {
            Error::signature_error("Failed to serialize commitment data", e.to_string())
        })?;

        let aggregate = AggregateSignature::aggregate(&admin_signatures)?;

        if !aggregate.verify(&serialized, groups)? {
            return Err(Error::signature_error(
                "Invalid aggregate signature",
                "Admin signatures failed verification",
            ));
        }

        Ok(Self {
            commitment,
            signatures: aggregate,
        })
    }

    pub fn verify(&self, groups: &CurveGroups) -> Result<bool> {
        let serialized = serde_json::to_vec(&self.commitment.data()).map_err(|e| {
            Error::signature_error("Failed to serialize commitment data", e.to_string())
        })?;

        self.signatures.verify(&serialized, groups)
    }

    pub fn commitment(&self) -> &StateMatrixCommitment {
        &self.commitment
    }

    pub fn aggregate_signature(&self) -> &AggregateSignature {
        &self.signatures
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::crypto::{
        commitment::{PedersenCommitment, StateMatrixEntry},
        primitives::{DomainSeparationTags, RandomGenerator},
    };

    #[test]
    fn test_signature_verification() {
        let groups = CurveGroups::new();
        let message = b"test message";
        let rng = RandomGenerator::new();
        let secret_key = rng.random_scalar();

        let signature = BlsSignature::sign(message, &secret_key, &groups).unwrap();
        assert!(signature.verify(message, &groups).unwrap());

        let wrong_message = b"wrong message";
        assert!(!signature.verify(wrong_message, &groups).unwrap());
    }

    #[test]
    fn test_aggregate_verification() {
        let groups = CurveGroups::new();
        let message = b"test message";
        let rng = RandomGenerator::new();
        let mut signatures = Vec::new();

        for _ in 0..3 {
            let secret_key = rng.random_scalar();
            signatures.push(BlsSignature::sign(message, &secret_key, &groups).unwrap());
        }

        let aggregate = AggregateSignature::aggregate(&signatures).unwrap();
        assert!(aggregate.verify(message, &groups).unwrap());
    }

    #[test]
    fn test_signed_state_matrix() {
        let groups = Arc::new(CurveGroups::new());
        let mut pedersen = PedersenCommitment::new(*groups);
        let mut transcript = ProofTranscript::new(DomainSeparationTags::COMMITMENT, groups.clone());
        let rng = RandomGenerator::new();

        // Create test entry
        let entry = StateMatrixEntry::new(
            [1u8; 32],
            [2u8; 32],
            1,
            vec![1, 2, 3],
            1,
            42u32,
            vec![G2::zero().into()],
        );

        // Create commitment
        let blinding = rng.random_scalar();
        let commitment = pedersen
            .commit_state_entry(entry, &blinding, &mut transcript)
            .unwrap();

        // Generate admin signatures
        let admin_keys: Vec<_> = (0..3).map(|_| rng.random_scalar()).collect();
        let signatures: Vec<_> = admin_keys
            .iter()
            .map(|key| {
                BlsSignature::sign(
                    &serde_json::to_vec(&commitment.data()).unwrap(),
                    key,
                    &groups,
                )
                .unwrap()
            })
            .collect();

        // Create and verify signed commitment
        let signed = SignedStateCommitment::new(commitment, signatures, &groups).unwrap();

        assert!(signed.verify(&groups).unwrap());
    }
}
