use crate::crypto::primitives::{Scalar, G1, G2};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy)]
pub struct SerializableG1(G1);
#[derive(Clone, Copy)]
pub struct SerializableG2(G2);
pub struct SerializableScalar(Scalar);

macro_rules! impl_point_serialization {
    ($name:ident, $point_type:ty) => {
        impl $name {
            pub fn new(point: $point_type) -> Self {
                Self(point)
            }

            pub fn inner(&self) -> &$point_type {
                &self.0
            }

            pub fn into_inner(self) -> $point_type {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut bytes = Vec::new();
                self.0
                    .serialize_compressed(&mut bytes)
                    .map_err(serde::ser::Error::custom)?;
                serializer.serialize_bytes(&bytes)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes = Vec::<u8>::deserialize(deserializer)?;
                let point = <$point_type>::deserialize_compressed(&bytes[..])
                    .map_err(serde::de::Error::custom)?;
                Ok(Self(point))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl PartialEq<$point_type> for $name {
            fn eq(&self, other: &$point_type) -> bool {
                &self.0 == other
            }
        }

        impl From<$point_type> for $name {
            fn from(point: $point_type) -> Self {
                Self(point)
            }
        }

        impl From<$name> for $point_type {
            fn from(wrapped: $name) -> Self {
                wrapped.0
            }
        }

        impl AsRef<$point_type> for $name {
            fn as_ref(&self) -> &$point_type {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).finish()
            }
        }

        impl std::ops::Deref for $name {
            type Target = $point_type;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

impl_point_serialization!(SerializableG1, G1);
impl_point_serialization!(SerializableG2, G2);

impl SerializableScalar {
    pub fn new(scalar: Scalar) -> Self {
        Self(scalar)
    }

    pub fn inner(&self) -> &Scalar {
        &self.0
    }

    pub fn into_inner(self) -> Scalar {
        self.0
    }
}

impl Serialize for SerializableScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.into_bigint().to_bytes_le();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for SerializableScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let scalar = Scalar::from_le_bytes_mod_order(&bytes);
        Ok(Self(scalar))
    }
}

impl Clone for SerializableScalar {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl PartialEq for SerializableScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Scalar> for SerializableScalar {
    fn eq(&self, other: &Scalar) -> bool {
        &self.0 == other
    }
}

impl From<Scalar> for SerializableScalar {
    fn from(scalar: Scalar) -> Self {
        Self(scalar)
    }
}

impl From<SerializableScalar> for Scalar {
    fn from(wrapped: SerializableScalar) -> Self {
        wrapped.0
    }
}

impl AsRef<Scalar> for SerializableScalar {
    fn as_ref(&self) -> &Scalar {
        &self.0
    }
}

impl std::fmt::Debug for SerializableScalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SerializableScalar").finish()
    }
}

impl std::ops::Deref for SerializableScalar {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait IntoSerializable<T> {
    fn into_serializable(self) -> T;
}

pub trait FromSerializable<T> {
    fn from_serializable(value: T) -> Self;
}

impl IntoSerializable<Vec<SerializableG1>> for Vec<G1> {
    fn into_serializable(self) -> Vec<SerializableG1> {
        self.into_iter().map(SerializableG1::new).collect()
    }
}

impl FromSerializable<Vec<SerializableG1>> for Vec<G1> {
    fn from_serializable(points: Vec<SerializableG1>) -> Self {
        points.into_iter().map(SerializableG1::into_inner).collect()
    }
}

impl IntoSerializable<Vec<SerializableG2>> for Vec<G2> {
    fn into_serializable(self) -> Vec<SerializableG2> {
        self.into_iter().map(SerializableG2::new).collect()
    }
}

impl FromSerializable<Vec<SerializableG2>> for Vec<G2> {
    fn from_serializable(points: Vec<SerializableG2>) -> Self {
        points.into_iter().map(SerializableG2::into_inner).collect()
    }
}

impl IntoSerializable<Vec<SerializableScalar>> for Vec<Scalar> {
    fn into_serializable(self) -> Vec<SerializableScalar> {
        self.into_iter().map(SerializableScalar::new).collect()
    }
}

impl FromSerializable<Vec<SerializableScalar>> for Vec<Scalar> {
    fn from_serializable(scalars: Vec<SerializableScalar>) -> Self {
        scalars
            .into_iter()
            .map(SerializableScalar::into_inner)
            .collect()
    }
}
