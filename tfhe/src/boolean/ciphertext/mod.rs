//! An encryption of a boolean message.
//!
//! This module implements the ciphertext structure containing an encryption of a Boolean message.

use crate::core_crypto::entities::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A structure containing a ciphertext, meant to encrypt a Boolean message.
///
/// It is used to evaluate a Boolean circuits homomorphically.
#[derive(Clone, Debug)]
pub enum Ciphertext {
    Encrypted(LweCiphertextOwned<u32>),
    Trivial(bool),
}

#[derive(Serialize, Deserialize)]
enum SerializableCiphertext {
    Encrypted(Vec<u8>),
    Trivial(bool),
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Ciphertext::Encrypted(lwe) => {
                let ciphertext = bincode::serialize(lwe).map_err(serde::ser::Error::custom)?;
                SerializableCiphertext::Encrypted(ciphertext)
            }
            Ciphertext::Trivial(b) => SerializableCiphertext::Trivial(*b),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing = SerializableCiphertext::deserialize(deserializer)?;

        Ok(match thing {
            SerializableCiphertext::Encrypted(data) => {
                let lwe =
                    bincode::deserialize(data.as_slice()).map_err(serde::de::Error::custom)?;
                Self::Encrypted(lwe)
            }
            SerializableCiphertext::Trivial(b) => Self::Trivial(b),
        })
    }
}

/// A structure containing a compressed ciphertext, meant to encrypt a Boolean message.
///
/// It has to be decompressed before evaluating a Boolean circuit.
#[derive(Clone, Debug)]
pub struct CompressedCiphertext {
    pub(crate) ciphertext: SeededLweCiphertext<u32>,
}

#[derive(Serialize, Deserialize)]
struct SerializableCompressedCiphertext {
    data: Vec<u8>,
}

impl Serialize for CompressedCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = bincode::serialize(&self.ciphertext).map_err(serde::ser::Error::custom)?;
        let ser_ct = SerializableCompressedCiphertext { data };

        ser_ct.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CompressedCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing = SerializableCompressedCiphertext::deserialize(deserializer)?;
        let lwe = bincode::deserialize(&thing.data).map_err(serde::de::Error::custom)?;
        Ok(Self { ciphertext: lwe })
    }
}

impl From<CompressedCiphertext> for Ciphertext {
    fn from(value: CompressedCiphertext) -> Self {
        Self::Encrypted(value.ciphertext.decompress_into_lwe_ciphertext())
    }
}
