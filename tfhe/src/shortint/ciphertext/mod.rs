//! Module with the definition of a short-integer ciphertext.
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{
    AbstractEngine, DefaultSerializationEngine, EntityDeserializationEngine,
    EntitySerializationEngine, LweCiphertext64,
};
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp;
use std::fmt::Debug;

/// This indicates the number of operations that has been done.
///
/// For instances, computing and addition increases this number by 1, whereas a multiplication by
/// a constant $\lambda$ increases it by $\lambda$.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct Degree(pub usize);

impl Degree {
    pub(crate) fn after_bitxor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        //Try every possibility to find the worst case
        for i in 0..min + 1 {
            if max ^ i > result {
                result = max ^ i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        for i in 0..min + 1 {
            if max | i > result {
                result = max | i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitand(&self, other: Degree) -> Degree {
        Degree(cmp::min(self.0, other.0))
    }

    pub(crate) fn after_left_shift(&self, shift: u8, modulus: usize) -> Degree {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = (i << shift) % modulus;
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }

    #[allow(dead_code)]
    pub(crate) fn after_pbs<F>(&self, f: F) -> Degree
    where
        F: Fn(usize) -> usize,
    {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = f(i);
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }
}

/// A structure representing a short-integer ciphertext.
/// It is used to evaluate a short-integer circuits homomorphically.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone)]
pub struct Ciphertext {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

#[derive(Serialize, Deserialize)]
struct SerializableCiphertext {
    data: Vec<u8>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_eng = DefaultSerializationEngine::new(()).map_err(serde::ser::Error::custom)?;

        let old_ct: LweCiphertext64 = self.ct.clone().into();

        let data = ser_eng
            .serialize(&old_ct)
            .map_err(serde::ser::Error::custom)?;

        SerializableCiphertext {
            data,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
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

        let mut de_eng = DefaultSerializationEngine::new(()).map_err(serde::de::Error::custom)?;

        let old_ct: LweCiphertext64 = de_eng
            .deserialize(thing.data.as_slice())
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            ct: old_ct.into(),
            degree: thing.degree,
            message_modulus: thing.message_modulus,
            carry_modulus: thing.carry_modulus,
        })
    }
}
