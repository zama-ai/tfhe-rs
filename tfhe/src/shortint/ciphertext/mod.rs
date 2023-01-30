//! Module with the definition of the Ciphertext.
use crate::core_crypto::entities::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt::Debug;

/// This tracks the number of operations that has been done.
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

/// A structure representing a shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

/// A structure representing a compressed shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

impl From<CompressedCiphertext> for Ciphertext {
    fn from(value: CompressedCiphertext) -> Self {
        let CompressedCiphertext {
            ct,
            degree,
            message_modulus,
            carry_modulus,
        } = value;

        Self {
            ct: ct.decompress_into_lwe_ciphertext(),
            degree,
            message_modulus,
            carry_modulus,
        }
    }
}
