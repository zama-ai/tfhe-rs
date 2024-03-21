//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextConformanceParams;
use super::common::*;
use super::standard::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::entities::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};

/// A structure representing a compressed shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompressedCiphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        self.ct.is_conformant(&param.ct_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
            && self.noise_level == param.noise_level
    }
}

impl CompressedCiphertext {
    pub fn decompress(self) -> Ciphertext {
        let Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        } = self;

        Ciphertext {
            ct: ct.decompress_into_lwe_ciphertext(),
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        }
    }

    /// Deconstruct a [`CompressedCiphertext`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        SeededLweCiphertext<u64>,
        Degree,
        MessageModulus,
        CarryModulus,
        PBSOrder,
        NoiseLevel,
    ) {
        let Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        } = self;

        (
            ct,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        )
    }

    /// Construct a [`CompressedCiphertext`] from its constituents.
    pub fn from_raw_parts(
        ct: SeededLweCiphertext<u64>,
        degree: Degree,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        pbs_order: PBSOrder,
        noise_level: NoiseLevel,
    ) -> Self {
        Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        }
    }
}

impl From<CompressedCiphertext> for Ciphertext {
    fn from(value: CompressedCiphertext) -> Self {
        value.decompress()
    }
}
