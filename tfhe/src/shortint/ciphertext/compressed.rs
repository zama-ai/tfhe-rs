//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextConformanceParams;
use super::common::*;
use super::standard::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::entities::*;
use crate::shortint::backward_compatibility::ciphertext::CompressedCiphertextVersions;
use crate::shortint::parameters::{AtomicPatternKind, CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// A structure representing a compressed shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCiphertextVersions)]
pub struct CompressedCiphertext {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub atomic_pattern: AtomicPatternKind,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompressedCiphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        let Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            noise_level,
        } = self;

        ct.is_conformant(&param.ct_params)
            && *message_modulus == param.message_modulus
            && *carry_modulus == param.carry_modulus
            && *atomic_pattern == param.atomic_pattern
            && *degree == param.degree
            && *noise_level == param.noise_level
    }
}

impl CompressedCiphertext {
    pub fn decompress(&self) -> Ciphertext {
        let Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            noise_level,
        } = self;

        Ciphertext::new(
            ct.clone().decompress_into_lwe_ciphertext(),
            *degree,
            *noise_level,
            *message_modulus,
            *carry_modulus,
            *atomic_pattern,
        )
    }

    /// Deconstruct a [`CompressedCiphertext`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        SeededLweCiphertext<u64>,
        Degree,
        MessageModulus,
        CarryModulus,
        AtomicPatternKind,
        NoiseLevel,
    ) {
        let Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            noise_level,
        } = self;

        (
            ct,
            degree,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            noise_level,
        )
    }

    /// Construct a [`CompressedCiphertext`] from its constituents.
    pub fn from_raw_parts(
        ct: SeededLweCiphertext<u64>,
        degree: Degree,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        atomic_pattern: AtomicPatternKind,
        noise_level: NoiseLevel,
    ) -> Self {
        Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            noise_level,
        }
    }
}
