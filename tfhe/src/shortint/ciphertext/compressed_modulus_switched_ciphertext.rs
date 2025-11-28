use tfhe_versionable::Versionize;

use super::common::*;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;
use crate::core_crypto::prelude::compressed_modulus_switched_multi_bit_lwe_ciphertext::CompressedModulusSwitchedMultiBitLweCiphertext;
use crate::core_crypto::prelude::CompressedModulusSwitchedLweCiphertextConformanceParams;
use crate::shortint::backward_compatibility::ciphertext::{
    CompressedModulusSwitchedCiphertextVersions,
    InternalCompressedModulusSwitchedCiphertextVersions,
};
use crate::shortint::parameters::{AtomicPatternKind, CiphertextConformanceParams};
use crate::shortint::{CarryModulus, MessageModulus};

/// An object to store a ciphertext using less memory.
/// Decompressing it requires a PBS
///
/// # Example
///
/// ```rust
/// use tfhe::shortint::gen_keys;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// // Generate the client key and the server key:
/// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
///
/// let clear = 3;
///
/// let ctxt = cks.unchecked_encrypt(clear);
///
/// // Can be serialized in a smaller buffer
/// let compressed_ct = sks.switch_modulus_and_compress(&ctxt);
///
/// let decompressed_ct = sks.decompress(&compressed_ct);
///
/// let dec = cks.decrypt(&decompressed_ct);
///
/// assert_eq!(clear, dec);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedCiphertextVersions)]
pub struct CompressedModulusSwitchedCiphertext {
    pub(crate) compressed_modulus_switched_lwe_ciphertext:
        InternalCompressedModulusSwitchedCiphertext,
    pub(crate) degree: Degree,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) atomic_pattern: AtomicPatternKind,
}

#[derive(Copy, Clone)]
pub struct CompressedModulusSwitchedCiphertextConformanceParams {
    pub ct_params: CompressedModulusSwitchedLweCiphertextConformanceParams<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub degree: Degree,
    pub atomic_pattern: AtomicPatternKind,
}

impl From<CompressedModulusSwitchedCiphertextConformanceParams> for CiphertextConformanceParams {
    fn from(value: CompressedModulusSwitchedCiphertextConformanceParams) -> Self {
        Self {
            ct_params: value.ct_params.ct_params,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            degree: value.degree,
            noise_level: NoiseLevel::NOMINAL,
            atomic_pattern: value.atomic_pattern,
        }
    }
}

impl ParameterSetConformant for CompressedModulusSwitchedCiphertext {
    type ParameterSet = CompressedModulusSwitchedCiphertextConformanceParams;

    fn is_conformant(&self, param: &CompressedModulusSwitchedCiphertextConformanceParams) -> bool {
        let Self {
            compressed_modulus_switched_lwe_ciphertext,
            degree,
            message_modulus,
            carry_modulus,
            atomic_pattern,
        } = self;

        let CompressedModulusSwitchedCiphertextConformanceParams {
            ct_params,
            message_modulus: param_message_modulus,
            carry_modulus: param_carry_modulus,
            degree: param_degree,
            atomic_pattern: param_atomic_pattern,
        } = param;

        compressed_modulus_switched_lwe_ciphertext.is_conformant(ct_params)
            && message_modulus == param_message_modulus
            && carry_modulus == param_carry_modulus
            && atomic_pattern == param_atomic_pattern
            && degree == param_degree
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(InternalCompressedModulusSwitchedCiphertextVersions)]
pub(crate) enum InternalCompressedModulusSwitchedCiphertext {
    Classic(CompressedModulusSwitchedLweCiphertext<u64>),
    MultiBit(CompressedModulusSwitchedMultiBitLweCiphertext<u64>),
}

impl ParameterSetConformant for InternalCompressedModulusSwitchedCiphertext {
    type ParameterSet = CompressedModulusSwitchedLweCiphertextConformanceParams<u64>;

    fn is_conformant(
        &self,
        param: &CompressedModulusSwitchedLweCiphertextConformanceParams<u64>,
    ) -> bool {
        match self {
            Self::Classic(a) => a.is_conformant(param),
            Self::MultiBit(a) => a.is_conformant(param),
        }
    }
}
