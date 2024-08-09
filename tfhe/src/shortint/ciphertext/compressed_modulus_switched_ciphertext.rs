use tfhe_versionable::Versionize;

use super::common::*;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;
use crate::core_crypto::prelude::compressed_modulus_switched_multi_bit_lwe_ciphertext::CompressedModulusSwitchedMultiBitLweCiphertext;
use crate::core_crypto::prelude::LweCiphertextParameters;
use crate::shortint::backward_compatibility::ciphertext::{
    CompressedModulusSwitchedCiphertextVersions,
    InternalCompressedModulusSwitchedCiphertextVersions,
};
use crate::shortint::parameters::CiphertextConformanceParams;
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
    pub(crate) pbs_order: PBSOrder,
}

impl ParameterSetConformant for CompressedModulusSwitchedCiphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        let Self {
            compressed_modulus_switched_lwe_ciphertext,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
        } = self;

        compressed_modulus_switched_lwe_ciphertext.is_conformant(&param.ct_params)
            && *message_modulus == param.message_modulus
            && *carry_modulus == param.carry_modulus
            && *pbs_order == param.pbs_order
            && *degree == param.degree
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(InternalCompressedModulusSwitchedCiphertextVersions)]
pub(crate) enum InternalCompressedModulusSwitchedCiphertext {
    Classic(CompressedModulusSwitchedLweCiphertext<u64>),
    MultiBit(CompressedModulusSwitchedMultiBitLweCiphertext<u64>),
}

impl ParameterSetConformant for InternalCompressedModulusSwitchedCiphertext {
    type ParameterSet = LweCiphertextParameters<u64>;

    fn is_conformant(&self, param: &LweCiphertextParameters<u64>) -> bool {
        match self {
            Self::Classic(a) => a.is_conformant(param),
            Self::MultiBit(a) => a.is_conformant(param),
        }
    }
}
