use tfhe_versionable::Versionize;

use super::common::*;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;
use crate::shortint::backward_compatibility::ciphertext::CompressedModulusSwitchedCiphertextVersions;
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::{CarryModulus, MessageModulus};

/// An object to store a ciphertext in little memory.
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
        CompressedModulusSwitchedLweCiphertext<u64>,
    pub(crate) degree: Degree,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) pbs_order: PBSOrder,
}

impl ParameterSetConformant for CompressedModulusSwitchedCiphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        self.compressed_modulus_switched_lwe_ciphertext
            .is_conformant(&param.ct_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
    }
}
