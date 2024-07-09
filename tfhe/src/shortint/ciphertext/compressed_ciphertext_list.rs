use tfhe_versionable::Versionize;

use self::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::*;
use crate::shortint::backward_compatibility::ciphertext::CompressedCiphertextListVersions;
use crate::shortint::parameters::CompressedCiphertextConformanceParams;
use crate::shortint::{CarryModulus, MessageModulus};

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedCiphertextListVersions)]
pub struct CompressedCiphertextList {
    pub modulus_switched_glwe_ciphertext_list: Vec<CompressedModulusSwitchedGlweCiphertext<u64>>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub lwe_per_glwe: LweCiphertextCount,
    pub count: CiphertextCount,
}

impl ParameterSetConformant for CompressedCiphertextList {
    type ParameterSet = CompressedCiphertextConformanceParams;

    fn is_conformant(&self, params: &CompressedCiphertextConformanceParams) -> bool {
        let len = self.modulus_switched_glwe_ciphertext_list.len();

        if len == 0 {
            return true;
        }

        let count_is_ok = self.modulus_switched_glwe_ciphertext_list[..len - 1]
            .iter()
            .all(|a| a.bodies_count() == params.lwe_per_glwe)
            && self
                .modulus_switched_glwe_ciphertext_list
                .last()
                .unwrap()
                .bodies_count()
                .0
                <= params.lwe_per_glwe.0;

        count_is_ok
            && self
                .modulus_switched_glwe_ciphertext_list
                .iter()
                .all(|glwe| {
                    glwe.glwe_dimension() == params.ct_params.glwe_dim
                        && glwe.polynomial_size() == params.ct_params.polynomial_size
                        && glwe.uncompressed_ciphertext_modulus() == params.ct_params.ct_modulus
                })
            && self.lwe_per_glwe.0 <= params.ct_params.polynomial_size.0
            && self.lwe_per_glwe == params.lwe_per_glwe
            && self.ciphertext_modulus == params.ct_params.ct_modulus
            && self.message_modulus == params.message_modulus
            && self.carry_modulus == params.carry_modulus
            && self.pbs_order == params.pbs_order
    }
}
