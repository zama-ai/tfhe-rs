use tfhe_versionable::Versionize;

use self::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::*;
use crate::shortint::backward_compatibility::ciphertext::CompressedCiphertextListVersions;
use crate::shortint::parameters::CompressedCiphertextConformanceParams;
use crate::shortint::{CarryModulus, MessageModulus};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
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
        let Self {
            modulus_switched_glwe_ciphertext_list,
            ciphertext_modulus,
            message_modulus,
            carry_modulus,
            pbs_order,
            lwe_per_glwe,
            count,
        } = self;

        let len = modulus_switched_glwe_ciphertext_list.len();

        if len == 0 {
            return true;
        }

        let last_body_count = modulus_switched_glwe_ciphertext_list
            .last()
            .unwrap()
            .bodies_count()
            .0;

        let count_is_ok = count.0.div_ceil(lwe_per_glwe.0) == len
            && modulus_switched_glwe_ciphertext_list[..len - 1]
                .iter()
                .all(|a| a.bodies_count() == params.lwe_per_glwe)
            && last_body_count <= params.lwe_per_glwe.0
            && (len - 1) * params.lwe_per_glwe.0 + last_body_count == count.0;

        count_is_ok
            && modulus_switched_glwe_ciphertext_list
                .iter()
                .all(|glwe| glwe.is_conformant(&params.ct_params))
            && lwe_per_glwe.0 <= params.ct_params.polynomial_size.0
            && *lwe_per_glwe == params.lwe_per_glwe
            && *ciphertext_modulus == params.ct_params.ct_modulus
            && *message_modulus == params.message_modulus
            && *carry_modulus == params.carry_modulus
            && *pbs_order == params.pbs_order
    }
}
