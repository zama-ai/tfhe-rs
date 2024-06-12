//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextListConformanceParams;
use super::common::*;
use super::standard::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::entities::*;
use crate::shortint::backward_compatibility::ciphertext::CompactCiphertextListVersions;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CompactCiphertextListVersions)]
pub struct CompactCiphertextList {
    pub ct_list: LweCompactCiphertextListOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CiphertextListConformanceParams;

    fn is_conformant(&self, param: &CiphertextListConformanceParams) -> bool {
        self.ct_list.is_conformant(&param.ct_list_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
            && self.noise_level == param.noise_level
    }
}

impl CompactCiphertextList {
    pub fn expand(&self) -> Vec<Ciphertext> {
        let mut output_lwe_ciphertext_list = LweCiphertextList::new(
            0u64,
            self.ct_list.lwe_size(),
            self.ct_list.lwe_ciphertext_count(),
            self.ct_list.ciphertext_modulus(),
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        {
            use crate::core_crypto::prelude::expand_lwe_compact_ciphertext_list;
            expand_lwe_compact_ciphertext_list(&mut output_lwe_ciphertext_list, &self.ct_list);
        }

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        {
            use crate::core_crypto::prelude::par_expand_lwe_compact_ciphertext_list;
            par_expand_lwe_compact_ciphertext_list(&mut output_lwe_ciphertext_list, &self.ct_list);
        }

        output_lwe_ciphertext_list
            .as_ref()
            .chunks_exact(self.ct_list.lwe_size().0)
            .map(|lwe_data| {
                let ct = LweCiphertext::from_container(
                    lwe_data.to_vec(),
                    self.ct_list.ciphertext_modulus(),
                );
                Ciphertext {
                    ct,
                    degree: self.degree,
                    message_modulus: self.message_modulus,
                    carry_modulus: self.carry_modulus,
                    pbs_order: self.pbs_order,
                    noise_level: self.noise_level,
                }
            })
            .collect::<Vec<_>>()
    }

    /// Deconstruct a [`CompactCiphertextList`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        LweCompactCiphertextListOwned<u64>,
        Degree,
        MessageModulus,
        CarryModulus,
        PBSOrder,
        NoiseLevel,
    ) {
        let Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        } = self;

        (
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        )
    }

    /// Construct a [`CompactCiphertextList`] from its constituents.
    pub fn from_raw_parts(
        ct_list: LweCompactCiphertextListOwned<u64>,
        degree: Degree,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        pbs_order: PBSOrder,
        noise_level: NoiseLevel,
    ) -> Self {
        Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        }
    }

    pub fn size_elements(&self) -> usize {
        self.ct_list.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.ct_list.size_bytes()
    }
}
