//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextListConformanceParams;
use super::common::*;
use super::standard::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::traits::ContiguousEntityContainer;
use crate::core_crypto::entities::*;
pub use crate::shortint::parameters::ShortintCompactCiphertextListCastingMode;
use crate::shortint::parameters::{
    CarryModulus, CompactCiphertextListExpansionKind, MessageModulus,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactCiphertextList {
    pub ct_list: LweCompactCiphertextListOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CiphertextListConformanceParams;

    fn is_conformant(&self, param: &CiphertextListConformanceParams) -> bool {
        let Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
            noise_level,
        } = self;
        let CiphertextListConformanceParams {
            ct_list_params,
            message_modulus: param_message_modulus,
            carry_modulus: param_carry_modulus,
            degree: param_degree,
            noise_level: param_noise_level,
            expansion_kind: param_expansion_kind,
        } = param;
        ct_list.is_conformant(ct_list_params)
            && *message_modulus == *param_message_modulus
            && *carry_modulus == *param_carry_modulus
            && *expansion_kind == *param_expansion_kind
            && *degree == *param_degree
            && *noise_level == *param_noise_level
    }
}

impl CompactCiphertextList {
    pub fn expand(
        &self,
        casting_mode: ShortintCompactCiphertextListCastingMode<'_>,
    ) -> Result<Vec<Ciphertext>, crate::Error> {
        if matches!(
            self.expansion_kind,
            CompactCiphertextListExpansionKind::RequiresCasting
        ) && matches!(
            casting_mode,
            ShortintCompactCiphertextListCastingMode::NoCasting
        ) {
            return Err(crate::Error::new(String::from(
                "Cannot expand a CompactCiphertextList that requires casting without casting, \
                please provide a shortint::KeySwitchingKey passing it with the enum variant \
                CompactCiphertextListExpansionMode::CastIfNecessary as casting_mode.",
            )));
        }

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

        match self.expansion_kind {
            CompactCiphertextListExpansionKind::RequiresCasting => match casting_mode {
                ShortintCompactCiphertextListCastingMode::CastIfNecessary(casting_key) => {
                    let pbs_order = casting_key.dest_server_key.pbs_order;

                    let res = output_lwe_ciphertext_list
                        .iter()
                        .map(|lwe_view| {
                            let lwe_to_cast = LweCiphertext::from_container(
                                lwe_view.as_ref().to_vec(),
                                self.ct_list.ciphertext_modulus(),
                            );
                            let shortint_ct_to_cast = Ciphertext {
                                ct: lwe_to_cast,
                                degree: self.degree,
                                message_modulus: self.message_modulus,
                                carry_modulus: self.carry_modulus,
                                pbs_order,
                                noise_level: self.noise_level,
                            };

                            casting_key.cast(&shortint_ct_to_cast)
                        })
                        .collect::<Vec<_>>();
                    Ok(res)
                }
                ShortintCompactCiphertextListCastingMode::NoCasting => unreachable!(),
            },
            CompactCiphertextListExpansionKind::NoCasting(pbs_order) => {
                let res = output_lwe_ciphertext_list
                    .iter()
                    .map(|lwe_view| {
                        let ct = LweCiphertext::from_container(
                            lwe_view.as_ref().to_vec(),
                            self.ct_list.ciphertext_modulus(),
                        );
                        Ciphertext {
                            ct,
                            degree: self.degree,
                            message_modulus: self.message_modulus,
                            carry_modulus: self.carry_modulus,
                            pbs_order,
                            noise_level: self.noise_level,
                        }
                    })
                    .collect::<Vec<_>>();

                Ok(res)
            }
        }
    }

    /// Deconstruct a [`CompactCiphertextList`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        LweCompactCiphertextListOwned<u64>,
        Degree,
        MessageModulus,
        CarryModulus,
        CompactCiphertextListExpansionKind,
        NoiseLevel,
    ) {
        let Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
            noise_level,
        } = self;

        (
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
            noise_level,
        )
    }

    /// Construct a [`CompactCiphertextList`] from its constituents.
    pub fn from_raw_parts(
        ct_list: LweCompactCiphertextListOwned<u64>,
        degree: Degree,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        expansion_kind: CompactCiphertextListExpansionKind,
        noise_level: NoiseLevel,
    ) -> Self {
        Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
            noise_level,
        }
    }

    pub fn needs_casting(&self) -> bool {
        matches!(
            self.expansion_kind,
            CompactCiphertextListExpansionKind::RequiresCasting
        )
    }

    pub fn size_elements(&self) -> usize {
        self.ct_list.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.ct_list.size_bytes()
    }
}
