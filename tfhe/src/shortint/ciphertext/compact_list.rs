//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextListConformanceParams;
use super::common::*;
use super::standard::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::traits::ContiguousEntityContainer;
use crate::core_crypto::entities::*;
use crate::shortint::backward_compatibility::ciphertext::CompactCiphertextListVersions;
pub use crate::shortint::parameters::ShortintCompactCiphertextListCastingMode;
use crate::shortint::parameters::{
    CarryModulus, CompactCiphertextListExpansionKind, MessageModulus,
};
use rayon::prelude::*;
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
    pub expansion_kind: CompactCiphertextListExpansionKind,
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
        } = self;

        let CiphertextListConformanceParams {
            ct_list_params,
            message_modulus: param_message_modulus,
            carry_modulus: param_carry_modulus,
            degree: param_degree,
            expansion_kind: param_expansion_kind,
        } = param;

        ct_list.is_conformant(ct_list_params)
            && *message_modulus == *param_message_modulus
            && *carry_modulus == *param_carry_modulus
            && *expansion_kind == *param_expansion_kind
            && *degree == *param_degree
    }
}

impl CompactCiphertextList {
    /// Expand a [`CompactCiphertextList`] to a `Vec` of [`Ciphertext`].
    ///
    /// The function takes a [`ShortintCompactCiphertextListCastingMode`] to indicate whether a
    /// keyswitch should be applied during expansion, and if it does, functions can be applied as
    /// well during casting, which can be more efficient if a refresh is required during casting.
    ///
    /// This is useful when using separate parameters for the public key used to encrypt the
    /// [`CompactCiphertextList`] allowing to keyswitch to the computation params during expansion.
    pub fn expand(
        &self,
        casting_mode: ShortintCompactCiphertextListCastingMode<'_>,
    ) -> Result<Vec<Ciphertext>, crate::Error> {
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

        match (self.expansion_kind, casting_mode) {
            (
                CompactCiphertextListExpansionKind::RequiresCasting,
                ShortintCompactCiphertextListCastingMode::NoCasting,
            ) => Err(crate::Error::new(String::from(
                "Cannot expand a CompactCiphertextList that requires casting without casting, \
                    please provide a shortint::KeySwitchingKey passing it with the enum variant \
                    CompactCiphertextListExpansionMode::CastIfNecessary as casting_mode.",
            ))),
            (
                CompactCiphertextListExpansionKind::RequiresCasting,
                ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                    casting_key,
                    functions,
                },
            ) => {
                let functions = match functions {
                    Some(functions) => {
                        if functions.len() != output_lwe_ciphertext_list.lwe_ciphertext_count().0 {
                            return Err(crate::Error::new(format!(
                            "Cannot expand a CompactCiphertextList: got {} functions for casting, \
                            expected {}",
                            functions.len(),
                            output_lwe_ciphertext_list.lwe_ciphertext_count().0
                        )));
                        }
                        functions
                    }
                    None => &vec![None; output_lwe_ciphertext_list.lwe_ciphertext_count().0],
                };

                let pbs_order = casting_key.dest_server_key.pbs_order;

                let res = output_lwe_ciphertext_list
                    .par_iter()
                    .zip(functions.par_iter())
                    .flat_map(|(lwe_view, functions)| {
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
                            noise_level: NoiseLevel::UNKNOWN,
                        };

                        casting_key
                            .cast_and_apply_functions(&shortint_ct_to_cast, functions.as_deref())
                    })
                    .collect::<Vec<_>>();
                Ok(res)
            }
            (CompactCiphertextListExpansionKind::NoCasting(pbs_order), _) => {
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
                            noise_level: NoiseLevel::NOMINAL,
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
    ) {
        let Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
        } = self;

        (
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
        )
    }

    /// Construct a [`CompactCiphertextList`] from its constituents.
    pub fn from_raw_parts(
        ct_list: LweCompactCiphertextListOwned<u64>,
        degree: Degree,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        expansion_kind: CompactCiphertextListExpansionKind,
    ) -> Self {
        Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
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
