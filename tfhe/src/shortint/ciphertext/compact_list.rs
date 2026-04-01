//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextListConformanceParams;
use super::common::*;
use super::standard::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::traits::ContiguousEntityContainer;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::par_expand_lwe_compact_ciphertext_list;
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::backward_compatibility::ciphertext::CompactCiphertextListVersions;
pub use crate::shortint::parameters::ShortintCompactCiphertextListCastingMode;
use crate::shortint::parameters::{
    CarryModulus, CiphertextConformanceParams, CompactCiphertextListExpansionKind, MessageModulus,
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
    /// Expands a `CompactCiphertextList` by extracting the individual LWEs, but do not perform any
    /// operations (casting, sanitizing, ...)
    pub fn expand_without_casting(&self) -> ExpandedCiphertextList {
        let mut output_lwe_ciphertext_list = LweCiphertextList::new(
            0u64,
            self.ct_list.lwe_size(),
            self.ct_list.lwe_ciphertext_count(),
            self.ct_list.ciphertext_modulus(),
        );

        par_expand_lwe_compact_ciphertext_list(&mut output_lwe_ciphertext_list, &self.ct_list);

        ExpandedCiphertextList {
            ct_list: output_lwe_ciphertext_list,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: self.expansion_kind,
        }
    }

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
        let expanded = self.expand_without_casting();

        expanded.cast(casting_mode)
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

    pub fn is_packed(&self) -> bool {
        self.degree.get() > self.message_modulus.corresponding_max_degree().get()
    }
}

/// A ciphertext list that has been expanded, but no post-processing (cast, unpack, sanitize) has
/// been applied
pub struct ExpandedCiphertextList {
    ct_list: LweCiphertextListOwned<u64>,
    degree: Degree,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    expansion_kind: CompactCiphertextListExpansionKind,
}

pub struct ExpandedCiphertextListConformanceParams {
    ct_params: LweCiphertextConformanceParams<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
}

impl From<CiphertextConformanceParams> for ExpandedCiphertextListConformanceParams {
    fn from(value: CiphertextConformanceParams) -> Self {
        Self {
            ct_params: value.ct_params,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
        }
    }
}

impl ParameterSetConformant for ExpandedCiphertextList {
    type ParameterSet = ExpandedCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let is_packed = self.is_packed();
        let Self {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind: _expansion_kind,
        } = self;

        let expected_degree = if is_packed {
            Degree::new(message_modulus.0 * message_modulus.0 - 1)
        } else {
            Degree::new(message_modulus.0 - 1)
        };

        for ct in ct_list.iter() {
            if !ct.is_conformant(&parameter_set.ct_params) {
                return false;
            }
        }

        *message_modulus == parameter_set.message_modulus
            && *carry_modulus == parameter_set.carry_modulus
            && *degree == expected_degree
    }
}

impl ExpandedCiphertextList {
    pub fn is_packed(&self) -> bool {
        self.degree.get() > self.message_modulus.corresponding_max_degree().get()
    }

    /// Merge 2 `ExpandedCiphertextList` that come from the same
    /// `ProvenCompactCiphertextList` into a single one.
    ///
    /// Returns an error if both lists do not have the same metadata.
    #[cfg(feature = "zk-pok")]
    pub fn merge(mut self, other: Self) -> Result<Self, crate::Error> {
        if self.ct_list.lwe_size() != other.ct_list.lwe_size()
            || self.ct_list.ciphertext_modulus() != other.ct_list.ciphertext_modulus()
            || self.degree != other.degree
            || self.message_modulus != other.message_modulus
            || self.carry_modulus != other.carry_modulus
            || self.expansion_kind != other.expansion_kind
        {
            return Err(crate::error!(
                "Parameters in the individual lists of the proven compact ciphertext list \
                do not match, cannot merge lists with incompatible parameters",
            ));
        }

        let lwe_size = self.ct_list.lwe_size();
        let modulus = self.ct_list.ciphertext_modulus();
        let mut data = self.ct_list.into_container();
        data.extend(other.ct_list.into_container());
        self.ct_list = LweCiphertextList::from_container(data, lwe_size, modulus);
        Ok(self)
    }

    /// Applies the post-processing step to the compact list, based on its
    /// CompactCiphertextListExpansionKind and the provided casting_mode.
    pub fn cast(
        self,
        casting_mode: ShortintCompactCiphertextListCastingMode<'_>,
    ) -> Result<Vec<Ciphertext>, crate::Error> {
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
                        if functions.len() != self.ct_list.lwe_ciphertext_count().0 {
                            return Err(crate::Error::new(format!(
                            "Cannot expand a CompactCiphertextList: got {} functions for casting, \
                            expected {}",
                            functions.len(),
                            self.ct_list.lwe_ciphertext_count().0
                        )));
                        }
                        functions
                    }
                    None => &vec![None; self.ct_list.lwe_ciphertext_count().0],
                };

                let atomic_pattern = casting_key.dest_server_key.atomic_pattern.kind();

                let res = self
                    .ct_list
                    .par_iter()
                    .zip(functions.par_iter())
                    .flat_map(|(lwe_view, functions)| {
                        let lwe_to_cast = LweCiphertext::from_container(
                            lwe_view.as_ref().to_vec(),
                            self.ct_list.ciphertext_modulus(),
                        );
                        let shortint_ct_to_cast = Ciphertext::new(
                            lwe_to_cast,
                            self.degree,
                            NoiseLevel::UNKNOWN,
                            self.message_modulus,
                            self.carry_modulus,
                            atomic_pattern,
                        );

                        casting_key
                            .cast_and_apply_functions(&shortint_ct_to_cast, functions.as_deref())
                    })
                    .collect::<Vec<_>>();
                Ok(res)
            }
            (CompactCiphertextListExpansionKind::NoCasting(atomic_pattern), _) => {
                let res = self
                    .ct_list
                    .iter()
                    .map(|lwe_view| {
                        let ct = LweCiphertext::from_container(
                            lwe_view.as_ref().to_vec(),
                            self.ct_list.ciphertext_modulus(),
                        );

                        Ciphertext::new(
                            ct,
                            self.degree,
                            NoiseLevel::NOMINAL,
                            self.message_modulus,
                            self.carry_modulus,
                            atomic_pattern,
                        )
                    })
                    .collect::<Vec<_>>();

                Ok(res)
            }
        }
    }
}
