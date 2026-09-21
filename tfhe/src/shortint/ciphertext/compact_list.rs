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
use crate::shortint::parameters::{
    CarryModulus, CompactCiphertextListExpansionKind, ExpandFunctionsView, MessageModulus,
};
use crate::shortint::server_key::GenericServerKey;
use crate::shortint::{AtomicPatternKind, KeySwitchingKeyView};
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
    fn expand_raw(&self) -> ExpandedCiphertextList {
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
    /// The expansion is done without casting or without applying any function.
    ///
    /// Return an error if the list requires casting to be used.
    pub fn expand_without_casting(&self) -> Result<Vec<Ciphertext>, crate::Error> {
        self.expand_raw().into_ciphertexts()
    }

    /// Expand a [`CompactCiphertextList`] to a `Vec` of [`Ciphertext`].
    ///
    /// The expansion is done without casting but will apply the provided list of functions.
    ///
    /// Return an error if the list requires casting to be used.
    pub fn expand_without_casting_and_apply_functions<AP: AtomicPattern + Sync>(
        &self,
        server_key: &GenericServerKey<AP>,
        functions: ExpandFunctionsView,
    ) -> Result<Vec<Ciphertext>, crate::Error> {
        self.expand_raw().apply_functions(server_key, functions)
    }

    /// Expand a [`CompactCiphertextList`] to a `Vec` of [`Ciphertext`].
    ///
    /// The ciphertexts will be casted to the destination params of the provided casting key.
    /// A list of functions will be applied at the same time.
    ///
    /// This is useful when using separate parameters for the public key used to encrypt the
    /// [`CompactCiphertextList`] allowing to keyswitch to the computation params during expansion.
    ///
    /// Return an error if the list does not require casting or if the list of function does not
    /// match the size of the ciphertext list.
    pub fn expand<'a>(
        &self,
        casting_key: KeySwitchingKeyView<'a>,
        functions: Option<ExpandFunctionsView<'a>>,
    ) -> Result<Vec<Ciphertext>, crate::Error> {
        self.expand_raw()
            .cast_and_apply_functions(casting_key, functions)
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

    pub fn len(&self) -> usize {
        self.ct_list.lwe_ciphertext_count().0
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A ciphertext list that has been expanded, but no post-processing (cast, unpack, sanitize) has
/// been applied
#[derive(Clone)]
struct ExpandedCiphertextList {
    ct_list: LweCiphertextListOwned<u64>,
    degree: Degree,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    expansion_kind: CompactCiphertextListExpansionKind,
}

impl ExpandedCiphertextList {
    fn block(
        &self,
        lwe_view: LweCiphertextView<'_, u64>,
        atomic_pattern: AtomicPatternKind,
        noise_level: NoiseLevel,
    ) -> Ciphertext {
        let ct = LweCiphertext::from_container(
            lwe_view.as_ref().to_vec(),
            self.ct_list.ciphertext_modulus(),
        );

        Ciphertext::new(
            ct,
            self.degree,
            noise_level,
            self.message_modulus,
            self.carry_modulus,
            atomic_pattern,
        )
    }

    fn par_iter_blocks(
        &self,
        atomic_pattern: AtomicPatternKind,
        noise_level: NoiseLevel,
    ) -> impl IndexedParallelIterator<Item = Ciphertext> + '_ {
        self.ct_list
            .par_iter()
            .map(move |lwe_view| self.block(lwe_view, atomic_pattern, noise_level))
    }

    /// Extract the raw ciphertexts from this list, without any post processing
    ///
    /// Returns an error if the ciphertexts require to be casted to new parameters
    pub fn into_ciphertexts(self) -> Result<Vec<Ciphertext>, crate::Error> {
        match self.expansion_kind {
            CompactCiphertextListExpansionKind::RequiresCasting => {
                Err(crate::Error::new(String::from(
                    "Cannot expand a CompactCiphertextList that requires casting without a \
                    shortint::KeySwitchingKey. Please call `.cast_and_apply_functions`.",
                )))
            }
            CompactCiphertextListExpansionKind::NoCasting(atomic_pattern) => {
                let res = self
                    .ct_list
                    .iter()
                    .map(|lwe_view| self.block(lwe_view, atomic_pattern, NoiseLevel::NOMINAL))
                    .collect::<Vec<_>>();

                Ok(res)
            }
        }
    }

    /// Extract the raw ciphertexts from this list, and apply the provided list of functions
    pub fn apply_functions<AP: AtomicPattern + Sync>(
        self,
        server_key: &GenericServerKey<AP>,
        functions: ExpandFunctionsView<'_>,
    ) -> Result<Vec<Ciphertext>, crate::Error> {
        if functions.len() != self.ct_list.lwe_ciphertext_count().0 {
            return Err(crate::error!(
                "Cannot expand a CompactCiphertextList: got {} functions for casting, \
                            expected {}",
                functions.len(),
                self.ct_list.lwe_ciphertext_count().0
            ));
        }

        match self.expansion_kind {
            CompactCiphertextListExpansionKind::RequiresCasting => {
                Err(crate::Error::new(String::from(
                    "Cannot expand a CompactCiphertextList that requires casting with a \
                    shortint::ServerKey. Please call `.cast_and_apply_functions` with a \
                    shortint::KeySwitchingKey.",
                )))
            }
            CompactCiphertextListExpansionKind::NoCasting(atomic_pattern) => {
                if server_key.atomic_pattern.kind() != atomic_pattern {
                    return Err(crate::error!(
                        "Cannot expand CompactCiphertextList: list encrypted for AP {:?}, \
                            expected AP {:?}",
                        atomic_pattern,
                        server_key.atomic_pattern.kind()
                    ));
                }

                let res = self
                    .par_iter_blocks(atomic_pattern, NoiseLevel::NOMINAL)
                    .zip(functions.par_iter())
                    .flat_map(|(block, functions)| match functions {
                        Some(functions) => functions
                            .par_iter()
                            .map(|function| {
                                let acc = server_key.generate_lookup_table(function);
                                server_key.apply_lookup_table(&block, &acc)
                            })
                            .collect::<Vec<_>>(),
                        None => vec![block],
                    })
                    .collect();

                Ok(res)
            }
        }
    }

    /// Extract the raw ciphertexts from this list, cast them using the provided casting key,
    /// and apply the provided list of functions
    pub fn cast_and_apply_functions<'a>(
        self,
        casting_key: KeySwitchingKeyView<'a>,
        functions: Option<ExpandFunctionsView<'a>>,
    ) -> Result<Vec<Ciphertext>, crate::Error> {
        match self.expansion_kind {
            CompactCiphertextListExpansionKind::RequiresCasting => {
                let functions = match functions {
                    Some(functions) => {
                        if functions.len() != self.ct_list.lwe_ciphertext_count().0 {
                            return Err(crate::error!(
                                "Cannot expand a CompactCiphertextList: got {} functions for casting, \
                                expected {}",
                                functions.len(),
                                self.ct_list.lwe_ciphertext_count().0
                            ));
                        }

                        functions
                    }
                    None => &vec![None; self.ct_list.lwe_ciphertext_count().0],
                };

                let atomic_pattern = casting_key.dest_server_key.atomic_pattern.kind();

                let res = self
                    .par_iter_blocks(atomic_pattern, NoiseLevel::UNKNOWN)
                    .zip(functions.par_iter())
                    .flat_map(|(block, functions)| {
                        casting_key.cast_and_apply_functions(&block, functions.as_deref())
                    })
                    .collect::<Vec<_>>();
                Ok(res)
            }
            CompactCiphertextListExpansionKind::NoCasting(_) => {
                Err(crate::Error::new(String::from(
                    "Cannot cast a CompactCiphertextList that does not require casting. Please \
                    call `.apply_functions` with a shortint::ServerKey, or `.into_ciphertexts` \
                    if there is no function to apply.",
                )))
            }
        }
    }
}
