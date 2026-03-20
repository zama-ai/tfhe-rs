use tfhe_versionable::Versionize;

use self::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::*;
use crate::error;
use crate::shortint::backward_compatibility::ciphertext::{
    CompressedCiphertextListMetaVersions, CompressedCiphertextListVersions,
    CompressedSquashedNoiseCiphertextListMetaVersions,
    CompressedSquashedNoiseCiphertextListVersions,
};
use crate::shortint::parameters::{
    CompressedCiphertextConformanceParams, CompressedSquashedNoiseCiphertextConformanceParams,
};
use crate::shortint::{AtomicPatternKind, CarryModulus, MessageModulus};

use super::{Degree, MaxDegree, SquashedNoiseCiphertext};

/// Metadata needed to rebuild the ciphertexts in a [`CompressedCiphertextList`]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedCiphertextListMetaVersions)]
pub(crate) struct CompressedCiphertextListMeta {
    pub(crate) ciphertext_modulus: CiphertextModulus<u64>,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) atomic_pattern: AtomicPatternKind,
    pub(crate) lwe_per_glwe: LweCiphertextCount,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedCiphertextListVersions)]
pub struct CompressedCiphertextList {
    pub(crate) modulus_switched_glwe_ciphertext_list:
        Vec<CompressedModulusSwitchedGlweCiphertext<u64>>,
    pub(crate) meta: Option<CompressedCiphertextListMeta>,
}

impl CompressedCiphertextList {
    pub fn len(&self) -> usize {
        self.modulus_switched_glwe_ciphertext_list
            .iter()
            .map(|comp_glwe| comp_glwe.bodies_count().0)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the message modulus of the Ciphertexts in the list, or None if the list is empty
    pub fn message_modulus(&self) -> Option<MessageModulus> {
        self.meta.as_ref().map(|meta| meta.message_modulus)
    }

    /// Returns how many u64 are needed to store the packed elements
    #[cfg(all(test, feature = "gpu"))]
    pub(crate) fn flat_len(&self) -> usize {
        self.modulus_switched_glwe_ciphertext_list
            .iter()
            .map(|glwe| glwe.packed_integers().packed_coeffs().len())
            .sum()
    }
}

impl ParameterSetConformant for CompressedCiphertextList {
    type ParameterSet = CompressedCiphertextConformanceParams;

    fn is_conformant(&self, params: &CompressedCiphertextConformanceParams) -> bool {
        let Self {
            modulus_switched_glwe_ciphertext_list,
            meta,
        } = self;

        let len = modulus_switched_glwe_ciphertext_list.len();

        if len == 0 {
            return true;
        }

        let Some(meta) = meta else {
            return false;
        };

        let CompressedCiphertextListMeta {
            ciphertext_modulus,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            lwe_per_glwe,
        } = meta;

        let last_body_count = modulus_switched_glwe_ciphertext_list
            .last()
            .unwrap()
            .bodies_count()
            .0;

        let count_is_ok = modulus_switched_glwe_ciphertext_list[..len - 1]
            .iter()
            .all(|a| a.bodies_count() == params.lwe_per_glwe)
            && last_body_count <= params.lwe_per_glwe.0;

        count_is_ok
            && modulus_switched_glwe_ciphertext_list
                .iter()
                .all(|glwe| glwe.is_conformant(&params.ct_params))
            && lwe_per_glwe.0 <= params.ct_params.polynomial_size.0
            && *lwe_per_glwe == params.lwe_per_glwe
            && *ciphertext_modulus == params.ct_params.ct_modulus
            && *message_modulus == params.message_modulus
            && *carry_modulus == params.carry_modulus
            && *atomic_pattern == params.atomic_pattern
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseCiphertextListMetaVersions)]
pub(crate) struct CompressedSquashedNoiseCiphertextListMeta {
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) lwe_per_glwe: LweCiphertextCount,
}

/// A compressed list of [`SquashedNoiseCiphertext`].
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseCiphertextListVersions)]
pub struct CompressedSquashedNoiseCiphertextList {
    pub(crate) glwe_ciphertext_list: Vec<CompressedModulusSwitchedGlweCiphertext<u128>>,
    pub(crate) meta: Option<CompressedSquashedNoiseCiphertextListMeta>,
}

impl ParameterSetConformant for CompressedSquashedNoiseCiphertextList {
    type ParameterSet = CompressedSquashedNoiseCiphertextConformanceParams;

    fn is_conformant(&self, params: &CompressedSquashedNoiseCiphertextConformanceParams) -> bool {
        let Self {
            glwe_ciphertext_list,
            meta,
        } = self;

        let len = glwe_ciphertext_list.len();

        if len == 0 {
            return true;
        }

        let Some(meta) = meta.as_ref() else {
            return false;
        };

        let last_body_count = glwe_ciphertext_list.last().unwrap().bodies_count().0;

        let count_is_ok = glwe_ciphertext_list[..len - 1]
            .iter()
            .all(|a| a.bodies_count() == params.lwe_per_glwe)
            && last_body_count <= params.lwe_per_glwe.0;

        count_is_ok
            && glwe_ciphertext_list
                .iter()
                .all(|glwe| glwe.is_conformant(&params.ct_params))
            && meta.lwe_per_glwe.0 <= params.ct_params.polynomial_size.0
            && meta.lwe_per_glwe == params.lwe_per_glwe
            && meta.message_modulus == params.message_modulus
            && meta.carry_modulus == params.carry_modulus
    }
}

impl CompressedSquashedNoiseCiphertextList {
    pub fn len(&self) -> usize {
        self.glwe_ciphertext_list
            .iter()
            .map(|comp_glwe| comp_glwe.bodies_count().0)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Unpack a single ciphertext from the list.
    ///
    /// Return an error if the index is greater than the size of the list.
    ///
    /// After unpacking, the individual ciphertexts must be decrypted with the
    /// [`NoiseSquashingPrivateKey`] derived from the [`NoiseSquashingCompressionPrivateKey`] used
    /// for compression.
    ///
    /// [`NoiseSquashingPrivateKey`]: crate::shortint::noise_squashing::NoiseSquashingPrivateKey
    /// [`NoiseSquashingCompressionPrivateKey`]: crate::shortint::list_compression::NoiseSquashingCompressionPrivateKey
    pub fn unpack(&self, index: usize) -> Result<SquashedNoiseCiphertext, crate::Error> {
        // Check this first to make sure we don't try to access the metadata if the list is empty
        if index >= self.len() {
            return Err(error!(
                "Tried getting index {index} for CompressedSquashedNoiseCiphertextList \
                with {} elements, out of bound access.",
                self.len()
            ));
        }

        let meta = self.meta.as_ref().ok_or_else(|| {
            error!("Missing ciphertext metadata in CompressedSquashedNoiseCiphertextList")
        })?;

        let lwe_per_glwe = meta.lwe_per_glwe.0;
        let glwe_idx = index / lwe_per_glwe;

        let glwe = self.glwe_ciphertext_list[glwe_idx].extract();

        let glwe_dimension = glwe.glwe_size().to_glwe_dimension();
        let polynomial_size = glwe.polynomial_size();
        let ciphertext_modulus = glwe.ciphertext_modulus();

        let lwe_size = glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size();

        let monomial_degree = MonomialDegree(index % lwe_per_glwe);

        let mut extracted_lwe = SquashedNoiseCiphertext::new_zero(
            lwe_size,
            ciphertext_modulus,
            meta.message_modulus,
            meta.carry_modulus,
        );

        extract_lwe_sample_from_glwe_ciphertext(
            &glwe,
            extracted_lwe.lwe_ciphertext_mut(),
            monomial_degree,
        );
        extracted_lwe.set_degree(Degree::new(
            MaxDegree::from_msg_carry_modulus(meta.message_modulus, meta.carry_modulus).get(),
        ));

        Ok(extracted_lwe)
    }

    pub fn message_modulus(&self) -> Option<MessageModulus> {
        self.meta.as_ref().map(|meta| meta.message_modulus)
    }
}
