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
    CompressedCiphertextListConformanceParams,
    CompressedSquashedNoiseCiphertextListConformanceParams,
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
    pub(crate) lwe_per_glwe: NonZeroLweCiphertextCount,
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
        // Since this is used by conformance, it should never panic
        self.modulus_switched_glwe_ciphertext_list
            .iter()
            .map(|comp_glwe| comp_glwe.bodies_count().0)
            .fold(0, usize::saturating_add)
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

/// Checks the layout of a compressed list packed in GLWEs: every GLWE but the last holds exactly
/// `lwe_per_glwe` bodies, all GLWEs are stored with `storage_log_modulus` and are conformant with
/// `ct_params`
fn is_glwe_list_conformant<Scalar: UnsignedInteger>(
    glwe_list: &[CompressedModulusSwitchedGlweCiphertext<Scalar>],
    ct_params: &GlweCiphertextConformanceParams<Scalar>,
    lwe_per_glwe: LweCiphertextCount,
    storage_log_modulus: CiphertextModulusLog,
) -> bool {
    let Some((last, full_glwes)) = glwe_list.split_last() else {
        return true;
    };

    let count_is_ok = full_glwes
        .iter()
        .all(|glwe| glwe.bodies_count() == lwe_per_glwe)
        && last.bodies_count().0 <= lwe_per_glwe.0;

    let log_modulus_is_ok = glwe_list
        .iter()
        .all(|glwe| glwe.packed_integers().log_modulus() == storage_log_modulus);

    count_is_ok
        && log_modulus_is_ok
        && lwe_per_glwe.0 <= ct_params.polynomial_size.0
        && glwe_list.iter().all(|glwe| glwe.is_conformant(ct_params))
}

impl ParameterSetConformant for CompressedCiphertextList {
    type ParameterSet = CompressedCiphertextListConformanceParams;

    fn is_conformant(&self, params: &CompressedCiphertextListConformanceParams) -> bool {
        let Self {
            modulus_switched_glwe_ciphertext_list,
            meta,
        } = self;

        let CompressedCiphertextListConformanceParams {
            ct_params,
            lwe_per_glwe: params_lwe_per_glwe,
            message_modulus: params_message_modulus,
            carry_modulus: params_carry_modulus,
            atomic_pattern: params_atomic_pattern,
            storage_log_modulus,
        } = params;

        if modulus_switched_glwe_ciphertext_list.is_empty() {
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

        is_glwe_list_conformant(
            modulus_switched_glwe_ciphertext_list,
            ct_params,
            *params_lwe_per_glwe,
            *storage_log_modulus,
        ) && LweCiphertextCount::from(*lwe_per_glwe) == *params_lwe_per_glwe
            && *ciphertext_modulus == ct_params.ct_modulus
            && message_modulus == params_message_modulus
            && carry_modulus == params_carry_modulus
            && atomic_pattern == params_atomic_pattern
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseCiphertextListMetaVersions)]
pub(crate) struct CompressedSquashedNoiseCiphertextListMeta {
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) lwe_per_glwe: NonZeroLweCiphertextCount,
}

/// A compressed list of [`SquashedNoiseCiphertext`].
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseCiphertextListVersions)]
pub struct CompressedSquashedNoiseCiphertextList {
    pub(crate) glwe_ciphertext_list: Vec<CompressedModulusSwitchedGlweCiphertext<u128>>,
    pub(crate) meta: Option<CompressedSquashedNoiseCiphertextListMeta>,
}

impl ParameterSetConformant for CompressedSquashedNoiseCiphertextList {
    type ParameterSet = CompressedSquashedNoiseCiphertextListConformanceParams;

    fn is_conformant(
        &self,
        params: &CompressedSquashedNoiseCiphertextListConformanceParams,
    ) -> bool {
        let Self {
            glwe_ciphertext_list,
            meta,
        } = self;

        let CompressedSquashedNoiseCiphertextListConformanceParams {
            ct_params,
            lwe_per_glwe: params_lwe_per_glwe,
            message_modulus: params_message_modulus,
            carry_modulus: params_carry_modulus,
        } = params;

        if glwe_ciphertext_list.is_empty() {
            return true;
        }

        let Some(meta) = meta.as_ref() else {
            return false;
        };

        let CompressedSquashedNoiseCiphertextListMeta {
            message_modulus,
            carry_modulus,
            lwe_per_glwe,
        } = meta;

        // Squashed noise ciphertexts are packed without modulus switch
        let storage_log_modulus = ct_params.ct_modulus.into_modulus_log();

        is_glwe_list_conformant(
            glwe_ciphertext_list,
            ct_params,
            *params_lwe_per_glwe,
            storage_log_modulus,
        ) && LweCiphertextCount::from(*lwe_per_glwe) == *params_lwe_per_glwe
            && message_modulus == params_message_modulus
            && carry_modulus == params_carry_modulus
    }
}

impl CompressedSquashedNoiseCiphertextList {
    pub fn len(&self) -> usize {
        // Since this is used by conformance, it should never panic
        self.glwe_ciphertext_list
            .iter()
            .map(|comp_glwe| comp_glwe.bodies_count().0)
            .fold(0, usize::saturating_add)
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

        let lwe_per_glwe = meta.lwe_per_glwe.get();
        let glwe_idx = index / lwe_per_glwe;

        let glwe = self
            .glwe_ciphertext_list
            .get(glwe_idx)
            .ok_or_else(|| {
                error!(
                    "Invalid CompressedSquashedNoiseCiphertextList: index {index} is in GLWE \
                    {glwe_idx}, but the list only has {} GLWEs",
                    self.glwe_ciphertext_list.len()
                )
            })?
            .extract();

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

    /// Returns the message modulus of the Ciphertexts in the list, or None if the list is empty
    pub fn message_modulus(&self) -> Option<MessageModulus> {
        self.meta.as_ref().map(|meta| meta.message_modulus)
    }
}
