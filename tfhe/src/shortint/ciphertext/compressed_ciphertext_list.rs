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
        && last.bodies_count().0 <= lwe_per_glwe.0
        && last.bodies_count().0 > 0;

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

        // If the list is seen as "empty", we check that everything is coherent, i.e. empty glwe
        // list and empty meta. This allows us to trust the `is_empty` method later.
        if self.is_empty() {
            return modulus_switched_glwe_ciphertext_list.is_empty() && meta.is_none();
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

        // If the list is seen as "empty", we check that everything is coherent, i.e. empty glwe
        // list and empty meta. This allows us to trust the `is_empty` method later.
        if self.is_empty() {
            return glwe_ciphertext_list.is_empty() && meta.is_none();
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

    /// Returns how many u128 are needed to store the packed elements
    #[cfg(all(test, feature = "gpu"))]
    pub(crate) fn flat_len(&self) -> usize {
        self.glwe_ciphertext_list
            .iter()
            .map(|glwe| glwe.packed_integers().packed_coeffs().len())
            .sum()
    }

    /// Unpack a single ciphertext from the list.
    ///
    /// Return an error if the index is greater than or equal to the size of the list.
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

        let meta = self.metadata()?;
        let lwe_per_glwe = meta.lwe_per_glwe.get();
        let glwe_idx = index / lwe_per_glwe;
        let sample = index % lwe_per_glwe;
        let glwe = self
            .get_glwe_checked(glwe_idx, sample..sample + 1, meta)?
            .extract();

        Ok(Self::extract_sample(&glwe, meta, MonomialDegree(sample)))
    }

    fn metadata(&self) -> crate::Result<&CompressedSquashedNoiseCiphertextListMeta> {
        self.meta.as_ref().ok_or_else(|| {
            error!("Missing ciphertext metadata in CompressedSquashedNoiseCiphertextList")
        })
    }

    /// Check the packing layout and requested samples before expanding a GLWE.
    fn get_glwe_checked(
        &self,
        glwe_idx: usize,
        samples: std::ops::Range<usize>,
        meta: &CompressedSquashedNoiseCiphertextListMeta,
    ) -> crate::Result<&CompressedModulusSwitchedGlweCiphertext<u128>> {
        let glwe = self.glwe_ciphertext_list.get(glwe_idx).ok_or_else(|| {
            error!(
                "Invalid CompressedSquashedNoiseCiphertextList: GLWE index {glwe_idx} \
                is out of bounds for {} GLWEs",
                self.glwe_ciphertext_list.len()
            )
        })?;
        let lwe_per_glwe = meta.lwe_per_glwe.get();
        let bodies_count = glwe.bodies_count().0;
        let polynomial_size = glwe.polynomial_size().0;
        if lwe_per_glwe > polynomial_size
            || bodies_count > lwe_per_glwe
            || (glwe_idx < self.glwe_ciphertext_list.len() - 1 && bodies_count != lwe_per_glwe)
            || samples.end > bodies_count
        {
            return Err(error!(
                "Invalid CompressedSquashedNoiseCiphertextList: GLWE {glwe_idx} has \
                {bodies_count} bodies and polynomial size {polynomial_size}, but the metadata \
                specifies {lwe_per_glwe} samples per GLWE and samples {samples:?} were requested"
            ));
        }
        Ok(glwe)
    }

    fn extract_sample(
        glwe: &GlweCiphertextOwned<u128>,
        meta: &CompressedSquashedNoiseCiphertextListMeta,
        monomial_degree: MonomialDegree,
    ) -> SquashedNoiseCiphertext {
        let glwe_dimension = glwe.glwe_size().to_glwe_dimension();
        let polynomial_size = glwe.polynomial_size();
        let ciphertext_modulus = glwe.ciphertext_modulus();

        let lwe_size = glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size();

        let mut extracted_lwe = SquashedNoiseCiphertext::new_zero(
            lwe_size,
            ciphertext_modulus,
            meta.message_modulus,
            meta.carry_modulus,
        );

        extract_lwe_sample_from_glwe_ciphertext(
            glwe,
            extracted_lwe.lwe_ciphertext_mut(),
            monomial_degree,
        );
        extracted_lwe.set_degree(Degree::new(
            MaxDegree::from_msg_carry_modulus(meta.message_modulus, meta.carry_modulus).get(),
        ));

        extracted_lwe
    }

    /// Unpacks a half-open range, expanding each touched GLWE only once.
    ///
    /// Empty ranges within the list (including `len()..len()`) return an empty vector.
    /// Reversed ranges and ranges extending past the list return an error.
    pub(crate) fn unpack_range(
        &self,
        range: std::ops::Range<usize>,
    ) -> crate::Result<Vec<SquashedNoiseCiphertext>> {
        let len = self.len();
        if range.start > range.end || range.end > len {
            return Err(error!(
                "Tried getting range {range:?} for CompressedSquashedNoiseCiphertextList \
                with {len} elements, out of bound access."
            ));
        }
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let meta = self.metadata()?;
        let lwe_per_glwe = meta.lwe_per_glwe.get();
        let mut result = Vec::with_capacity(range.len());
        let mut index = range.start;
        while index < range.end {
            let glwe_idx = index / lwe_per_glwe;
            let first_sample = index % lwe_per_glwe;
            // Stop at either the GLWE boundary or the end of the requested range.
            let count = (lwe_per_glwe - first_sample).min(range.end - index);
            let glwe = self
                .get_glwe_checked(glwe_idx, first_sample..first_sample + count, meta)?
                .extract();
            for sample in first_sample..first_sample + count {
                result.push(Self::extract_sample(&glwe, meta, MonomialDegree(sample)));
            }
            index += count;
        }
        Ok(result)
    }

    /// Returns the message modulus of the Ciphertexts in the list, or None if the list is empty
    pub fn message_modulus(&self) -> Option<MessageModulus> {
        self.meta.as_ref().map(|meta| meta.message_modulus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn squashed_list() -> CompressedSquashedNoiseCiphertextList {
        let glwe_ciphertext_list = [4, 4, 2]
            .into_iter()
            .enumerate()
            .map(|(glwe_index, count)| {
                // Nonzero, distinct mask and body coefficients exercise sample offsets,
                // negacyclic mask rotations, and modulus-switch decompression.
                let coefficients = (0..16)
                    .map(|i| ((glwe_index * 16 + i + 1) as u128) << 116)
                    .collect::<Vec<_>>();
                let glwe = GlweCiphertext::from_container(
                    coefficients,
                    PolynomialSize(8),
                    CiphertextModulus::new_native(),
                );
                CompressedModulusSwitchedGlweCiphertext::compress(
                    &glwe,
                    CiphertextModulusLog(12),
                    LweCiphertextCount(count),
                )
            })
            .collect();
        CompressedSquashedNoiseCiphertextList {
            glwe_ciphertext_list,
            meta: Some(CompressedSquashedNoiseCiphertextListMeta {
                message_modulus: MessageModulus(4),
                carry_modulus: CarryModulus(4),
                lwe_per_glwe: NonZeroLweCiphertextCount::new(4).unwrap(),
            }),
        }
    }

    #[test]
    fn unpack_range_matches_individual_samples() {
        let list = squashed_list();
        assert_eq!(list.len(), 10);
        // Exhaustively covers singleton, empty, aligned, mid-GLWE, and crossing ranges,
        // including the partially filled last GLWE.
        for start in 0..=list.len() {
            for end in start..=list.len() {
                let expected = (start..end)
                    .map(|index| list.unpack(index).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(list.unpack_range(start..end).unwrap(), expected);
            }
        }
    }

    #[test]
    fn unpack_range_rejects_invalid_ranges() {
        let list = squashed_list();
        for (start, end) in [
            (4, 3),
            (0, 11),
            (11, 11),
            (0, usize::MAX),
            (usize::MAX, usize::MAX),
        ] {
            assert!(list.unpack_range(start..end).is_err());
        }
        assert!(list.unpack(list.len()).is_err());
        assert!(list.unpack(usize::MAX).is_err());
    }

    #[test]
    fn unpack_range_empty_and_inconsistent_lists() {
        let empty = CompressedSquashedNoiseCiphertextList {
            glwe_ciphertext_list: Vec::new(),
            meta: None,
        };
        assert!(empty.unpack_range(0..0).unwrap().is_empty());
        assert!(empty.unpack_range(0..1).is_err());
        assert!(empty.unpack(0).is_err());

        let mut list = squashed_list();
        list.meta = None;
        assert!(list.unpack_range(0..1).is_err());
        assert!(list.unpack_range(0..0).unwrap().is_empty());

        let mut list = squashed_list();
        list.meta.as_mut().unwrap().lwe_per_glwe = NonZeroLweCiphertextCount::new(1).unwrap();
        // The body count admits the range, but the inconsistent metadata maps it past
        // the available GLWEs. Preserve the single-item accessor's error behavior.
        assert!(list.unpack_range(0..4).is_err());
        assert!(list.unpack(3).is_err());
    }

    #[test]
    fn unpack_range_rejects_samples_outside_glwe() {
        // Even though len() admits the indices, the metadata must fit the polynomial.
        let mut list = squashed_list();
        list.meta.as_mut().unwrap().lwe_per_glwe = NonZeroLweCiphertextCount::new(16).unwrap();
        assert!(list.unpack_range(0..10).is_err());
        assert!(list.unpack_range(8..10).is_err());
        assert!(list.unpack(8).is_err());

        // Metadata fits the polynomial, but not the stored bodies of a non-final GLWE.
        list.meta.as_mut().unwrap().lwe_per_glwe = NonZeroLweCiphertextCount::new(8).unwrap();
        assert!(list.unpack_range(0..5).is_err());
        assert!(list.unpack_range(4..5).is_err());
        assert!(list.unpack(4).is_err());

        // A partial GLWE is only allowed at the end, even for an in-bounds sample.
        let mut list = squashed_list();
        list.glwe_ciphertext_list.swap(0, 2);
        assert!(list.unpack_range(0..1).is_err());
        assert!(list.unpack(0).is_err());
    }
}
