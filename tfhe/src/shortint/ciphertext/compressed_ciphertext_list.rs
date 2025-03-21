use tfhe_versionable::Versionize;

use self::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::*;
use crate::shortint::backward_compatibility::ciphertext::{
    CompressedCiphertextListVersions, CompressedSquashedNoiseCiphertextListVersions,
};
use crate::shortint::parameters::CompressedCiphertextConformanceParams;
use crate::shortint::{CarryModulus, MessageModulus};

use super::SquashedNoiseCiphertext;

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

impl CompressedCiphertextList {
    /// Returns how many u64 are needed to store the packed elements
    #[cfg(all(test, feature = "gpu"))]
    pub(crate) fn flat_len(&self) -> usize {
        self.modulus_switched_glwe_ciphertext_list
            .iter()
            .map(|glwe| glwe.packed_integers.packed_coeffs.len())
            .sum()
    }
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

/// A compressed list of [`SquashedNoiseCiphertext`].
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseCiphertextListVersions)]
pub struct CompressedSquashedNoiseCiphertextList {
    pub glwe_ciphertext_list: GlweCiphertextListOwned<u128>,
    pub message_modulus: MessageModulus,
    pub lwe_per_glwe: LweCiphertextCount,
    pub count: CiphertextCount,
}

impl CompressedSquashedNoiseCiphertextList {
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
        if index >= self.count.0 {
            return Err(crate::Error::new(format!(
                "Tried getting index {index} for CompressedNoiseSquashedCiphertextList \
                with {} elements, out of bound access.",
                self.count.0
            )));
        }

        let lwe_per_glwe = self.lwe_per_glwe.0;
        let glwe_idx = index / lwe_per_glwe;

        let glwe_dimension = self.glwe_ciphertext_list.glwe_size().to_glwe_dimension();
        let polynomial_size = self.glwe_ciphertext_list.polynomial_size();
        let ciphertext_modulus = self.glwe_ciphertext_list.ciphertext_modulus();

        let lwe_size = glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size();

        let glwe = self.glwe_ciphertext_list.get(glwe_idx);

        let monomial_degree = MonomialDegree(index % lwe_per_glwe);

        let mut extracted_lwe =
            SquashedNoiseCiphertext::new_zero(lwe_size, ciphertext_modulus, self.message_modulus);

        extract_lwe_sample_from_glwe_ciphertext(
            &glwe,
            extracted_lwe.lwe_ciphertext_mut(),
            monomial_degree,
        );

        Ok(extracted_lwe)
    }
}
