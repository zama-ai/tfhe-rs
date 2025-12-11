//! Module with new-types wrapping basic rust types, giving them a particular meaning, to avoid
//! common mistakes when passing parameters to functions.
//!
//! These types have 0 overhead compared to the type being wrapped.

use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

pub use super::ciphertext_modulus::CiphertextModulus;
use super::traits::CastInto;
use crate::core_crypto::backward_compatibility::commons::parameters::*;

/// The number plaintexts in a plaintext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(PlaintextCountVersions)]
pub struct PlaintextCount(pub usize);

/// The number messages in a messages list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CleartextCountVersions)]
pub struct CleartextCount(pub usize);

/// The number of ciphertexts in a ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CiphertextCountVersions)]
pub struct CiphertextCount(pub usize);

/// The number of ciphertexts in an lwe ciphertext list.
#[derive(
    Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Serialize, Deserialize, Versionize,
)]
#[versionize(LweCiphertextCountVersions)]
pub struct LweCiphertextCount(pub usize);

/// The index of a ciphertext in an lwe ciphertext list.
#[cfg(feature = "gpu")]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(LweCiphertextIndexVersions)]
pub struct LweCiphertextIndex(pub usize);

/// The number of ciphertexts in a glwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(GlweCiphertextCountVersions)]
pub struct GlweCiphertextCount(pub usize);

/// The number of ciphertexts in a gsw ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(GswCiphertextCountVersions)]
pub struct GswCiphertextCount(pub usize);

/// The number of ciphertexts in a ggsw ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(GgswCiphertextCountVersions)]
pub struct GgswCiphertextCount(pub usize);

/// The number of scalars in an LWE ciphertext, i.e. the number of scalar in an LWE mask plus one.
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize, Versionize,
)]
#[versionize(LweSizeVersions)]
pub struct LweSize(pub usize);

impl LweSize {
    /// Return the associated [`LweDimension`].
    pub fn to_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.0.saturating_sub(1))
    }
}

/// The number of scalar in an LWE mask, or the length of an LWE secret key.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize, Versionize,
)]
#[versionize(LweDimensionVersions)]
pub struct LweDimension(pub usize);

impl LweDimension {
    /// Return the associated [`LweSize`].
    pub fn to_lwe_size(&self) -> LweSize {
        LweSize(self.0.saturating_add(1))
    }
}

/// The number of LWE encryptions of 0 in an LWE public ke, Versionize, Versionizey.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(LwePublicKeyZeroEncryptionCountVersions)]
pub struct LwePublicKeyZeroEncryptionCount(pub usize);

/// The number of masks in a collection of LWE masks.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(LweMaskCountVersions)]
pub struct LweMaskCount(pub usize);

/// The number of bodues in a collection of LWE bodies.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(LweBodyCountVersions)]
pub struct LweBodyCount(pub usize);

/// The number of polynomials in a GLWE ciphertext, i.e. the number of polynomials in a GLWE mask
/// plus one.
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize, Versionize,
)]
#[versionize(GlweSizeVersions)]
pub struct GlweSize(pub usize);

impl GlweSize {
    /// Return the associated [`GlweDimension`].
    pub fn to_glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.0 - 1)
    }
}

/// The number of polynomials of a GLWE mask, or the size of a GLWE secret key.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize, Versionize,
)]
#[versionize(GlweDimensionVersions)]
pub struct GlweDimension(pub usize);

impl GlweDimension {
    /// Return the associated [`GlweSize`].
    pub fn to_glwe_size(&self) -> GlweSize {
        GlweSize(self.0 + 1)
    }

    pub const fn to_equivalent_lwe_dimension(self, poly_size: PolynomialSize) -> LweDimension {
        LweDimension(self.0 * poly_size.0)
    }
}

/// The number of coefficients of a polynomial.
///
/// Assuming a polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this new-type contains $N$.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Versionize, Hash,
)]
#[versionize(PolynomialSizeVersions)]
pub struct PolynomialSize(pub usize);

impl PolynomialSize {
    /// Return the associated [`PolynomialSizeLog`].
    /// If the polynomial size is not a power of 2, returns the floor of its log2
    pub const fn log2(&self) -> PolynomialSizeLog {
        PolynomialSizeLog(self.0.ilog2() as usize)
    }

    pub fn to_fourier_polynomial_size(&self) -> FourierPolynomialSize {
        assert_eq!(
            self.0 % 2,
            0,
            "Cannot convert a PolynomialSize that is not a multiple of 2 to FourierPolynomialSize"
        );
        FourierPolynomialSize(self.0 / 2)
    }

    /// Inputs of a blind rotation are monomials which degree may be up to 2 * N because of the
    /// negacyclicity
    /// Converts a polynomial size into the log modulus of the inputs of a blind rotation
    pub const fn to_blind_rotation_input_modulus_log(&self) -> CiphertextModulusLog {
        CiphertextModulusLog(self.log2().0 + 1)
    }
}

/// The number of elements in the container of a fourier polynomial.
///
/// Assuming a standard polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this new-type contains
/// $\frac{N}{2}$.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Versionize,
)]
#[versionize(FourierPolynomialSizeVersions)]
pub struct FourierPolynomialSize(pub usize);

impl FourierPolynomialSize {
    pub fn to_standard_polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.0 * 2)
    }
}

/// The logarithm of the number of coefficients of a polynomial.
///
/// Assuming a polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this returns $\log\_2(N)$.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Versionize,
)]
#[versionize(PolynomialSizeLogVersions)]
pub struct PolynomialSizeLog(pub usize);

impl PolynomialSizeLog {
    /// Return the associated [`PolynomialSizeLog`].
    pub fn to_polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(1 << self.0)
    }
}

/// The number of polynomials in a polynomial list.
///
/// Assuming a polynomial list, this return the number of polynomials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(PolynomialCountVersions)]
pub struct PolynomialCount(pub usize);

/// The degree of a monomial.
///
/// Assuming a monomial $aX^N$, this returns the $N$ value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(MonomialDegreeVersions)]
pub struct MonomialDegree(pub usize);

/// The logarithm of the base used in a decomposition.
///
/// When decomposing an integer over powers of the $2^B$ basis, this type represents the $B$ value.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(DecompositionBaseLogVersions)]
pub struct DecompositionBaseLog(pub usize);

/// The number of levels used in a decomposition.
///
/// When decomposing an integer over the $l$ largest powers of the basis, this type represents
/// the $l$ value.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(DecompositionLevelCountVersions)]
pub struct DecompositionLevelCount(pub usize);

/// The logarithm of the number of LUT evaluated in a PBS.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(LutCountLogVersions)]
pub struct LutCountLog(pub usize);

/// The number of MSB shifted in a Modulus Switch.
///
/// When performing a Modulus Switch, this type represents the number of MSB that will be
/// discarded.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(ModulusSwitchOffsetVersions)]
pub struct ModulusSwitchOffset(pub usize);

/// The base 2 logarithm of the scaling factor (generally written $\Delta$) used to store the
/// message in the MSB of ciphertexts.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(DeltaLogVersions)]
pub struct DeltaLog(pub usize);

/// The number of bits to extract in a bit extraction.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(ExtractedBitsCountVersions)]
pub struct ExtractedBitsCount(pub usize);

/// The number of functional packing keyswitch key in a functional packing keyswitch key list.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(FunctionalPackingKeyswitchKeyCountVersions)]
pub struct FunctionalPackingKeyswitchKeyCount(pub usize);

/// The number of bits used for the mask coefficients and the body of a ciphertext
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(CiphertextModulusLogVersions)]
pub struct CiphertextModulusLog(pub usize);

/// The number of bits that can be represented in a message
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(MessageModulusLogVersions)]
pub struct MessageModulusLog(pub usize);

/// The number of cpu execution thread to use
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(ThreadCountVersions)]
pub struct ThreadCount(pub usize);

/// The number of key bits grouped together in the multi_bit PBS
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash, Serialize, Deserialize, Versionize)]
#[versionize(LweBskGroupingFactorVersions)]
pub struct LweBskGroupingFactor(pub usize);

impl LweBskGroupingFactor {
    pub fn ggsw_per_multi_bit_element(&self) -> GgswPerLweMultiBitBskElement {
        GgswPerLweMultiBitBskElement(1 << self.0)
    }
}

/// The number of GGSW ciphertexts required per multi_bit BSK element
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(GgswPerLweMultiBitBskElementVersions)]
pub struct GgswPerLweMultiBitBskElement(pub usize);

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(EncryptionKeyChoiceVersions)]
pub enum EncryptionKeyChoice {
    Big,
    Small,
}

impl EncryptionKeyChoice {
    pub const fn into_pbs_order(self) -> PBSOrder {
        match self {
            Self::Big => PBSOrder::KeyswitchBootstrap,
            Self::Small => PBSOrder::BootstrapKeyswitch,
        }
    }
}

impl From<EncryptionKeyChoice> for PBSOrder {
    fn from(value: EncryptionKeyChoice) -> Self {
        value.into_pbs_order()
    }
}

impl From<PBSOrder> for EncryptionKeyChoice {
    fn from(value: PBSOrder) -> Self {
        match value {
            PBSOrder::KeyswitchBootstrap => Self::Big,
            PBSOrder::BootstrapKeyswitch => Self::Small,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Versionize)]
#[versionize(PBSOrderVersions)]
pub enum PBSOrder {
    /// Ciphertext is encrypted using the big LWE secret key corresponding to the GLWE secret key.
    ///
    /// A keyswitch is first performed to bring it to the small LWE secret key realm, then the PBS
    /// is computed bringing it back to the large LWE secret key.
    KeyswitchBootstrap = 0,
    /// Ciphertext is encrypted using the small LWE secret key.
    ///
    /// The PBS is computed first and a keyswitch is applied to get back to the small LWE secret
    /// key realm.
    BootstrapKeyswitch = 1,
}

pub use crate::core_crypto::commons::math::random::DynamicDistribution;

/// A quantity representing a number of scalar used for mask samples generation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EncryptionMaskSampleCount(pub usize);

impl EncryptionMaskSampleCount {
    pub(crate) fn to_mask_byte_count(
        self,
        mask_byte_per_scalar: EncryptionMaskByteCount,
    ) -> EncryptionMaskByteCount {
        EncryptionMaskByteCount(self.0 * mask_byte_per_scalar.0)
    }
}

impl std::ops::Mul<usize> for EncryptionMaskSampleCount {
    type Output = Self;

    fn mul(self, rhs: usize) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl std::ops::Mul<EncryptionMaskSampleCount> for usize {
    type Output = EncryptionMaskSampleCount;

    fn mul(self, rhs: EncryptionMaskSampleCount) -> Self::Output {
        EncryptionMaskSampleCount(self * rhs.0)
    }
}

/// A quantity representing a number of bytes used for mask generation during encryption.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EncryptionMaskByteCount(pub usize);

/// A quantity representing a number of scalar used for noise samples generation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EncryptionNoiseSampleCount(pub usize);

impl EncryptionNoiseSampleCount {
    pub(crate) fn to_noise_byte_count(
        self,
        noise_byte_per_scalar: EncryptionNoiseByteCount,
    ) -> EncryptionNoiseByteCount {
        EncryptionNoiseByteCount(self.0 * noise_byte_per_scalar.0)
    }
}

impl std::ops::Mul<usize> for EncryptionNoiseSampleCount {
    type Output = Self;

    fn mul(self, rhs: usize) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl std::ops::Mul<EncryptionNoiseSampleCount> for usize {
    type Output = EncryptionNoiseSampleCount;

    fn mul(self, rhs: EncryptionNoiseSampleCount) -> Self::Output {
        EncryptionNoiseSampleCount(self * rhs.0)
    }
}

/// A quantity representing a number of bytes used for noise generation during encryption.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EncryptionNoiseByteCount(pub usize);

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(RSigmaFactorVersions)]
pub struct RSigmaFactor(pub f64);

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseEstimationMeasureBoundVersions)]
pub struct NoiseEstimationMeasureBound(pub f64);

/// The size of a chunk in a chunked key.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ChunkSizeVersions)]
pub struct ChunkSize(pub usize);

/// The max normalized hamming weight
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NormalizedHammingWeightBoundVersions)]
pub struct NormalizedHammingWeightBound(f64);

impl NormalizedHammingWeightBound {
    /// Creates `self`, returns None if pmax not in ]0.5, 1.0]
    pub fn new(pmax: f64) -> Option<Self> {
        if 0.5 < pmax && pmax <= 1.0 {
            Some(Self(pmax))
        } else {
            None
        }
    }

    /// Returns the inner value
    pub fn get(self) -> f64 {
        self.0
    }

    /// Given the number of bits `num_bits`, returns the range
    /// of acceptable hamming weights for a slice of `num_bits` bits
    pub fn range(self, num_bits: usize) -> RangeInclusive<u128> {
        RangeInclusive::new(
            ((1.0 - self.0) * num_bits as f64) as u128,
            (self.0 * num_bits as f64) as u128,
        )
    }

    /// Checks that the binary_slice's hamming weight is ok with regards to `self`
    ///
    /// * Returns Ok(()) if the hamming weight is ok, otherwise Err(())
    ///
    /// # Note
    ///
    /// The slice elements must be binary, that is they must be 0 or 1,
    /// otherwise the result will be incorrect
    #[allow(clippy::result_unit_err)]
    pub fn check_binary_slice<T>(self, binary_slice: &[T]) -> Result<(), ()>
    where
        T: Copy + CastInto<u128>,
    {
        let hamming_weight = binary_slice
            .iter()
            .copied()
            .map(|bit| -> u128 { bit.cast_into() })
            .sum::<u128>();

        let bounds = self.range(binary_slice.len());

        if bounds.contains(&hamming_weight) {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bad_lwe_size() {
        // Check that it does not underflow
        let lwe_size = LweSize(0);

        let lwe_dim = lwe_size.to_lwe_dimension();
        assert_eq!(lwe_dim.0, 0);
    }

    #[test]
    fn test_bad_lwe_dimension() {
        // Check that it does not overflow
        let lwe_dim = LweDimension(usize::MAX);

        let lwe_size = lwe_dim.to_lwe_size();
        assert_eq!(lwe_size.0, usize::MAX);
    }
}
