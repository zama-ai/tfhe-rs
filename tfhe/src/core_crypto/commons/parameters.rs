//! Module with new-types wrapping basic rust types, giving them a particular meaning, to avoid
//! common mistakes when passing parameters to functions.
//!
//! These types have 0 overhead compared to the type being wrapped.

use serde::{Deserialize, Serialize};

pub use super::ciphertext_modulus::CiphertextModulus;

/// The number plaintexts in a plaintext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct PlaintextCount(pub usize);

/// The number encoder in an encoder list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncoderCount(pub usize);

/// The number messages in a messages list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct CleartextCount(pub usize);

/// The number of ciphertexts in a ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct CiphertextCount(pub usize);

/// The number of ciphertexts in an lwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct LweCiphertextCount(pub usize);

/// The index of a ciphertext in an lwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct LweCiphertextIndex(pub usize);

/// The range of indices of multiple contiguous ciphertexts in an lwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct LweCiphertextRange(pub usize, pub usize);

impl LweCiphertextRange {
    pub fn is_ordered(&self) -> bool {
        self.1 <= self.0
    }
}

/// The number of ciphertexts in a glwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct GlweCiphertextCount(pub usize);

/// The number of ciphertexts in a gsw ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct GswCiphertextCount(pub usize);

/// The number of ciphertexts in a ggsw ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct GgswCiphertextCount(pub usize);

/// The number of scalars in an LWE ciphertext, i.e. the number of scalar in an LWE mask plus one.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize)]
pub struct LweSize(pub usize);

impl LweSize {
    /// Return the associated [`LweDimension`].
    pub fn to_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.0 - 1)
    }
}

/// The number of scalar in an LWE mask, or the length of an LWE secret key.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct LweDimension(pub usize);

impl LweDimension {
    /// Return the associated [`LweSize`].
    pub fn to_lwe_size(&self) -> LweSize {
        LweSize(self.0 + 1)
    }
}

/// The number of LWE encryptions of 0 in an LWE public key.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct LwePublicKeyZeroEncryptionCount(pub usize);

/// The number of masks in a collection of LWE masks.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct LweMaskCount(pub usize);

/// The number of bodues in a collection of LWE bodies.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct LweBodyCount(pub usize);

/// The number of polynomials in a GLWE ciphertext, i.e. the number of polynomials in a GLWE mask
/// plus one.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize)]
pub struct GlweSize(pub usize);

impl GlweSize {
    /// Return the associated [`GlweDimension`].
    pub fn to_glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.0 - 1)
    }
}

/// The number of polynomials of a GLWE mask, or the size of a GLWE secret key.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct GlweDimension(pub usize);

impl GlweDimension {
    /// Return the associated [`GlweSize`].
    pub fn to_glwe_size(&self) -> GlweSize {
        GlweSize(self.0 + 1)
    }
}

/// The number of coefficients of a polynomial.
///
/// Assuming a polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this new-type contains $N$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolynomialSize(pub usize);

impl PolynomialSize {
    /// Return the associated [`PolynomialSizeLog`].
    pub fn log2(&self) -> PolynomialSizeLog {
        PolynomialSizeLog((self.0 as f64).log2().ceil() as usize)
    }

    pub fn to_fourier_polynomial_size(&self) -> FourierPolynomialSize {
        assert_eq!(
            self.0 % 2,
            0,
            "Cannot convert a PolynomialSize that is not a multiple of 2 to FourierPolynomialSize"
        );
        FourierPolynomialSize(self.0 / 2)
    }
}

/// The number of elements in the container of a fourier polynomial.
///
/// Assuming a standard polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this new-type contains
/// $\frac{N}{2}$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FourierPolynomialSize(pub usize);

impl FourierPolynomialSize {
    pub fn to_standard_polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.0 * 2)
    }
}

/// The logarithm of the number of coefficients of a polynomial.
///
/// Assuming a polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this returns $\log\_2(N)$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolynomialCount(pub usize);

/// The degree of a monomial.
///
/// Assuming a monomial $aX^N$, this returns the $N$ value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonomialDegree(pub usize);

/// The index of a monomial in a polynomial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonomialIndex(pub usize);

/// The logarithm of the base used in a decomposition.
///
/// When decomposing an integer over powers of the $2^B$ basis, this type represents the $B$ value.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct DecompositionBaseLog(pub usize);

/// The number of levels used in a decomposition.
///
/// When decomposing an integer over the $l$ largest powers of the basis, this type represents
/// the $l$ value.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct DecompositionLevelCount(pub usize);

/// The logarithm of the number of LUT evaluated in a PBS.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct LutCountLog(pub usize);

/// The number of MSB shifted in a Modulus Switch.
///
/// When performing a Modulus Switch, this type represents the number of MSB that will be
/// discarded.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct ModulusSwitchOffset(pub usize);

/// The base 2 logarithm of the scaling factor (generally written $\Delta$) used to store the
/// message in the MSB of ciphertexts.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct DeltaLog(pub usize);

/// The number of bits to extract in a bit extraction.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct ExtractedBitsCount(pub usize);

/// The number of functional packing keyswitch key in a functional packing keyswitch key list.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct FunctionalPackingKeyswitchKeyCount(pub usize);

/// The number of bits used for the mask coefficients and the body of a ciphertext
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct CiphertextModulusLog(pub usize);

/// The number of cpu execution thread to use
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct ThreadCount(pub usize);

/// The number of key bits grouped together in the multi_bit PBS
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct LweBskGroupingFactor(pub usize);

impl LweBskGroupingFactor {
    pub fn ggsw_per_multi_bit_element(&self) -> GgswPerLweMultiBitBskElement {
        GgswPerLweMultiBitBskElement(1 << self.0)
    }
}

/// The number of GGSW ciphertexts required per multi_bit BSK element
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct GgswPerLweMultiBitBskElement(pub usize);

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum EncryptionKeyChoice {
    Big,
    Small,
}

impl From<EncryptionKeyChoice> for PBSOrder {
    fn from(value: EncryptionKeyChoice) -> Self {
        match value {
            EncryptionKeyChoice::Big => Self::KeyswitchBootstrap,
            EncryptionKeyChoice::Small => Self::BootstrapKeyswitch,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
