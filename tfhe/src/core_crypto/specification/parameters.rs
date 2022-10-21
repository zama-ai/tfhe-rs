#![allow(deprecated)]
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// The number plaintexts in a plaintext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct PlaintextCount(pub usize);

/// The number encoder in an encoder list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct EncoderCount(pub usize);

/// The number messages in a messages list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct CleartextCount(pub usize);

/// The number of ciphertexts in a ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct CiphertextCount(pub usize);

/// The number of ciphertexts in an lwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct LweCiphertextCount(pub usize);

/// The index of a ciphertext in an lwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct LweCiphertextIndex(pub usize);

/// The range of indices of multiple contiguous ciphertexts in an lwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct LweCiphertextRange(pub usize, pub usize);

impl LweCiphertextRange {
    pub fn is_ordered(&self) -> bool {
        self.1 <= self.0
    }
}

/// The number of ciphertexts in a glwe ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct GlweCiphertextCount(pub usize);

/// The number of ciphertexts in a gsw ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct GswCiphertextCount(pub usize);

/// The number of ciphertexts in a ggsw ciphertext list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct GgswCiphertextCount(pub usize);

/// The number of scalars in an LWE ciphertext, i.e. the number of scalar in an LWE mask plus one.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct LweSize(pub usize);

impl LweSize {
    /// Returns the associated [`LweDimension`].
    pub fn to_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.0 - 1)
    }
}

/// The number of scalar in an LWE mask, or the length of an LWE secret key.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct LweDimension(pub usize);

impl LweDimension {
    /// Returns the associated [`LweSize`].
    pub fn to_lwe_size(&self) -> LweSize {
        LweSize(self.0 + 1)
    }
}

/// The number of LWE encryptions of 0 in an LWE public key.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct LwePublicKeyZeroEncryptionCount(pub usize);

/// The number of polynomials in a GLWE ciphertext, i.e. the number of polynomials in a GLWE mask
/// plus one.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct GlweSize(pub usize);

impl GlweSize {
    /// Returns the associated [`GlweDimension`].
    pub fn to_glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.0 - 1)
    }
}

/// The number of polynomials of an GLWE mask, or the size of an GLWE secret key.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct GlweDimension(pub usize);

impl GlweDimension {
    /// Returns the associated [`GlweSize`].
    pub fn to_glwe_size(&self) -> GlweSize {
        GlweSize(self.0 + 1)
    }
}

/// The number of coefficients of a polynomial.
///
/// Assuming a polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this returns $N$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct PolynomialSize(pub usize);

impl PolynomialSize {
    /// Returns the associated [`PolynomialSizeLog`].
    pub fn log2(&self) -> PolynomialSizeLog {
        PolynomialSizeLog((self.0 as f64).log2().ceil() as usize)
    }
}

/// The logarithm of the number of coefficients of a polynomial.
///
/// Assuming a polynomial $a\_0 + a\_1X + /dots + a\_{N-1}X^{N-1}$, this returns $\log\_2(N)$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct PolynomialSizeLog(pub usize);

impl PolynomialSizeLog {
    /// Returns the associated [`PolynomialSizeLog`].
    pub fn to_polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(1 << self.0)
    }
}

/// The number of polynomials in a polynomial list.
///
/// Assuming a polynomial list, this return the number of polynomials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct PolynomialCount(pub usize);

/// The degree of a monomial.
///
/// Assuming a monomial $aX^N$, this returns the $N$ value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[deprecated(note = "MonomialDegree is not used anymore in the API. You should not use it.")]
pub struct MonomialDegree(pub usize);

/// The index of a monomial in a polynomial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct MonomialIndex(pub usize);

/// The logarithm of the base used in a decomposition.
///
/// When decomposing an integer over powers of the $2^B$ basis, this type represents the $B$ value.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct DecompositionBaseLog(pub usize);

/// The number of levels used in a decomposition.
///
/// When decomposing an integer over the $l$ largest powers of the basis, this type represents
/// the $l$ value.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct DecompositionLevelCount(pub usize);

/// The logarithm of the number of LUT evaluated in a PBS.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct LutCountLog(pub usize);

/// The number of MSB shifted in a Modulus Switch.
///
/// When performing a Modulus Switch, this type represents the number of MSB that will be
/// discarded.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct ModulusSwitchOffset(pub usize);

/// The base 2 logarithm of the scaling factor (generally written $\Delta$) used to store the
/// message in the MSB of ciphertexts.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct DeltaLog(pub usize);

/// The number of bits to extract in a bit extraction.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct ExtractedBitsCount(pub usize);

/// The number of functional packing keyswitch key in a functional packing keyswitch key list.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct FunctionalPackingKeyswitchKeyCount(pub usize);

/// The number of bits used for the mask coefficients and the body of a ciphertext
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
pub struct CiphertextModulusLog(pub usize);
