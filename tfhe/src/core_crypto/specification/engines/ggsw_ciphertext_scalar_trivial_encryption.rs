use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};

use crate::core_crypto::specification::engines::{engine_error, AbstractEngine};
use crate::core_crypto::specification::entities::{GgswCiphertextEntity, PlaintextEntity};

engine_error! {
    GgswCiphertextScalarTrivialEncryptionError for GgswCiphertextScalarTrivialEncryptionEngine @
}

/// A trait for engines trivially encrypting GGSW ciphertext containing a single plaintext.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GGSW ciphertext containing the
/// trivial encryption of the `input` plaintext with the requested `glwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait GgswCiphertextScalarTrivialEncryptionEngine<Plaintext, Ciphertext>:
    AbstractEngine
where
    Plaintext: PlaintextEntity,
    Ciphertext: GgswCiphertextEntity,
{
    /// Trivially encrypts a plaintext vector into a GGSW ciphertext.
    fn trivially_encrypt_scalar_ggsw_ciphertext(
        &mut self,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        input: &Plaintext,
    ) -> Result<Ciphertext, GgswCiphertextScalarTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely creates the trivial GGSW encryption of the plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GgswCiphertextScalarTrivialEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        input: &Plaintext,
    ) -> Ciphertext;
}
