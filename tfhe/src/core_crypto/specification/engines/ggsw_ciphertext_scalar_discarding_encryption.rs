use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GgswCiphertextEntity, GlweSecretKeyEntity, PlaintextEntity,
};

engine_error! {
    GgswCiphertextScalarDiscardingEncryptionError for GgswCiphertextScalarDiscardingEncryptionEngine @
    GlweDimensionMismatch => "The GLWE dimension of the key and ciphertext must be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and ciphertext must be the same."
}

impl<EngineError: std::error::Error> GgswCiphertextScalarDiscardingEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, Ciphertext>(
        key: &SecretKey,
        output: &Ciphertext,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        Ciphertext: GgswCiphertextEntity,
    {
        if key.polynomial_size() != output.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting (discarding) GGSW ciphertexts containing a single plaintext.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GGSW ciphertext with
/// the encryption of the `input` plaintext, under the `key` secret key.
///
/// # Formal Definition
pub trait GgswCiphertextScalarDiscardingEncryptionEngine<SecretKey, Plaintext, Ciphertext>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    Plaintext: PlaintextEntity,
    Ciphertext: GgswCiphertextEntity,
{
    /// Encrypts a GGSW ciphertext.
    fn discard_encrypt_scalar_ggsw_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &Plaintext,
        noise: Variance,
    ) -> Result<(), GgswCiphertextScalarDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GGSW ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GgswCiphertextScalarDiscardingEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &Plaintext,
        noise: Variance,
    );
}
