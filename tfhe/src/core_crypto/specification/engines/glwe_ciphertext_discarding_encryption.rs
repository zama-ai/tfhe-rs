use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextDiscardingEncryptionError for GlweCiphertextDiscardingEncryptionEngine @
    GlweDimensionMismatch => "The GLWE dimension of the key and ciphertext must be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and ciphertext must be the same.",
    PlaintextCountMismatch => "The size of the input plaintext vector and the output ciphertext \
                               polynomial size must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextDiscardingEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextVector, Ciphertext>(
        key: &SecretKey,
        output: &Ciphertext,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextVector: PlaintextVectorEntity,
        Ciphertext: GlweCiphertextEntity,
    {
        if key.polynomial_size() != output.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if key.polynomial_size().0 != input.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting (discarding) GLWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext with
/// the encryption of the `input` plaintext vector, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::GlweCiphertextEncryptionEngine`)
pub trait GlweCiphertextDiscardingEncryptionEngine<SecretKey, PlaintextVector, Ciphertext>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    Ciphertext: GlweCiphertextEntity,
{
    /// Encrypts a GLWE ciphertext .
    fn discard_encrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<(), GlweCiphertextDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE ciphertext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextDiscardingEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &PlaintextVector,
        noise: Variance,
    );
}
