use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextEntity, LwePublicKeyEntity, PlaintextEntity,
};

engine_error! {
    LweCiphertextDiscardingPublicKeyEncryptionError for LweCiphertextDiscardingPublicKeyEncryptionEngine @
    LweDimensionMismatch => "The public key and ciphertext LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingPublicKeyEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<PublicKey, Ciphertext>(
        key: &PublicKey,
        output: &Ciphertext,
    ) -> Result<(), Self>
    where
        PublicKey: LwePublicKeyEntity,
        Ciphertext: LweCiphertextEntity,
    {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting (discarding) LWE ciphertexts with a public key.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the encryption of the `input` plaintext, using the public `key`. The ciphertext can be decrypted
/// by the secret key used to generate the public key.
///
/// # Formal Definition
pub trait LweCiphertextDiscardingPublicKeyEncryptionEngine<PublicKey, Plaintext, Ciphertext>:
    AbstractEngine
where
    PublicKey: LwePublicKeyEntity,
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity,
{
    /// Encrypts an LWE ciphertext using a public key.
    fn discard_encrypt_lwe_ciphertext_with_public_key(
        &mut self,
        key: &PublicKey,
        output: &mut Ciphertext,
        input: &Plaintext,
    ) -> Result<(), LweCiphertextDiscardingPublicKeyEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an LWE ciphertext using a public key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingPublicKeyEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_encrypt_lwe_ciphertext_with_public_key_unchecked(
        &mut self,
        key: &PublicKey,
        output: &mut Ciphertext,
        input: &Plaintext,
    );
}
