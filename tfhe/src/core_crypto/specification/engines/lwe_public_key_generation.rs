use crate::core_crypto::prelude::{LwePublicKeyZeroEncryptionCount, Variance};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LwePublicKeyEntity, LweSecretKeyEntity};

engine_error! {
    LwePublicKeyGenerationError for LwePublicKeyGenerationEngine @
    NullPublicKeyZeroEncryptionCount => "The number of LWE encryptions of zero in the LWE public \
                                        key must be greater than zero."
}

impl<EngineError: std::error::Error> LwePublicKeyGenerationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<(), Self> {
        if lwe_public_key_zero_encryption_count.0 == 0 {
            return Err(Self::NullPublicKeyZeroEncryptionCount);
        }
        Ok(())
    }
}

/// A trait for engines generating new LWE public keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a new LWE public key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::LwePublicKeyEntity`)
pub trait LwePublicKeyGenerationEngine<SecretKey, PublicKey>: AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PublicKey: LwePublicKeyEntity,
{
    /// Generates a new LWE public key.
    fn generate_new_lwe_public_key(
        &mut self,
        lwe_secret_key: &SecretKey,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<PublicKey, LwePublicKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates a new LWE public key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LwePublicKeyGenerationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn generate_new_lwe_public_key_unchecked(
        &mut self,
        lwe_secret_key: &SecretKey,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> PublicKey;
}
