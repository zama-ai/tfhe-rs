use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

engine_error! {
    LweSecretKeyConversionError for LweSecretKeyConversionEngine @
}

/// A trait for engines converting LWE secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a LWE secret key containing the
/// conversion of the `input` LWE secret key to a type with a different representation (for instance
/// from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweSecretKeyConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweSecretKeyEntity,
    Output: LweSecretKeyEntity,
{
    /// Converts a LWE secret key.
    fn convert_lwe_secret_key(
        &mut self,
        input: &Input,
    ) -> Result<Output, LweSecretKeyConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE secret key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSecretKeyConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_lwe_secret_key_unchecked(&mut self, input: &Input) -> Output;
}
