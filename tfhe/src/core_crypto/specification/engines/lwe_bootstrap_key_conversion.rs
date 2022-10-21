use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;

engine_error! {
    LweBootstrapKeyConversionError for LweBootstrapKeyConversionEngine @
}

/// A trait for engines converting LWE bootstrap keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a LWE bootstrap key containing the
/// conversion of the `input` bootstrap key to a type with a different representation (for instance
/// from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweBootstrapKeyConversionEngine<InputKey, OutputKey>: AbstractEngine
where
    InputKey: LweBootstrapKeyEntity,
    OutputKey: LweBootstrapKeyEntity,
{
    /// Converts an LWE bootstrap key.
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &InputKey,
    ) -> Result<OutputKey, LweBootstrapKeyConversionError<Self::EngineError>>;

    /// Unsafely converts an LWE bootstrap key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_lwe_bootstrap_key_unchecked(&mut self, input: &InputKey) -> OutputKey;
}
