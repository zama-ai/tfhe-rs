use super::engine_error;
use crate::core_crypto::prelude::AbstractEngine;

use crate::core_crypto::specification::entities::{
    LweBootstrapKeyEntity, LweSeededBootstrapKeyEntity,
};

engine_error! {
    LweSeededBootstrapKeyToLweBootstrapKeyTransformationError
    for LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine @
}

/// A trait for engines transforming LWE seeded bootstrap keys into LWE bootstrap keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing LWE seeded bootstrap key
/// into a LWE bootstrap key.
///
/// # Formal Definition
///
/// ## LWE seeded bootstrap key to LWE bootstrap key transformation
///
/// TODO
pub trait LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine<
    InputSeededBootstrapKey,
    OutputBootstrapKey,
>: AbstractEngine where
    InputSeededBootstrapKey: LweSeededBootstrapKeyEntity,
    OutputBootstrapKey: LweBootstrapKeyEntity,
{
    /// Does the transformation of the LWE seeded bootstrap key into an LWE bootstrap key
    fn transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(
        &mut self,
        lwe_seeded_bootstrap_key: InputSeededBootstrapKey,
    ) -> Result<
        OutputBootstrapKey,
        LweSeededBootstrapKeyToLweBootstrapKeyTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms an LWE seeded bootstrap key into an LWE bootstrap key
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededBootstrapKeyToLweBootstrapKeyTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked(
        &mut self,
        lwe_seeded_bootstrap_key: InputSeededBootstrapKey,
    ) -> OutputBootstrapKey;
}
