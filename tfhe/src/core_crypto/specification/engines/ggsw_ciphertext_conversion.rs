use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::GgswCiphertextEntity;

engine_error! {
    GgswCiphertextConversionError for GgswCiphertextConversionEngine @
}

/// A trait for engines converting GGSW ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GGSW ciphertext containing the
/// conversion of the `input` GGSW ciphertext to a type with a different representation (for
/// instance from standard to Fourier domain).
///
/// # Formal Definition
pub trait GgswCiphertextConversionEngine<Input, Output>: AbstractEngine
where
    Input: GgswCiphertextEntity,
    Output: GgswCiphertextEntity,
{
    /// Converts a GGSW ciphertext.
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &Input,
    ) -> Result<Output, GgswCiphertextConversionError<Self::EngineError>>;

    /// Unsafely converts a GGSW ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GgswCiphertextConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_ggsw_ciphertext_unchecked(&mut self, input: &Input) -> Output;
}
