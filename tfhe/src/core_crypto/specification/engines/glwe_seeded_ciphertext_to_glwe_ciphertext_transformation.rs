use super::engine_error;
use crate::core_crypto::prelude::AbstractEngine;

use crate::core_crypto::specification::entities::{
    GlweCiphertextEntity, GlweSeededCiphertextEntity,
};

engine_error! {
    GlweSeededCiphertextToGlweCiphertextTransformationError for GlweSeededCiphertextToGlweCiphertextTransformationEngine @
}

/// A trait for engines transforming GLWE seeded ciphertexts into GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing GLWE seeded ciphertext into
/// a GLWE ciphertext.
///
/// # Formal Definition
///
/// ## GLWE seeded ciphertext to GLWE ciphertext transformation
/// ###### inputs:
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\tilde{\mathsf{CT}} = \left( \mathsf{seed} , B \right) \in \mathsf{SeededGLWE}^k\_{\vec{S},
///   G}( \mathsf{PT} )\subseteq \mathcal{S}\times \mathcal{R}\_q^{k+1}$: a seeded GLWE ciphertext
///
/// ###### outputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT} )\subseteq
///   \mathcal{R}\_q^{k+1}$: a GLWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample each coefficient of the polynomial vector $\vec{A}\in\mathcal{R}^k\_q$ from
/// $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 2. output $\left( \vec{A} , B \right)$
pub trait GlweSeededCiphertextToGlweCiphertextTransformationEngine<
    InputCiphertext,
    OutputCiphertext,
>: AbstractEngine where
    InputCiphertext: GlweSeededCiphertextEntity,
    OutputCiphertext: GlweCiphertextEntity,
{
    /// Does the transformation of the GLWE seeded ciphertext into an GLWE ciphertext
    fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext(
        &mut self,
        glwe_seeded_ciphertext: InputCiphertext,
    ) -> Result<
        OutputCiphertext,
        GlweSeededCiphertextToGlweCiphertextTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms a GLWE seeded ciphertext into a GLWE ciphertext
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextToGlweCiphertextTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext_unchecked(
        &mut self,
        glwe_seeded_ciphertext: InputCiphertext,
    ) -> OutputCiphertext;
}
