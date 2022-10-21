use super::engine_error;
use crate::core_crypto::prelude::AbstractEngine;

use crate::core_crypto::specification::entities::{
    GlweCiphertextVectorEntity, GlweSeededCiphertextVectorEntity,
};

engine_error! {
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError
    for GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine @
}

/// A trait for engines transforming GLWE seeded ciphertexts vectors into GLWE ciphertexts vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing GLWE seeded ciphertext
/// vector into a GLWE ciphertext vector.
///
/// # Formal Definition
///
/// ## GLWE seeded ciphertext vector to GLWE ciphertext vector transformation
/// ###### inputs:
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\vec{\tilde{\mathsf{CT}}} = \left( \mathsf{seed} , \vec{\tilde{B}} \right) \in
///   \mathsf{SeededGLWEVector}^{k,t}\_{\vec{S}, G}( \vec{\mathsf{PT}} )\subseteq \mathcal{S}\times
///   \mathcal{R}\_q^t$: a seeded GLWE ciphertext vector
///
/// ###### outputs:
/// - $\vec{\mathsf{CT}} = \vec{\left( \vec{A} , B \right)} \in \mathsf{GLWEVector}^{k,t}\_{\vec{S}}
///   (\vec{\mathsf{PT}} )\subseteq {\mathcal{R}\_q^{k+1}}^t$: a GLWE ciphertext vector
///
/// ###### algorithm:
/// 1. let $\vec{\mathsf{CT}} = \vec{\left( \vec{A} , B \right)} \in
/// \mathsf{GLWEVector}^{k,t}\_{\vec{S}} (\vec{\mathsf{PT}} )\subseteq {\mathcal{R}\_q^{k+1}}^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(\left( \vec{A\_i}, B\_i\right) , \tilde{B\_i})$ in $(\vec{\left( \vec{A} ,
/// B\right)}, \vec{\tilde{B}})$
///     - uniformly sample each coefficient of the polynomial vector $\vec{A\_i}\in\mathcal{R}^k\_q$
///       from $G$
///     - set $B\_i = \tilde{B\_i}$
/// 4. output $\vec{\left( \vec{A} , B\right)}$
pub trait GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine<
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    InputCiphertextVector: GlweSeededCiphertextVectorEntity,
    OutputCiphertextVector: GlweCiphertextVectorEntity,
{
    /// Does the transformation of the GLWE seeded ciphertext vector into a GLWE ciphertext vector
    fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
        &mut self,
        glwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> Result<
        OutputCiphertextVector,
        GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms a GLWE seeded ciphertext vector into a GLWE ciphertext vector
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector_unchecked(
        &mut self,
        glwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> OutputCiphertextVector;
}
