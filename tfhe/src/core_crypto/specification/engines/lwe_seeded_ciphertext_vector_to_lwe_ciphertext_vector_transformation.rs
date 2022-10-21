use super::engine_error;
use crate::core_crypto::prelude::AbstractEngine;

use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, LweSeededCiphertextVectorEntity,
};

engine_error! {
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationError
    for LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine @
}

/// A trait for engines transforming LWE seeded ciphertext vectors into LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing LWE seeded ciphertext vector
/// into an LWE ciphertext vector.
///
/// # Formal Definition
///
/// ## LWE seeded ciphertext vector to LWE ciphertext vector transformation
/// ###### inputs:
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\vec{\tilde{\mathsf{ct}}} = \left( \mathsf{seed} , \vec{\tilde{b}}\right) \in
///   \mathsf{SeededLWEVector}^{n, t}\_{\vec{s}, G}( \vec{\mathsf{pt}})\subseteq \mathcal{S}\times
///   \mathbb{Z}\_q^t$: a seeded LWE ciphertext vector
///
/// ###### outputs:
/// - $\vec{\mathsf{ct}} = \vec{\left( \vec{a} , b\right)} \in \mathsf{LWEVector}^{n,t}\_{\vec{s}}(
///   \mathsf{pt} )\subseteq {\mathbb{Z}\_q^{(n+1)}}^t$: an LWE ciphertext vector
///
/// ###### algorithm:
/// 1. let $\vec{\mathsf{ct}} = \vec{\left( \vec{a} , b\right)} \in
/// \mathsf{LWEVector}^{n,t}\_{\vec{s}}(   \mathsf{pt} )\subseteq {\mathbb{Z}\_q^{(n+1)}}^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(\left(\vec{a\_i}, b\_i\right), \tilde{b\_i})$ in $(\vec{\left( \vec{a} ,
/// b\right)}, \vec{\tilde{b}})$
///     - uniformly sample $n$ integers in $\mathbb{Z}\_q$ from $G$ and store them in
///       $\vec{a}\_i\in\mathbb{Z}^n\_q$
///     - set $b\_i = \tilde{b\_i}$
/// 4. output $\vec{\left( \vec{a} , b\right)}$
pub trait LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine<
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    InputCiphertextVector: LweSeededCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Does the transformation of the LWE seeded ciphertext vector into an LWE ciphertext vector
    fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
        &mut self,
        lwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> Result<
        OutputCiphertextVector,
        LweSeededCiphertextVectorToLweCiphertextVectorTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms an LWE seeded ciphertext vector into an LWE ciphertext vector
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextVectorToLweCiphertextVectorTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_unchecked(
        &mut self,
        lwe_seeded_ciphertext_vector: InputCiphertextVector,
    ) -> OutputCiphertextVector;
}
