use super::engine_error;
use crate::core_crypto::prelude::AbstractEngine;

use crate::core_crypto::specification::entities::{LweCiphertextEntity, LweSeededCiphertextEntity};

engine_error! {
    LweSeededCiphertextToLweCiphertextTransformationError for
    LweSeededCiphertextToLweCiphertextTransformationEngine @
}

/// A trait for engines transforming LWE seeded ciphertexts into LWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing LWE seeded ciphertext into a
/// LWE ciphertext.
///
/// # Formal Definition
///
/// ## LWE seeded ciphertext to LWE ciphertext transformation
/// ###### inputs:
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\tilde{\mathsf{ct}} = \left( \mathsf{seed} , b\right) \in \mathsf{SeededLWE}^n\_{\vec{s}, G}(
///   \mathsf{pt})\subseteq \mathcal{S}\times \mathbb{Z}\_q$: a seeded LWE ciphertext
///
/// ###### outputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample $n$ integers in $\mathbb{Z}\_q$ from $G$ with the seed
/// $\mathsf{seed}\in\mathcal{S}$ and store them in $\vec{a}\in\mathbb{Z}^n\_q$
/// 2. output $\left( \vec{a} , b\right)$
pub trait LweSeededCiphertextToLweCiphertextTransformationEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweSeededCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Does the transformation of the LWE seeded ciphertext into an LWE ciphertext
    fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext(
        &mut self,
        lwe_seeded_ciphertext: InputCiphertext,
    ) -> Result<
        OutputCiphertext,
        LweSeededCiphertextToLweCiphertextTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms an LWE seeded ciphertext into an LWE ciphertext
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextToLweCiphertextTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext_unchecked(
        &mut self,
        lwe_seeded_ciphertext: InputCiphertext,
    ) -> OutputCiphertext;
}
