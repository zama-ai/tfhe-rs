use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{CleartextEntity, LweCiphertextEntity};

engine_error! {
    LweCiphertextCleartextDiscardingMultiplicationError for LweCiphertextCleartextDiscardingMultiplicationEngine @
    LweDimensionMismatch => "The input and output ciphertext LWE dimension must be the same."
}

impl<EngineError: std::error::Error>
    LweCiphertextCleartextDiscardingMultiplicationError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input_1: &InputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity,
    {
        if output.lwe_dimension() != input_1.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines multiplying (discarding) LWE ciphertext by cleartexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the multiplication of the `input_1` LWE ciphertext with the `input_2` cleartext.
///
/// # Formal Definition
///
/// ## LWE product with plaintext
///
/// It is a specification of the GLWE product with a plaintext described below.
///
/// ## GLWE product with plaintext
/// [`GLWE ciphertexts`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`)
/// are homomorphic with respect to the addition.
/// By generalization of this property, they are also homomorphic with respect to the product with a
/// plaintext.
///
/// Let s GLWE ciphertexts
/// $$
/// \mathsf{CT} = \left( \vec{A}, B\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT} \right)
/// \subseteq \mathcal{R}\_q^{k+1} $$
/// encrypted under the [`GLWE secret
/// key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`) $\vec{S} \in
/// \mathcal{R}\_q^k$. Let a clear plaintext
/// $$
/// \mathsf{PT}' \in \mathcal{R}.
/// $$
///
/// We can multiply them homomorhically and obtain as a result a new GLWE ciphertext encrypting the
/// product of the two plaintexts $\mathsf{PT}' \cdot \mathsf{PT}$.
///
/// ###### inputs:
/// - $\mathsf{CT} = \left( \vec{A}, B\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT}
///   \right) \subseteq \mathcal{R}\_q^{k+1}$: a GLWE ciphertext
/// - $\mathsf{PT}' \in \mathcal{R}$: a plaintext
///
/// ###### outputs:
/// - $\mathsf{CT}' = \left( \vec{A}' , B' \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT}' \cdot
///   \mathsf{PT} )\subseteq \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
///
/// ###### algorithm:
/// 1. Compute $\vec{A}' = \mathsf{PT}' \cdot \vec{A} \in\mathcal{R}^k\_q$
/// 2. Compute $B' = \mathsf{PT}' \cdot B \in\mathcal{R}\_q$
/// 3. Output $\left( \vec{A}' , B' \right)$
pub trait LweCiphertextCleartextDiscardingMultiplicationEngine<
    InputCiphertext,
    Cleartext,
    OutputCiphertext,
>: AbstractEngine where
    Cleartext: CleartextEntity,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Multiply an LWE ciphertext with a cleartext.
    fn discard_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Cleartext,
    ) -> Result<(), LweCiphertextCleartextDiscardingMultiplicationError<Self::EngineError>>;

    /// Unsafely multiply an LWE ciphertext with a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextCleartextDiscardingMultiplicationError`]. For safety concerns _specific_
    /// to an engine, refer to the implementer safety section.
    unsafe fn discard_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Cleartext,
    );
}
