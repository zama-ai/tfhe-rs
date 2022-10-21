use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextDiscardingAdditionError for LweCiphertextDiscardingAdditionEngine @
    LweDimensionMismatch => "All the ciphertext LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingAdditionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity,
    {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines adding (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the addition of the `input_1` LWE ciphertext and the `input_2` LWE ciphertext.
///
/// # Formal Definition
///
/// ## LWE homomorphic addition
///
/// It is a specification of the GLWE homomorphic addition described below.
///
/// ## GLWE homomorphic addition
/// [`GLWE ciphertexts`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`)
/// are homomorphic with
/// respect to the addition.
/// Let two GLWE ciphertexts
/// $$
/// \begin{cases}
/// \mathsf{CT}\_1 = \left( \vec{A}\_1, B\_1\right) \in \mathsf{GLWE}\_{\vec{S}} \left(
/// \mathsf{PT}\_1 \right) \subseteq \mathcal{R}\_q^{k+1} \\ \mathsf{CT}\_2 = \left( \vec{A}\_2,
/// B\_2\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT}\_2 \right) \subseteq
/// \mathcal{R}\_q^{k+1} \end{cases} $$
/// encrypted under the same
/// [`GLWE secret key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`)
/// $\vec{S} \in \mathcal{R}\_q^k$. We can add these ciphertexts homomorhically and obtain as a
/// result a new GLWE ciphertext encrypting the sum of the two plaintexts $\mathsf{PT}\_1 +
/// \mathsf{PT}\_2$.
///
/// ###### inputs:
/// - $\mathsf{CT}\_1 = \left( \vec{A}\_1, B\_1\right) \in \mathsf{GLWE}\_{\vec{S}} \left(
///   \mathsf{PT}\_1 \right) \subseteq \mathcal{R}\_q^{k+1}$: a GLWE ciphertext
/// - $\mathsf{CT}\_2 = \left( \vec{A}\_2, B\_2\right) \in \mathsf{GLWE}\_{\vec{S}} \left(
///   \mathsf{PT}\_2 \right) \subseteq \mathcal{R}\_q^{k+1}$: a GLWE ciphertext
///
/// ###### outputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT}\_1 +
///   \mathsf{PT}\_2 )\subseteq \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
///
/// ###### algorithm:
/// 1. Compute $\vec{A} = \vec{A}\_1 + \vec{A}\_2 \in\mathcal{R}^k\_q$
/// 2. Compute $B = B\_1 + B\_2 \in\mathcal{R}\_q$
/// 3. Output $\left( \vec{A} , B \right)$
pub trait LweCiphertextDiscardingAdditionEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Adds two LWE ciphertexts.
    fn discard_add_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    ) -> Result<(), LweCiphertextDiscardingAdditionError<Self::EngineError>>;

    /// Unsafely adds two LWE ciphertexts.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingAdditionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    );
}
