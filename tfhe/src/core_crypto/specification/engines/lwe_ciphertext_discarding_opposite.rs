use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextDiscardingOppositeError for LweCiphertextDiscardingOppositeEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingOppositeError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity,
    {
        if input.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        Ok(())
    }
}

/// A trait for engines computing the opposite (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the opposite of the `input` LWE ciphertext.
///
/// # Formal Definition
///
/// ## LWE opposite computation
/// This is a specification of the compuation of the opposite of a GLWE ciphertext, described
/// below.
///
/// ## GLWE opposite computation
///
/// It is easy to compute the opposite of a
/// [`GLWE ciphertext`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`),
/// i.e., a GLWE ciphertext
/// encrypting the opposite of the encrypted plaintext. Let a GLWE ciphertext $$
/// \mathsf{CT} = \left( \vec{A}, B\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT} \right)
/// \subseteq \mathcal{R}\_q^{k+1} $$
/// encrypted under the [`GLWE secret
/// key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`) $\vec{S} \in
/// \mathcal{R}\_q^k$. We can compute the opposite of this GLWE ciphertext and obtain as a result a
/// new GLWE ciphertext encrypting the opposite of the plaintext $- \mathsf{PT}$.
///
/// ###### inputs:
/// - $\mathsf{CT} = \left( \vec{A}, B\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT}
///   \right) \subseteq \mathcal{R}\_q^{k+1}$: a GLWE ciphertext
///
/// ###### outputs:
/// - $\mathsf{CT}' = \left( \vec{A}' , B' \right) \in \mathsf{GLWE}\_{\vec{S}}( -\mathsf{PT}
///   )\subseteq \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
///
/// ###### algorithm:
/// 1. Compute $\vec{A}' = -\vec{A} \in\mathcal{R}^k\_q$
/// 2. Compute $B' = -B \in\mathcal{R}\_q$
/// 3. Output $\left( \vec{A} , B \right)$
pub trait LweCiphertextDiscardingOppositeEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Computes the opposite of an LWE ciphertext.
    fn discard_opp_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), LweCiphertextDiscardingOppositeError<Self::EngineError>>;

    /// Unsafely computes the opposite of an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingOppositeError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_opp_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    );
}
