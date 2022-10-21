use super::engine_error;
use crate::core_crypto::prelude::{
    GlweCiphertextEntity, LwePrivateFunctionalPackingKeyswitchKeyEntity,
};
use crate::core_crypto::specification::engines::AbstractEngine;

use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError for
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext vector and input private functional packing \
                                 keyswitch key LWE dimension must be the same.",
    OutputGlweDimensionMismatch => "The output ciphertext vector and private functional packing \
                                   keyswitch key output GLWE dimensions must be the same.",
    OutputPolynomialSizeMismatch => "The output ciphertext vector and private functional packing \
                                    keyswitch key polynomial sizes must be the same.",
    CiphertextCountMismatch => "The input ciphertext count is bigger than the output polynomial \
                               size."
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<
        LwePrivateFunctionalPackingKeyswitchKey,
        InputCiphertextVector,
        OutputCiphertext,
    >(
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        ksk: &LwePrivateFunctionalPackingKeyswitchKey,
    ) -> Result<(), Self>
    where
        LwePrivateFunctionalPackingKeyswitchKey: LwePrivateFunctionalPackingKeyswitchKeyEntity,
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertext: GlweCiphertextEntity,
    {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if output.glwe_dimension() != ksk.output_glwe_dimension() {
            return Err(Self::OutputGlweDimensionMismatch);
        }

        if output.polynomial_size() != ksk.output_polynomial_size() {
            return Err(Self::OutputPolynomialSizeMismatch);
        }

        if input.lwe_ciphertext_count().0 > output.polynomial_size().0 {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines implementing private functional packing keyswitching (discarding) LWE
/// ciphertext vectors into a GLWE ciphertext.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext
/// with the private functional packing keyswitch of the `input` LWE ciphertext vector, under the
/// `pfpksk` private functional packing keyswitch key.
///
/// # Formal Definition
///
/// The private functional packing keyswitch takes as input an [`LWE ciphertext vector`]
/// (crate::core_crypto::specification::entities::LweCiphertextVectorEntity)
/// $$\mathsf{CT} = (\mathsf{ct\_1}, \mathsf{ct\_2}, \cdots, \mathsf{ct\_t}$$ where
/// $$\mathsf{ct\_i} = \left( \vec{a}\_i , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt}\_i)$$
/// (encrypted under some key `s`) along with an [`LWE private functional Packing keyswitch Key`]
/// (crate::core_crypto::specification::entities::LwePrivateFunctionalPackingKeyswitchKeyEntity)
/// (which privately encodes some function `f`) under the key `K`. The output is a
/// [`GLWE ciphertext`](`crate::core_crypto::specification::entities::GlweCiphertextVectorEntity`)
/// which encrypts the function `f` evaluated on the input
/// [`LWE ciphertext
/// vector`](crate::core_crypto::specification::entities::LweCiphertextVectorEntity).
/// under the key `K`. In particular, `f` encodes multiplication by some polynomial `p` and so the
/// output GLWE ciphertext encrypts: $(m_1 + m_2 X + ... + m_t X^(t-1)) * p(X)$
///
/// A full description of the algorithm can be found in <https://eprint.iacr.org/2017/430.pdf>
/// (pg.10)
pub trait LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine<
    LwePrivateFunctionalPackingKeyswitchKey,
    InputCiphertextVector,
    OutputCiphertext,
>: AbstractEngine where
    LwePrivateFunctionalPackingKeyswitchKey: LwePrivateFunctionalPackingKeyswitchKeyEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertext: GlweCiphertextEntity,
{
    /// Keyswitches an LWE ciphertext vector using a private functional packing keyswitch key.
    fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pfpksk: &LwePrivateFunctionalPackingKeyswitchKey,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    >;

    /// Unsafely keyswitches an LWE ciphertext vector using a private functional packing
    /// keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pfpksk: &LwePrivateFunctionalPackingKeyswitchKey,
    );
}
