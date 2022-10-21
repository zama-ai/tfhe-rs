use super::engine_error;
use crate::core_crypto::prelude::{
    AbstractEngine, CiphertextModulusLog, DeltaLog, ExtractedBitsCount, LweBootstrapKeyEntity,
    LweCiphertextEntity, LweCiphertextVectorEntity, LweKeyswitchKeyEntity,
};

engine_error! {
    LweCiphertextDiscardingBitExtractError for LweCiphertextDiscardingBitExtractEngine @
    InputLweDimensionMismatch => "The input ciphertext and bootstrap key LWE dimension must be the \
                                  same.",
    InputKeyswitchKeyLweDimensionMismatch => "The input ciphertext LWE dimension must be the same \
                                            as the keyswitch key input LWE dimension.",
    OutputLweDimensionMismatch => "The output ciphertext vector LWE dimension must be the same \
                                  as the output LWE dimension of the keyswitch key.",
    ExtractedBitsCountMismatch => "The output LWE ciphertext vector count must be the same as \
                                  the number of bits to extract.",
    KeyDimensionMismatch => "The keyswitch key output LWE dimension must be the same as the \
                            bootstrap key input LWE dimension.",
    NotEnoughBitsToExtract => "The number of bits to extract, starting from the bit at index  \
                              delta_log towards the most significant bits, should not exceed the \
                              total number of available bits in the ciphertext."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingBitExtractError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<
        BootstrapKey,
        KeyswitchKey,
        InputCiphertext,
        OutputCiphertextVector,
    >(
        output: &OutputCiphertextVector,
        input: &InputCiphertext,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        extracted_bits_count: ExtractedBitsCount,
        ciphertext_modulus_log: CiphertextModulusLog,
        delta_log: DeltaLog,
    ) -> Result<(), Self>
    where
        BootstrapKey: LweBootstrapKeyEntity,
        KeyswitchKey: LweKeyswitchKeyEntity,
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
    {
        if input.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputKeyswitchKeyLweDimensionMismatch);
        }
        if output.lwe_dimension() != ksk.output_lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }
        if output.lwe_ciphertext_count().0 != extracted_bits_count.0 {
            return Err(Self::ExtractedBitsCountMismatch);
        }
        if ksk.output_lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(Self::KeyDimensionMismatch);
        }
        if ciphertext_modulus_log.0 < extracted_bits_count.0 + delta_log.0 {
            return Err(Self::NotEnoughBitsToExtract);
        }
        Ok(())
    }
}

/// A trait for engines doing a (discarding) bit extract over LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the bit extraction of the `input` LWE ciphertext, extracting `number_of_bits_to_extract`
/// bits starting from the bit at index `delta_log` (0-indexed) included, and going towards the
/// most significant bits.
///
/// Output bits are ordered from the MSB to the LSB. Each one of them is output in a distinct LWE
/// ciphertext, containing the encryption of the bit scaled by q/2 (i.e., the most significant bit
/// in the plaintext representation).
///
/// # Formal Definition
///
/// This function takes as input an [`LWE ciphertext`]
/// (crate::core_crypto::specification::entities::LweCiphertextEntity)
/// $$\mathsf{ct\} = \mathsf{LWE}^n\_{\vec{s}}( \mathsf{m}) \subseteq \mathbb{Z}\_q^{(n+1)}$$
/// which encrypts some message `m`. We extract bits $m\_i$ of this message into individual LWE
/// ciphertexts. Each of these ciphertexts contains an encryption of $m\_i \cdot q/2$, i.e.
/// $$\mathsf{ct\_i} = \mathsf{LWE}^n\_{\vec{s}}( \mathsf{m\_i} \cdot q/2 )$$. The number of
/// output LWE ciphertexts is determined by the `number_of_bits_to_extract` input parameter.
pub trait LweCiphertextDiscardingBitExtractEngine<
    BootstrapKey,
    KeyswitchKey,
    InputCiphertext,
    OutputCiphertextVector,
>: AbstractEngine where
    BootstrapKey: LweBootstrapKeyEntity,
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Extract bits of an LWE ciphertext.
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertext,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>>;

    /// Unsafely extract bits of an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingBitExtractError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertext,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    );
}
