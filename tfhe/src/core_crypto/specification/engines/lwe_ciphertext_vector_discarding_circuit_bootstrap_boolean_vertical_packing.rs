use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweBootstrapKeyEntity, LweCiphertextVectorEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, PlaintextVectorEntity,
};
use crate::core_crypto::specification::parameters::{
    DecompositionBaseLog, DecompositionLevelCount,
};

engine_error! {
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError for
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine @
    NullDecompositionBaseLog => "The circuit bootstrap decomposition base log must be greater \
                                than zero.",
    NullDecompositionLevelCount => "The circuit bootstrap decomposition level count must be \
                                    greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    KeysLweDimensionMismatch => "The bootstrap key output LWE dimension must be the same as the \
                                input LWE dimension of the circuit bootstrap private functional \
                                packing keyswitch keys.",
    InputLweDimensionMismatch => "The input ciphertexts LWE dimension must be the same as the \
                                    bootstrap key input LWE dimension.",
    OutputLweDimensionMismatch => "The output ciphertexts LWE dimension must be the same as the \
                                    `cbs_pfpksk` output GLWE dimension times its output polynomial \
                                    size.",
    MalformedLookUpTables => "The input `luts` must have a size divisible by the circuit bootstrap \
                                private functional packing keyswitch keys output polynomial size \
                                times the number of output ciphertexts. This is required to get \
                                small look-up tables of polynomials of the same size for each \
                                output ciphertext.",
    InvalidSmallLookUpTableSize => "The number of polynomials times the polynomial size in a small \
                                    look-up table must be equal to 2 to the power the number of \
                                    input ciphertexts encrypting bits."
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError<EngineError>
{
    /// Validates the inputs
    #[allow(clippy::too_many_arguments)]
    pub fn perform_generic_checks<
        Input: LweCiphertextVectorEntity,
        Output: LweCiphertextVectorEntity,
        BootstrapKey: LweBootstrapKeyEntity,
        LUTs: PlaintextVectorEntity,
        CBSPFPKSK: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    >(
        input: &Input,
        output: &Output,
        bsk: &BootstrapKey,
        luts: &LUTs,
        cbs_decomposition_level_count: DecompositionLevelCount,
        cbs_decomposition_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CBSPFPKSK,
        ciphertext_modulus_log: usize,
    ) -> Result<(), Self> {
        if bsk.output_lwe_dimension() != cbs_pfpksk.input_lwe_dimension() {
            return Err(Self::KeysLweDimensionMismatch);
        }
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }
        if output.lwe_dimension().0
            != cbs_pfpksk.output_glwe_dimension().0 * cbs_pfpksk.output_polynomial_size().0
        {
            return Err(Self::OutputLweDimensionMismatch);
        }

        let lut_polynomial_size = cbs_pfpksk.output_polynomial_size().0;
        if luts.plaintext_count().0 % (lut_polynomial_size * output.lwe_ciphertext_count().0) != 0 {
            return Err(Self::MalformedLookUpTables);
        }

        let small_lut_size = luts.plaintext_count().0 / output.lwe_ciphertext_count().0;
        if small_lut_size < lut_polynomial_size {
            return Err(Self::InvalidSmallLookUpTableSize);
        }

        if cbs_decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }
        if cbs_decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }
        if cbs_decomposition_base_log.0 * cbs_decomposition_level_count.0 > ciphertext_modulus_log {
            return Err(Self::DecompositionTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines performing a (discarding) boolean circuit bootstrapping followed by a
/// vertical packing on LWE ciphertext vectors. The term "boolean" refers to the fact the input
/// ciphertexts encrypt a single bit of message.
///
/// The provided "big" `luts` look-up table is expected to be divisible into the same number of
/// chunks of polynomials as there are ciphertexts in the `output` LweCiphertextVector. Each chunk
/// of polynomials is used as a look-up table to evaluate during the vertical packing operation to
/// fill an output ciphertext.
///
/// Note that there should be enough polynomials provided in each chunk to perform the vertical
/// packing given the number of boolean input ciphertexts. The number of boolean input ciphertexts
/// is in fact a number of bits. For this example let's say we have 16 input ciphertexts
/// representing 16 bits and want to output 4 ciphertexts. The "big" `luts` will need to be
/// divisible into 4 chunks of equal size. If the polynomial size used is $1024 = 2^{10}$ then each
/// chunk must contain $2^6 = 64$ polynomials ($2^6 * 2^{10} = 2^{16}$) to match the amount of
/// values representable by the 16 input ciphertexts each encrypting a bit. The "big" `luts` then
/// has a layout looking as follows:
///
/// ```text
/// small lut for 1st output ciphertext|...|small lut for 4th output ciphertext
/// |[polynomial 1] ... [polynomial 64]|...|[polynomial 1] ... [polynomial 64]|
/// ```
///
/// The polynomials in the above representation are not necessarily the same, this is just for
/// illustration purposes.
///
/// It is also possible in the above example to have a single polynomial of size $2^{16} = 65 536$
/// for each chunk if the polynomial size is supported for computation (which is not the case for 65
/// 536 at the moment for implemented backends). Chunks containing a single polynomial of size
/// $2^{10} = 1024$ would work for example for 10 input ciphertexts as that polynomial size is
/// supported for computations. The "big" `luts` layout would then look as follows for that 10 bits
/// example (still with 4 output ciphertexts):
///
/// ```text
/// small lut for 1st output ciphertext|...|small lut for 4th output ciphertext
/// |[          polynomial 1          ]|...|[          polynomial 1          ]|
/// ```
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation first performs the circuit bootstrapping
/// on all boolean (i.e. containing only 1 bit of message) input LWE ciphertexts from the `input`
/// vector. It then fills the `output` LWE ciphertext vector with the result of the vertical packing
/// operation applied on the output of the circuit bootstrapping, using the provided look-up table.
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine<
    Input,
    Output,
    BootstrapKey,
    LUTs,
    CirctuiBootstrapFunctionalPackingKeyswitchKeys,
>: AbstractEngine where
    Input: LweCiphertextVectorEntity,
    Output: LweCiphertextVectorEntity,
    BootstrapKey: LweBootstrapKeyEntity,
    LUTs: PlaintextVectorEntity,
    CirctuiBootstrapFunctionalPackingKeyswitchKeys:
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
{
    /// Performs the circuit bootstrapping on all boolean input LWE ciphertexts followed by vertical
    /// packing using the provided look-up table.
    #[allow(clippy::too_many_arguments)]
    fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
        bsk: &BootstrapKey,
        luts: &LUTs,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CirctuiBootstrapFunctionalPackingKeyswitchKeys,
    ) -> Result<
        (),
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError<Self::EngineError>,
    >;

    /// Unsafely performs the circuit bootstrapping on all boolean input LWE ciphertexts followed by
    /// vertical packing using the provided look-up table.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError`]. For safety
    /// concerns _specific_ to an engine, refer to the implementer safety section.
    #[allow(clippy::too_many_arguments)]
    unsafe fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
        bsk: &BootstrapKey,
        luts: &LUTs,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CirctuiBootstrapFunctionalPackingKeyswitchKeys,
    );
}
