use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GgswCiphertextEntity, GlweCiphertextEntity,
};

use super::engine_error;

engine_error! {
    GlweCiphertextsGgswCiphertextFusingCmuxError for
    GlweCiphertextsGgswCiphertextFusingCmuxEngine @
    PolynomialSizeMismatch => "The GGSW ciphertext and GLWE ciphertexts polynomial sizes must be \
    the same.",
    GlweDimensionMismatch => "The GGSW ciphertext and GLWE ciphertexts GLWE dimensions must be the \
    same."
}

impl<EngineError: std::error::Error> GlweCiphertextsGgswCiphertextFusingCmuxError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputGlweCiphertext, OutputGlweCiphertext, GgswCiphertext>(
        glwe_output: &OutputGlweCiphertext,
        glwe_input: &InputGlweCiphertext,
        ggsw: &GgswCiphertext,
    ) -> Result<(), Self>
    where
        InputGlweCiphertext: GlweCiphertextEntity,
        OutputGlweCiphertext: GlweCiphertextEntity,
        GgswCiphertext: GgswCiphertextEntity,
    {
        if (glwe_input.polynomial_size().0 != glwe_output.polynomial_size().0)
            | (glwe_output.polynomial_size().0 != ggsw.polynomial_size().0)
        {
            return Err(Self::PolynomialSizeMismatch);
        }
        if (glwe_input.glwe_dimension().0 != glwe_output.glwe_dimension().0)
            | (glwe_output.glwe_dimension().0 != ggsw.glwe_dimension().0)
        {
            return Err(Self::GlweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines computing the controlled multiplexer (cmux) of two GLWE ciphertexts and a
/// GGSW ciphertext.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation computes the result of the cmux between
/// `glwe_input` and `glwe_output` GLWE ciphertexts and a `ggsw_input` GGSW ciphertext.
///
/// # Formal Definition
///
/// The cmux is a homomorphic binary multiplexer which can been thought of as a homomorphic if
/// condition. It takes three encrypted values as input one of which is an encrypted bit which
/// selects which of the other two values is output.
///
/// In particular, it takes two
/// [`GLWE ciphertexts`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`)
/// $\mathsf{ct}\_0 \in \mathsf{GLWE}\_{\vec{s}}(
/// \mathsf{pt}\_0 )$ and $\mathsf{ct}\_1 \in \mathsf{GLWE}\_{\vec{s}}( \mathsf{pt}\_1 )$ and a
/// [`GGSW ciphertext`](`crate::core_crypto::specification::entities::GgswCiphertextEntity`)
/// $\mathsf{CT} \in \mathsf{GGSW}\_{\vec{s}}( b )$, for a bit $b$, and returns a
/// [`GLWE ciphertext`](`GlweCiphertextEntity`)
/// $\mathsf{ct}\_{\mathsf{out}} \in \mathsf{GLWE}\_{\vec{s}}( \mathsf{pt}\_b )$.
///
/// This is done by homomorphically computing $(\mathsf{pt}\_1-\mathsf{pt}\_0)*b + \mathsf{pt}\_0$
/// using the external product: $\mathsf{CT} \boxdot (\mathsf{ct}\_1 - \mathsf{ct}\_0) +
/// \mathsf{ct}\_0$.
pub trait GlweCiphertextsGgswCiphertextFusingCmuxEngine<GlweInput, GlweOutput, GgswInput>:
    AbstractEngine
where
    GlweInput: GlweCiphertextEntity,
    GgswInput: GgswCiphertextEntity,
    GlweOutput: GlweCiphertextEntity,
{
    /// Computes the cmux between two GLWE ciphertexts and a GGSW ciphertext.
    fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
        &mut self,
        glwe_output: &mut GlweOutput,
        glwe_input: &mut GlweInput,
        ggsw_input: &GgswInput,
    ) -> Result<(), GlweCiphertextsGgswCiphertextFusingCmuxError<Self::EngineError>>;

    /// Unsafely computes the cmux between two GLWE ciphertexts and a GGSW ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different
    /// variants of [`GlweCiphertextsGgswCiphertextFusingCmux']. For safety concerns _specific_
    /// to an engine, refer to the implementer safety section.
    unsafe fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_ouput: &mut GlweOutput,
        glwe_input: &mut GlweInput,
        ggsw_input: &GgswInput,
    );
}
