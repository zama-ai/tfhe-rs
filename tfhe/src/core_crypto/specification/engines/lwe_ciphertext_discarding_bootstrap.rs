use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;

use crate::core_crypto::specification::entities::{
    GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
};

engine_error! {
    LweCiphertextDiscardingBootstrapError for LweCiphertextDiscardingBootstrapEngine @
    InputLweDimensionMismatch => "The input ciphertext and key LWE dimension must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext dimension and key size (dimension * \
                                   polynomial size) must be the same.",
    AccumulatorPolynomialSizeMismatch => "The accumulator and key polynomial sizes must be the same.",
    AccumulatorGlweDimensionMismatch => "The accumulator and key GLWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingBootstrapError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<BootstrapKey, Accumulator, InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input: &InputCiphertext,
        acc: &Accumulator,
        bsk: &BootstrapKey,
    ) -> Result<(), Self>
    where
        BootstrapKey: LweBootstrapKeyEntity,
        Accumulator: GlweCiphertextEntity,
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity,
    {
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }
        if acc.polynomial_size() != bsk.polynomial_size() {
            return Err(Self::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_dimension() != bsk.glwe_dimension() {
            return Err(Self::AccumulatorGlweDimensionMismatch);
        }
        if output.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }

        Ok(())
    }
}

/// A trait for engines bootstrapping (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the bootstrap of the `input` LWE ciphertext, using the `acc` accumulator as lookup-table, and
/// the `bsk` bootstrap key.
///
/// # Formal Definition
///
/// ## Programmable Bootstrapping
///
/// This homomorphic procedure allows to both reduce the noise of a ciphertext and to evaluate a
/// Look-Up Table (LUT) on the encrypted plaintext at the same time, i.e., it transforms an input
/// [`LWE ciphertext`](`crate::core_crypto::specification::entities::LweCiphertextEntity`)
/// $\mathsf{ct}\_{\mathsf{in}} = \left(
/// \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in
/// \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}( \mathsf{pt} ) \subseteq
/// \mathbb{Z}\_q^{(n\_{\mathsf{in}}+1)}$ into an output
/// [`LWE ciphertext`](`LweCiphertextEntity`)
/// $\mathsf{ct}\_{\mathsf{out}} = \left( \vec{a}\_{\mathsf{out}} ,
/// b\_{\mathsf{out}}\right) \in \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}(
/// \mathsf{LUT(pt)} )\subseteq \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)}$ where $n\_{\mathsf{in}} =
/// |\vec{s}\_{\mathsf{in}}|$ and $n\_{\mathsf{out}} = |\vec{s}\_{\mathsf{out}}|$, such that the
/// noise in this latter is set to a fixed (reduced) amount. It requires a
/// [`bootstrapping key`](`LweBootstrapKeyEntity`).
///
/// The input ciphertext is encrypted under the
/// [`LWE secret key`](`crate::core_crypto::specification::entities::LweSecretKeyEntity`)
/// $\vec{s}\_{\mathsf{in}}$ and the
/// output ciphertext is encrypted under the
/// [`LWE secret key`](`crate::core_crypto::specification::entities::LweSecretKeyEntity`)
/// $\vec{s}\_{\mathsf{out}}$.
///
/// $$\mathsf{ct}\_{\mathsf{in}} \in \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}(
/// \mathsf{pt} ) ~~~~~~~~~~\mathsf{BSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow
/// \vec{S}\_{\mathsf{out}}}$$ $$ \mathsf{PBS}\left(\mathsf{ct}\_{\mathsf{in}} , \mathsf{BSK}
/// \right) \rightarrow \mathsf{ct}\_{\mathsf{out}} \in
/// \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}} \left( \mathsf{pt} \right)$$
///
/// ## Algorithm
/// ###### inputs:
/// - $\mathsf{ct}\_{\mathsf{in}} = \left( \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in
///   \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}( \mathsf{pt} )$: an [`LWE
///   ciphertext`](`LweCiphertextEntity`) with $\vec{a}\_{\mathsf{in}}=\left(a\_0, \cdots
///   a\_{n\_{\mathsf{in}}-1}\right)$
/// - $\mathsf{BSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{S}\_{\mathsf{out}}}$: a bootstrapping
///   key as defined above
/// - $\mathsf{LUT} \in \mathcal{R}\_q$: a LUT represented as a polynomial \_with redundancy\_
///
/// ###### outputs:
/// - $\mathsf{ct}\_{\mathsf{out}} \in \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}
///   \left( \mathsf{LUT(pt)} \right)$: an [`LWE
///   ciphertext`](`crate::core_crypto::specification::entities::LweCiphertextEntity`)
///
/// ###### algorithm:
/// 1. Compute $\tilde{a}\_i \in \mathbb{Z}\_{2N\_{\mathsf{out}}} \leftarrow \lfloor \frac{2
/// N\_{\mathsf{out}} \cdot a\_i}{q} \rceil$, for $i= 0, 1, \ldots, n\_{\mathsf{in}-1}$ 2. Compute
/// $\tilde{b}\_\mathsf{in} \in \mathbb{Z}\_{2N\_{\mathsf{out}}} \leftarrow \lfloor \frac{2
/// N\_{\mathsf{out}} \cdot b\_\mathsf{in}}{q} \rceil$ 3. Set $\mathsf{ACC} = (0, \ldots, 0,
/// \mathsf{LUT} \cdot X^{-\tilde{b}\_\mathsf{in}})$ 4. Compute $\mathsf{ACC} =
/// \mathsf{CMux}(\overline{\overline{\mathsf{CT}\_i}}, \mathsf{ACC} \cdot X^{\tilde{a}\_i},
/// \mathsf{ACC})$, for $i= 0, 1, \ldots, n\_{\mathsf{in}-1}$ 5. Output $\mathsf{ct}\_{\mathsf{out}}
/// \leftarrow \mathsf{SampleExtract}(\mathsf{ACC})$
pub trait LweCiphertextDiscardingBootstrapEngine<
    BootstrapKey,
    Accumulator,
    InputCiphertext,
    OutputCiphertext,
>: AbstractEngine where
    BootstrapKey: LweBootstrapKeyEntity,
    Accumulator: GlweCiphertextEntity,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Bootstrap an LWE ciphertext .
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        acc: &Accumulator,
        bsk: &BootstrapKey,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>>;

    /// Unsafely bootstrap an LWE ciphertext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingBootstrapError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        acc: &Accumulator,
        bsk: &BootstrapKey,
    );
}
