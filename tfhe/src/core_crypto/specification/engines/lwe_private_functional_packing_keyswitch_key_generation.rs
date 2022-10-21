use super::engine_error;
use crate::core_crypto::prelude::{
    CleartextVectorEntity, GlweSecretKeyEntity, LwePrivateFunctionalPackingKeyswitchKeyEntity,
};
use crate::core_crypto::specification::engines::AbstractEngine;

use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, PolynomialSize, StandardDev,
};
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

engine_error! {
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError for
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    DifferentPolynomialSizes => "The polynomial size of the output GLWE key is different from \
                                 that of the polynomial scalar defining the function."
}

impl<EngineError: std::error::Error>
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks(
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        ciphertext_modulus_log: usize,
        output_key_polynomial_size: PolynomialSize,
        polynomial_scalar_polynomial_size: PolynomialSize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }

        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }

        if decomposition_level_count.0 * decomposition_base_log.0 > ciphertext_modulus_log {
            return Err(Self::DecompositionTooLarge);
        }

        if output_key_polynomial_size != polynomial_scalar_polynomial_size {
            return Err(Self::DifferentPolynomialSizes);
        }
        Ok(())
    }
}

/// A trait for engines generating new LWE functional packing keyswitch keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a new LWE private functional packing
/// keyswitch key allowing to switch from the `input_key` LWE secret key to the `output_key` GLWE
/// secret key while applying the private function.
///
/// # Formal Definition
///
/// A private functional packing keyswitch key is a public key which allows to go from a vector
/// of LWE ciphertexts encrypting messages $m\_1,\dotsc,m_t$ under the input secret key, to a GLWE
/// ciphertext under the output secret key encrypting the
/// message $F(m\_1)+F(m\_2) X+\dotsb+F(m\_t) X^{t-1}$ in the ring $\mathbb{Z}\_q\lbrack X\rbrack/
/// (X^N+1)$ for
/// $t<N$ and a scalar function $F\colon\mathbb{Z}\_q\rightarrow\mathbb{Z}\_q\lbrack X\rbrack/
/// (X^n+1)$.
///
/// The scalar function F is defined in terms of the input `polynomial_scalar` as $F(z) =
/// \mathsf{polynomial\\_scalar}\cdot z$, where
/// $\mathsf{polynomial\\_scalar}$ is an element of $\mathbb{Z}\_q\lbrack X\rbrack/(X^n+1)$.
///
/// In particular, creation of a private functional packing keyswitch key takes seven inputs:
/// a [`LWE secret key`](`crate::core_crypto::specification::entities::LweSecretKeyEntity`)
/// for the input secret key, a [`GLWE secret
/// key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`) for the output
/// secret key, a [`decomposition
/// level`](`crate::core_crypto::prelude::DecompositionLevelCount`), a [`decomposition
/// base`](`crate::core_crypto::prelude::DecompositionBaseLog`), a standard deviation for the
/// [`noise`](`crate::core_crypto::prelude::StandardDev`), and finally the
/// input `polynomial_scalar` given as a
/// [`cleartext vector`](`crate::core_crypto::specification::entities::CleartextEntity`)
/// starting from the constant term.
pub trait LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine<
    InputSecretKey,
    OutputSecretKey,
    LwePrivateFunctionalPackingKeyswitchKey,
    CleartextVector,
    FunctionScalarType,
>: AbstractEngine where
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: GlweSecretKeyEntity,
    CleartextVector: CleartextVectorEntity,
    LwePrivateFunctionalPackingKeyswitchKey: LwePrivateFunctionalPackingKeyswitchKeyEntity,
{
    /// Generates a new private functional packing keyswitch key.
    #[allow(clippy::too_many_arguments)]
    fn generate_new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(FunctionScalarType) -> FunctionScalarType,
        polynomial: &CleartextVector,
    ) -> Result<
        LwePrivateFunctionalPackingKeyswitchKey,
        LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError<Self::EngineError>,
    >;

    /// Unsafely generates a new private functional packing keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError`]. For safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    #[allow(clippy::too_many_arguments)]
    unsafe fn generate_new_lwe_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(FunctionScalarType) -> FunctionScalarType,
        polynomial: &CleartextVector,
    ) -> LwePrivateFunctionalPackingKeyswitchKey;
}
