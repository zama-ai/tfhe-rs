use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GgswCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
};
use crate::core_crypto::specification::parameters::DeltaLog;

engine_error! {
    LweCiphertextDiscardingCircuitBootstrapBooleanError for
    LweCiphertextDiscardingCircuitBootstrapBooleanEngine @
    KeysDimensionMismatched => "The input LWE dimension of the private functional packing keyswitch\
                                keys need to be the same as the bootstrap key output LWE dimension\
                                .",
    MismatchedPolynomialSize => "The output GGSW ciphertext polynomial size must be the same as \
                                the private functional packing keyswitch keys polynomial size.",
    MismatchedGlweDimension => "The output GGSW ciphertext GLWE dimension must be the same as \
                                the private functional packing keyswitch keys GLWE dimension.",
    MismatchedPFPKSKCount => "The number of private function packing keyswitch keys does not match \
                                the required amount for the given output GGSW ciphertext.",
    MismatchedInputLweDimension => "The input ciphertext LWE dimension does not match the \
                                    bootstrap key input LWE dimension."
}

impl<EngineError: std::error::Error>
    LweCiphertextDiscardingCircuitBootstrapBooleanError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<
        Input,
        Output,
        BootstrapKey,
        CirctuiBootstrapFunctionalPackingKeyswitchKeys,
    >(
        input_lwe_ct: &Input,
        output_ggsw_ct: &Output,
        bootstrap_key: &BootstrapKey,
        cbs_pfpksk: &CirctuiBootstrapFunctionalPackingKeyswitchKeys,
    ) -> Result<(), Self>
    where
        Input: LweCiphertextEntity,
        Output: GgswCiphertextEntity,
        BootstrapKey: LweBootstrapKeyEntity,
        CirctuiBootstrapFunctionalPackingKeyswitchKeys:
            LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    {
        println!(
            "{:?} != {:?}",
            cbs_pfpksk.input_lwe_dimension(),
            bootstrap_key.output_lwe_dimension()
        );

        if cbs_pfpksk.input_lwe_dimension() != bootstrap_key.output_lwe_dimension() {
            return Err(Self::KeysDimensionMismatched);
        }
        if cbs_pfpksk.output_polynomial_size() != output_ggsw_ct.polynomial_size() {
            return Err(Self::MismatchedPolynomialSize);
        }
        if cbs_pfpksk.output_glwe_dimension() != output_ggsw_ct.glwe_dimension() {
            return Err(Self::MismatchedGlweDimension);
        }
        if cbs_pfpksk.key_count().0
            != output_ggsw_ct.decomposition_level_count().0
                * output_ggsw_ct.glwe_dimension().to_glwe_size().0
        {
            return Err(Self::MismatchedPFPKSKCount);
        }
        if input_lwe_ct.lwe_dimension() != bootstrap_key.input_lwe_dimension() {
            return Err(Self::MismatchedInputLweDimension);
        }
        Ok(())
    }
}

/// A trait for engines performing a (discarding) circuit bootstrap on an LWE ciphertext encrypting
/// a boolean message (i.e. containing only 1 bit of information).
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GGSW ciphertext with
/// the result of the circuit bootstrap of the `input` LWE ciphertext using the given bootstrap key
/// `bsk` and vector of private functional packing keyswitch keys `cbs_pfpksk`.
///
/// # Formal Definition
/// Circuit bootstrapping takes as input an [`LWE ciphertext`]
/// (crate::core_crypto::specification::entities::LweCiphertextEntity)
/// `ct` encrypting a boolean value $m \in \{0,1}$, i.e.
/// $$\mathsf{ct\} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{m} )$$
/// and an [`LWE Bootstrapping
/// key`](crate::core_crypto::specification::entities::LweBootstrapKeyEntity) `BSK`. The goal
/// of circuit bootstrapping is to convert an LWE ciphertext into a GGSW ciphertext. Therefore, the
/// output is a [`GGSW ciphertext`]
/// (crate::core_crypto::specification::entities::GgswCiphertextEntity)
/// which encrypts the boolean value $m \in \{0,1}$. We also require usage of an
/// [`LWE private functional Packing keyswitch Key`]
/// (crate::core_crypto::specification::entities::LwePrivateFunctionalPackingKeyswitchKeyEntity)
/// which enables a [`Private functional packing keyswitch`]
/// (crate::core_crypto::specification::engines::LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine)
/// to be evaluated. The algorithm operates as follows:
/// 1. Perform several PBS' to transform the input LWE ciphertext into LWE encryptions of
/// $ m \cdot q / b^j$.
/// 2. Perform a [`Private functional packing keyswitch`]
/// (crate::core_crypto::specification::engines::LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine)
/// in order to multiply the messages $ m \cdot q / b^j$ by the element of the secret key. This
/// allows us to obtain the output [`GGSW ciphertext`]
/// (crate::core_crypto::specification::entities::GgswCiphertextEntity).
pub trait LweCiphertextDiscardingCircuitBootstrapBooleanEngine<
    Input,
    Output,
    BootstrapKey,
    CirctuiBootstrapFunctionalPackingKeyswitchKeys,
>: AbstractEngine where
    Input: LweCiphertextEntity,
    Output: GgswCiphertextEntity,
    BootstrapKey: LweBootstrapKeyEntity,
    CirctuiBootstrapFunctionalPackingKeyswitchKeys:
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
{
    /// Perfom the circuit bootstrap on the input LWE ciphertext.
    fn discard_circuit_bootstrap_boolean_lwe_ciphertext(
        &mut self,
        output: &mut Output,
        input: &Input,
        delta_log: DeltaLog,
        bsk: &BootstrapKey,
        cbs_pfpksk: &CirctuiBootstrapFunctionalPackingKeyswitchKeys,
    ) -> Result<(), LweCiphertextDiscardingCircuitBootstrapBooleanError<Self::EngineError>>;

    /// Unsafely perfom the circuit bootstrap on the input LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingCircuitBootstrapBooleanError`]. For safety concerns _specific_
    /// to an engine, refer to the implementer safety section.
    unsafe fn discard_circuit_bootstrap_boolean_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
        delta_log: DeltaLog,
        bsk: &BootstrapKey,
        cbs_pfpksk: &CirctuiBootstrapFunctionalPackingKeyswitchKeys,
    );
}
