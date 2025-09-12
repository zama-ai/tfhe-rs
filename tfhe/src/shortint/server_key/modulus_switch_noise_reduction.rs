use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{CompressionSeed, DynamicDistribution, Uniform};
use crate::core_crypto::commons::parameters::{
    LweDimension, NoiseEstimationMeasureBound, PlaintextCount, RSigmaFactor,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key;
use crate::core_crypto::prelude::{
    CiphertextModulus as CoreCiphertextModulus, CiphertextModulusLog, Variance,
};
use crate::shortint::backward_compatibility::server_key::modulus_switch_noise_reduction::*;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::ModulusSwitchNoiseReductionParams;

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Copy, Clone)]
pub struct ModulusSwitchNoiseReductionKeyConformanceParams {
    pub modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
    pub lwe_dimension: LweDimension,
}

/// Using a [ModulusSwitchNoiseReductionKey], it's possible do apply a modulus switch which adds
/// less noise by calling the
/// [switch_modulus](ModulusSwitchNoiseReductionKey::improve_noise_and_modulus_switch) method on the
/// target ciphertext.
///
/// The lower level primitive is
/// [improve_lwe_ciphertext_modulus_switch_noise_for_binary_key](crate::core_crypto::algorithms::modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ModulusSwitchNoiseReductionKeyVersions)]
pub struct ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    pub modulus_switch_zeros: LweCiphertextListOwned<InputScalar>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
    pub ms_input_variance: Variance,
}

impl<InputScalar> ParameterSetConformant for ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    type ParameterSet = ModulusSwitchNoiseReductionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = self;

        let ModulusSwitchNoiseReductionKeyConformanceParams {
            modulus_switch_noise_reduction_params,
            lwe_dimension,
        } = parameter_set;

        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: param_modulus_switch_zeros_count,
            ms_bound: param_ms_bound,
            ms_r_sigma_factor: param_ms_r_sigma_factor,
            ms_input_variance: param_ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        ms_bound == param_ms_bound
            && ms_r_sigma_factor == param_ms_r_sigma_factor
            && ms_input_variance == param_ms_input_variance
            && modulus_switch_zeros.entity_count() == param_modulus_switch_zeros_count.0
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == *lwe_dimension
    }
}

impl<InputScalar> ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    pub(crate) fn improve_modulus_switch_noise<Cont>(
        &self,
        input: &mut LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) where
        Cont: ContainerMut<Element = InputScalar>,
    {
        improve_lwe_ciphertext_modulus_switch_noise_for_binary_key(
            input,
            &self.modulus_switch_zeros,
            self.ms_r_sigma_factor,
            self.ms_bound,
            self.ms_input_variance,
            log_modulus,
        );
    }

    pub fn improve_noise_and_modulus_switch<Cont, SwitchedScalar>(
        &self,
        input: &LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) -> LazyStandardModulusSwitchedLweCiphertext<InputScalar, SwitchedScalar, Vec<InputScalar>>
    where
        InputScalar: CastInto<SwitchedScalar>,
        SwitchedScalar: UnsignedInteger,
        Cont: Container<Element = InputScalar>,
    {
        let mut input: LweCiphertext<Vec<InputScalar>> =
            LweCiphertext::from_container(input.as_ref().to_owned(), input.ciphertext_modulus());

        self.improve_modulus_switch_noise(&mut input, log_modulus);

        lwe_ciphertext_modulus_switch(input, log_modulus)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchNoiseReductionKeyVersions)]
pub struct CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    pub modulus_switch_zeros: SeededLweCiphertextListOwned<InputScalar>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
    pub ms_input_variance: Variance,
}

impl<InputScalar> ParameterSetConformant for CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    type ParameterSet = ModulusSwitchNoiseReductionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = self;

        let ModulusSwitchNoiseReductionKeyConformanceParams {
            modulus_switch_noise_reduction_params,
            lwe_dimension,
        } = parameter_set;

        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: param_modulus_switch_zeros_count,
            ms_bound: param_ms_bound,
            ms_r_sigma_factor: param_ms_r_sigma_factor,
            ms_input_variance: param_ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        ms_bound == param_ms_bound
            && ms_r_sigma_factor == param_ms_r_sigma_factor
            && ms_input_variance == param_ms_input_variance
            && modulus_switch_zeros.entity_count() == param_modulus_switch_zeros_count.0
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == *lwe_dimension
    }
}

impl<InputScalar> ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: Encryptable<Uniform, DynamicDistribution<InputScalar>>,
{
    pub fn new<KeyCont: Container<Element = InputScalar> + Sync>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        engine: &mut ShortintEngine,
        ciphertext_modulus: CoreCiphertextModulus<InputScalar>,
        lwe_noise_distribution: DynamicDistribution<InputScalar>,
    ) -> Self {
        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        let lwe_size = secret_key.lwe_dimension().to_lwe_size();

        let mut modulus_switch_zeros =
            LweCiphertextList::new(InputScalar::ZERO, lwe_size, count, ciphertext_modulus);

        let plaintext_list = PlaintextList::new(InputScalar::ZERO, PlaintextCount(count.0));

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        par_encrypt_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.encryption_generator,
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        encrypt_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.encryption_generator,
        );

        Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        }
    }
}

impl<InputScalar> CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: Encryptable<Uniform, DynamicDistribution<InputScalar>>,
{
    pub fn new<KeyCont: Container<Element = InputScalar> + Sync>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        engine: &mut ShortintEngine,
        ciphertext_modulus: CoreCiphertextModulus<InputScalar>,
        lwe_noise_distribution: DynamicDistribution<InputScalar>,
        compression_seed: CompressionSeed,
    ) -> Self {
        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        let lwe_size = secret_key.lwe_dimension().to_lwe_size();

        let mut modulus_switch_zeros = SeededLweCiphertextList::new(
            InputScalar::ZERO,
            lwe_size,
            count,
            compression_seed,
            ciphertext_modulus,
        );

        let plaintext_list = PlaintextList::new(InputScalar::ZERO, PlaintextCount(count.0));

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        par_encrypt_seeded_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.seeder,
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        encrypt_seeded_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.seeder,
        );

        Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        }
    }
}

impl<InputScalar> CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedTorus,
{
    pub fn decompress(&self) -> ModulusSwitchNoiseReductionKey<InputScalar> {
        ModulusSwitchNoiseReductionKey {
            modulus_switch_zeros: self
                .modulus_switch_zeros
                .as_view()
                .decompress_into_lwe_ciphertext_list(),
            ms_bound: self.ms_bound,
            ms_r_sigma_factor: self.ms_r_sigma_factor,
            ms_input_variance: self.ms_input_variance,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchConfigurationVersions)]
pub enum CompressedModulusSwitchConfiguration<Scalar>
where
    Scalar: UnsignedInteger,
{
    Standard,
    DriftTechniqueNoiseReduction(CompressedModulusSwitchNoiseReductionKey<Scalar>),
    CenteredMeanNoiseReduction,
}

impl<Scalar: UnsignedTorus> CompressedModulusSwitchConfiguration<Scalar> {
    pub fn decompress(&self) -> ModulusSwitchConfiguration<Scalar> {
        match self {
            Self::Standard => ModulusSwitchConfiguration::Standard,
            Self::DriftTechniqueNoiseReduction(compressed_modulus_switch_noise_reduction_key) => {
                ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                    compressed_modulus_switch_noise_reduction_key.decompress(),
                )
            }
            Self::CenteredMeanNoiseReduction => {
                ModulusSwitchConfiguration::CenteredMeanNoiseReduction
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ModulusSwitchConfigurationVersions)]
pub enum ModulusSwitchConfiguration<Scalar>
where
    Scalar: UnsignedInteger,
{
    Standard,
    DriftTechniqueNoiseReduction(ModulusSwitchNoiseReductionKey<Scalar>),
    CenteredMeanNoiseReduction,
}

impl<'a, Scalar: UnsignedInteger> ModulusSwitchConfiguration<Scalar> {
    pub fn lwe_ciphertext_modulus_switch<SwitchedScalar, Cont>(
        &self,
        lwe_in: &'a LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) -> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, Cow<'a, [Scalar]>>
    where
        Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
        SwitchedScalar: UnsignedInteger,
        Cont: Container<Element = Scalar>,
    {
        let lwe_in = LweCiphertext::from_container(
            Cow::Borrowed(lwe_in.as_ref()),
            lwe_in.ciphertext_modulus(),
        );

        match self {
            Self::Standard => lwe_ciphertext_modulus_switch(lwe_in, log_modulus),
            Self::DriftTechniqueNoiseReduction(modulus_switch_noise_reduction_key) => {
                let lazy_msed_ct: LazyStandardModulusSwitchedLweCiphertext<
                    Scalar,
                    SwitchedScalar,
                    Vec<Scalar>,
                > = modulus_switch_noise_reduction_key
                    .improve_noise_and_modulus_switch(&lwe_in, log_modulus);

                let (lwe_ct, body_correction_to_add_before_switching, log_modulus) =
                    lazy_msed_ct.into_raw_parts();

                let ciphertext_modulus = lwe_ct.ciphertext_modulus();

                // Change lwe_ct container from Vec<Scalar> to Cow<'_, [Scalar]>
                let lwe_ct = LweCiphertext::from_container(
                    Cow::Owned(lwe_ct.into_container()),
                    ciphertext_modulus,
                );

                LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(
                    lwe_ct,
                    body_correction_to_add_before_switching,
                    log_modulus,
                )
            }
            Self::CenteredMeanNoiseReduction => {
                lwe_ciphertext_centered_binary_modulus_switch(lwe_in, log_modulus)
            }
        }
    }

    pub fn modulus_switch_noise_reduction_key(
        &self,
    ) -> Option<&ModulusSwitchNoiseReductionKey<Scalar>> {
        match self {
            Self::Standard | Self::CenteredMeanNoiseReduction => None,
            Self::DriftTechniqueNoiseReduction(modulus_switch_noise_reduction_key) => {
                Some(modulus_switch_noise_reduction_key)
            }
        }
    }
}

// ============== Noise measurement trait implementations ============== //
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateDriftTechniqueStandardModSwitchResult, AllocateStandardModSwitchResult,
    DriftTechniqueStandardModSwitch, StandardModSwitch,
};

impl<Scalar: UnsignedInteger> AllocateDriftTechniqueStandardModSwitchResult
    for ModulusSwitchNoiseReductionKey<Scalar>
{
    type AfterDriftOutput = LweCiphertextOwned<Scalar>;
    type AfterMsOutput = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        let after_drift = Self::AfterDriftOutput::new(
            Scalar::ZERO,
            self.modulus_switch_zeros.lwe_size(),
            self.modulus_switch_zeros.ciphertext_modulus(),
        );
        let after_ms = after_drift.allocate_standard_mod_switch_result(side_resources);
        (after_drift, after_ms)
    }
}

impl<
        Scalar: UnsignedInteger,
        InputCont: Container<Element = Scalar>,
        AfterDriftCont: ContainerMut<Element = Scalar>,
        AfterMsCont: ContainerMut<Element = Scalar>,
    >
    DriftTechniqueStandardModSwitch<
        LweCiphertext<InputCont>,
        LweCiphertext<AfterDriftCont>,
        LweCiphertext<AfterMsCont>,
    > for ModulusSwitchNoiseReductionKey<Scalar>
{
    type SideResources = ();

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &LweCiphertext<InputCont>,
        after_drift_technique: &mut LweCiphertext<AfterDriftCont>,
        after_mod_switch: &mut LweCiphertext<AfterMsCont>,
        side_resources: &mut Self::SideResources,
    ) {
        after_drift_technique
            .as_mut()
            .copy_from_slice(input.as_ref());
        self.improve_modulus_switch_noise(after_drift_technique, output_modulus_log);

        after_drift_technique.standard_mod_switch(
            output_modulus_log,
            after_mod_switch,
            side_resources,
        );
    }
}
