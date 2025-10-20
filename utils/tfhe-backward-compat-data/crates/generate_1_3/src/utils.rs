use std::path::Path;

use tfhe::core_crypto::prelude::{
    CiphertextModulusLog, LweCiphertextCount, TUniform, UnsignedInteger,
};
use tfhe::shortint::parameters::{
    CarryModulus, CiphertextModulus, CiphertextModulus32, ClassicPBSParameters,
    CompressionParameters, CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, EncryptionKeyChoice, GlweDimension, KeySwitch32PBSParameters,
    LweBskGroupingFactor, LweDimension, MaxNoiseLevel, MessageModulus,
    ModulusSwitchNoiseReductionParams, NoiseEstimationMeasureBound,
    NoiseSquashingCompressionParameters, NoiseSquashingParameters, PolynomialSize, RSigmaFactor,
    StandardDev, Variance,
};
use tfhe::shortint::prelude::ModulusSwitchType;
use tfhe::shortint::{AtomicPatternParameters, MultiBitPBSParameters};
use tfhe_versionable::Versionize;

use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

pub(crate) fn store_versioned_test<Data: Versionize + 'static, P: AsRef<Path>>(
    msg: &Data,
    dir: P,
    test_filename: &str,
) {
    generic_store_versioned_test(Versionize::versionize, msg, dir, test_filename)
}

#[allow(dead_code)]
pub(crate) fn store_versioned_auxiliary<Data: Versionize + 'static, P: AsRef<Path>>(
    msg: &Data,
    dir: P,
    test_filename: &str,
) {
    generic_store_versioned_auxiliary(Versionize::versionize, msg, dir, test_filename)
}

/// This trait allows to convert version independent parameters types defined in
/// `tfhe-backward-compat-data` to the equivalent TFHE-rs parameters for this version.
///
/// This is similar to `Into` but allows to circumvent the orphan rule.
pub(crate) trait ConvertParams<TfheRsParams> {
    fn convert(self) -> TfheRsParams;
}

impl<Scalar> ConvertParams<DynamicDistribution<Scalar>> for TestDistribution
where
    Scalar: UnsignedInteger,
{
    fn convert(self) -> DynamicDistribution<Scalar> {
        match self {
            TestDistribution::Gaussian { stddev } => {
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(stddev))
            }
            TestDistribution::TUniform { bound_log2 } => {
                DynamicDistribution::TUniform(TUniform::new(bound_log2))
            }
        }
    }
}

impl ConvertParams<ModulusSwitchNoiseReductionParams> for TestModulusSwitchNoiseReductionParams {
    fn convert(self) -> ModulusSwitchNoiseReductionParams {
        let TestModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = self;

        ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(modulus_switch_zeros_count),
            ms_bound: NoiseEstimationMeasureBound(ms_bound),
            ms_r_sigma_factor: RSigmaFactor(ms_r_sigma_factor),
            ms_input_variance: Variance(ms_input_variance),
        }
    }
}

impl ConvertParams<ModulusSwitchType> for TestModulusSwitchType {
    fn convert(self) -> ModulusSwitchType {
        match self {
            TestModulusSwitchType::Standard => ModulusSwitchType::Standard,
            TestModulusSwitchType::DriftTechniqueNoiseReduction(
                test_modulus_switch_noise_reduction_params,
            ) => ModulusSwitchType::DriftTechniqueNoiseReduction(
                test_modulus_switch_noise_reduction_params.convert(),
            ),
            TestModulusSwitchType::CenteredMeanNoiseReduction => {
                ModulusSwitchType::CenteredMeanNoiseReduction
            }
        }
    }
}

impl ConvertParams<ClassicPBSParameters> for TestClassicParameterSet {
    fn convert(self) -> ClassicPBSParameters {
        let TestClassicParameterSet {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            ciphertext_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            encryption_key_choice,
            modulus_switch_noise_reduction_params,
        } = self;

        ClassicPBSParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_noise_distribution: lwe_noise_distribution.convert(),
            glwe_noise_distribution: glwe_noise_distribution.convert(),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            max_noise_level: MaxNoiseLevel::new(max_noise_level as u64),
            log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params.convert(),
        }
    }
}

impl ConvertParams<MultiBitPBSParameters> for TestMultiBitParameterSet {
    fn convert(self) -> MultiBitPBSParameters {
        let TestMultiBitParameterSet {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            ciphertext_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            encryption_key_choice,
            grouping_factor,
        } = self;

        MultiBitPBSParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_noise_distribution: lwe_noise_distribution.convert(),
            glwe_noise_distribution: glwe_noise_distribution.convert(),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            max_noise_level: MaxNoiseLevel::new(max_noise_level as u64),
            log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
            grouping_factor: LweBskGroupingFactor(grouping_factor),
            deterministic_execution: false,
        }
    }
}

impl ConvertParams<KeySwitch32PBSParameters> for TestKS32ParameterSet {
    fn convert(self) -> KeySwitch32PBSParameters {
        let TestKS32ParameterSet {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            ciphertext_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            modulus_switch_noise_reduction_params,
            post_keyswitch_ciphertext_modulus,
        } = self;

        KeySwitch32PBSParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_noise_distribution: lwe_noise_distribution.convert(),
            glwe_noise_distribution: glwe_noise_distribution.convert(),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            max_noise_level: MaxNoiseLevel::new(max_noise_level as u64),
            log2_p_fail,
            post_keyswitch_ciphertext_modulus: CiphertextModulus32::try_new(
                post_keyswitch_ciphertext_modulus,
            )
            .unwrap(),
            ciphertext_modulus: CiphertextModulus::try_new(ciphertext_modulus).unwrap(),
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params.convert(),
        }
    }
}

impl ConvertParams<AtomicPatternParameters> for TestParameterSet {
    fn convert(self) -> AtomicPatternParameters {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                AtomicPatternParameters::Standard(test_classic_parameter_set.convert().into())
            }
            TestParameterSet::TestMultiBitParameterSet(test_parameter_set_multi_bit) => {
                AtomicPatternParameters::Standard(test_parameter_set_multi_bit.convert().into())
            }
            TestParameterSet::TestKS32ParameterSet(test_parameter_set_ks32) => {
                AtomicPatternParameters::KeySwitch32(test_parameter_set_ks32.convert())
            }
        }
    }
}

impl ConvertParams<CompressionParameters> for TestCompressionParameterSet {
    fn convert(self) -> CompressionParameters {
        let TestCompressionParameterSet {
            br_level,
            br_base_log,
            packing_ks_level,
            packing_ks_base_log,
            packing_ks_polynomial_size,
            packing_ks_glwe_dimension,
            lwe_per_glwe,
            storage_log_modulus,
            packing_ks_key_noise_distribution,
            decompression_grouping_factor,
        } = self;

        assert!(decompression_grouping_factor.is_none());

        CompressionParameters {
            br_level: DecompositionLevelCount(br_level),
            br_base_log: DecompositionBaseLog(br_base_log),
            packing_ks_level: DecompositionLevelCount(packing_ks_level),
            packing_ks_base_log: DecompositionBaseLog(packing_ks_base_log),
            packing_ks_polynomial_size: PolynomialSize(packing_ks_polynomial_size),
            packing_ks_glwe_dimension: GlweDimension(packing_ks_glwe_dimension),
            lwe_per_glwe: LweCiphertextCount(lwe_per_glwe),
            storage_log_modulus: CiphertextModulusLog(storage_log_modulus),
            packing_ks_key_noise_distribution: packing_ks_key_noise_distribution.convert(),
        }
    }
}

impl ConvertParams<NoiseSquashingParameters> for TestNoiseSquashingParams {
    fn convert(self) -> NoiseSquashingParameters {
        let TestNoiseSquashingParams {
            glwe_dimension,
            polynomial_size,
            glwe_noise_distribution,
            decomp_base_log,
            decomp_level_count,
            modulus_switch_noise_reduction_params,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        } = self;

        NoiseSquashingParameters {
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            glwe_noise_distribution: glwe_noise_distribution.convert(),
            decomp_base_log: DecompositionBaseLog(decomp_base_log),
            decomp_level_count: DecompositionLevelCount(decomp_level_count),
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params.convert(),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            ciphertext_modulus: CoreCiphertextModulus::try_new(ciphertext_modulus).unwrap(),
        }
    }
}

impl ConvertParams<NoiseSquashingCompressionParameters>
    for TestNoiseSquashingCompressionParameters
{
    fn convert(self) -> NoiseSquashingCompressionParameters {
        let TestNoiseSquashingCompressionParameters {
            packing_ks_level,
            packing_ks_base_log,
            packing_ks_polynomial_size,
            packing_ks_glwe_dimension,
            lwe_per_glwe,
            packing_ks_key_noise_distribution,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        } = self;

        NoiseSquashingCompressionParameters {
            packing_ks_level: DecompositionLevelCount(packing_ks_level),
            packing_ks_base_log: DecompositionBaseLog(packing_ks_base_log),
            packing_ks_polynomial_size: PolynomialSize(packing_ks_polynomial_size),
            packing_ks_glwe_dimension: GlweDimension(packing_ks_glwe_dimension),
            lwe_per_glwe: LweCiphertextCount(lwe_per_glwe),
            packing_ks_key_noise_distribution: packing_ks_key_noise_distribution.convert(),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            ciphertext_modulus: CoreCiphertextModulus::try_new(ciphertext_modulus).unwrap(),
        }
    }
}
