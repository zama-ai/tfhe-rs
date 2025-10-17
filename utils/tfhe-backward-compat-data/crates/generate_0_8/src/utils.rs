use std::path::Path;

use tfhe::core_crypto::prelude::{
    CiphertextModulusLog, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweCiphertextCount, LweDimension, PolynomialSize, StandardDev, TUniform,
    UnsignedInteger,
};
use tfhe::shortint::parameters::{CompressionParameters, LweBskGroupingFactor};
use tfhe::shortint::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
    MessageModulus, MultiBitPBSParameters, PBSParameters,
};
use tfhe_versionable::Versionize;

use tfhe_backward_compat_data::generate::{
    generic_store_versioned_auxiliary, generic_store_versioned_test,
};
use tfhe_backward_compat_data::{
    TestClassicParameterSet, TestCompressionParameterSet, TestDistribution,
    TestMultiBitParameterSet, TestParameterSet,
};

pub(crate) fn store_versioned_test<Data: Versionize + 'static, P: AsRef<Path>>(
    msg: &Data,
    dir: P,
    test_filename: &str,
) {
    generic_store_versioned_test(Versionize::versionize, msg, dir, test_filename)
}

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
            modulus_switch_noise_reduction_params: _,
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
            message_modulus: MessageModulus(message_modulus),
            carry_modulus: CarryModulus(carry_modulus),
            max_noise_level: MaxNoiseLevel::new(max_noise_level),
            log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
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
            message_modulus: MessageModulus(message_modulus),
            carry_modulus: CarryModulus(carry_modulus),
            max_noise_level: MaxNoiseLevel::new(max_noise_level),
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

impl ConvertParams<PBSParameters> for TestParameterSet {
    fn convert(self) -> PBSParameters {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                PBSParameters::PBS(test_classic_parameter_set.convert())
            }
            TestParameterSet::TestMultiBitParameterSet(test_parameter_set_multi_bit) => {
                PBSParameters::MultiBitPBS(test_parameter_set_multi_bit.convert())
            }
            TestParameterSet::TestKS32ParameterSet(_) => {
                panic!("unsupported ks32 parameters for version")
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
