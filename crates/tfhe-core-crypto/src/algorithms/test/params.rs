use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{CastFrom, CastInto, UnsignedInteger};
use crate::keycache::NamedParam;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassicBootstrapKeys<Scalar: UnsignedInteger> {
    pub small_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub big_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub bsk: LweBootstrapKeyOwned<Scalar>,
    pub fbsk: FourierLweBootstrapKeyOwned,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultiBitBootstrapKeys<Scalar: UnsignedInteger> {
    pub small_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub big_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub bsk: LweMultiBitBootstrapKeyOwned<Scalar>,
    pub fbsk: FourierLweMultiBitBootstrapKeyOwned,
}

// Fourier key is generated afterward in order to use generic test function
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FftBootstrapKeys<Scalar: UnsignedInteger> {
    pub small_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub big_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub bsk: LweBootstrapKeyOwned<Scalar>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FftWopPbsKeys<Scalar: UnsignedInteger> {
    pub small_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub big_lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub fbsk: FourierLweBootstrapKeyOwned,
    pub lwe_pfpksk: LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>,
}

// Fourier key is generated afterward in order to use generic test function
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackingKeySwitchKeys<Scalar: UnsignedInteger> {
    pub lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub glwe_sk: GlweSecretKey<Vec<Scalar>>,
    pub pksk: LwePackingKeyswitchKeyOwned<Scalar>,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassicTestParams<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub pfks_noise_distribution: DynamicDistribution<Scalar>,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub message_modulus_log: MessageModulusLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MultiBitTestParams<Scalar: UnsignedInteger> {
    pub input_lwe_dimension: LweDimension,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub message_modulus_log: MessageModulusLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
    pub grouping_factor: LweBskGroupingFactor,
    pub thread_count: ThreadCount,
}

// PartialEq is implemented manually because thread_count doesn't affect key generation and we want
// to change its value in test without the need of regenerating keys in the key cache.
impl<Scalar: UnsignedInteger> PartialEq for MultiBitTestParams<Scalar> {
    fn eq(&self, other: &Self) -> bool {
        self.input_lwe_dimension == other.input_lwe_dimension
            && self.lwe_noise_distribution == other.lwe_noise_distribution
            && self.decomp_base_log == other.decomp_base_log
            && self.decomp_level_count == other.decomp_level_count
            && self.glwe_dimension == other.glwe_dimension
            && self.polynomial_size == other.polynomial_size
            && self.glwe_noise_distribution == other.glwe_noise_distribution
            && self.message_modulus_log == other.message_modulus_log
            && self.ciphertext_modulus == other.ciphertext_modulus
            && self.grouping_factor == other.grouping_factor
    }
}

// Parameters to test FFT implementation
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct FftTestParams<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

// Parameters to test FFT implementation on wopPBS
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FftWopPbsTestParams<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PackingKeySwitchTestParams<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub message_modulus_log: MessageModulusLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger + CastFrom<usize> + CastInto<usize>> From<ClassicTestParams<Scalar>>
    for PackingKeySwitchTestParams<Scalar>
{
    fn from(params: ClassicTestParams<Scalar>) -> Self {
        Self {
            lwe_dimension: params.lwe_dimension,
            glwe_dimension: params.glwe_dimension,
            polynomial_size: params.polynomial_size,
            lwe_noise_distribution: params.lwe_noise_distribution,
            glwe_noise_distribution: params.glwe_noise_distribution,
            pbs_base_log: params.pbs_base_log,
            pbs_level: params.pbs_level,
            message_modulus_log: params.message_modulus_log,
            ciphertext_modulus: params.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger> NamedParam for ClassicTestParams<Scalar> {
    fn name(&self) -> String {
        format!(
                "PARAM_LWE_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_lwe_dim_{}_ct_modulus_{}_msg_modulus_{}",
                self.glwe_dimension.0, self.polynomial_size.0, self.pbs_base_log.0, self.pbs_level.0,
                self.lwe_dimension.0, self.ciphertext_modulus, self.message_modulus_log.0
            )
    }
}

impl<Scalar: UnsignedInteger> NamedParam for MultiBitTestParams<Scalar> {
    fn name(&self) -> String {
        format!(
                "PARAM_LWE_MULTI_BIT_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_input_dim_{}_ct_modulus_{}_msg_modulus_log_{}_group_factor_{}",
                self.glwe_dimension.0, self.polynomial_size.0, self.decomp_base_log.0,
                self.decomp_level_count.0, self.input_lwe_dimension.0, self.ciphertext_modulus, self.message_modulus_log.0,
                self.grouping_factor.0,
            )
    }
}

impl<Scalar: UnsignedInteger> NamedParam for FftTestParams<Scalar> {
    fn name(&self) -> String {
        format!(
                "PARAM_FFT_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_lwe_dim_{}_ct_modulus_{}_lwe_std_dev_{}_glwe_std_dev_{}",
                self.glwe_dimension.0, self.polynomial_size.0, self.pbs_base_log.0,
                self.pbs_level.0,
                self.lwe_dimension.0, self.ciphertext_modulus, self.lwe_noise_distribution,
                self.glwe_noise_distribution,
            )
    }
}

impl<Scalar: UnsignedInteger> NamedParam for FftWopPbsTestParams<Scalar> {
    fn name(&self) -> String {
        format!(
                "PARAM_FFT_WOPBS_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_lwe_dim_{}_ct_modulus_{}_pfks_level_{}_pfks_base_log_{}_cbs_level_{}_cbs_base_log_{}",
                self.glwe_dimension.0, self.polynomial_size.0, self.pbs_base_log.0,
                self.pbs_level.0,
                self.lwe_dimension.0, self.ciphertext_modulus, self.pfks_level.0, self.pfks_base_log.0,
                self.cbs_level.0, self.cbs_base_log.0,
            )
    }
}

impl<Scalar: UnsignedInteger> NamedParam for PackingKeySwitchTestParams<Scalar> {
    fn name(&self) -> String {
        format!(
                "PARAM_PKS_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_lwe_dim_{}_ct_modulus_{}_lwe_std_dev_{}_glwe_std_dev_{}",
                self.glwe_dimension.0, self.polynomial_size.0, self.pbs_base_log.0,
                self.pbs_level.0,
                self.lwe_dimension.0, self.ciphertext_modulus, self.lwe_noise_distribution,
                self.glwe_noise_distribution,
            )
    }
}
