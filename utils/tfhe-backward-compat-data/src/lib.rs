pub mod generate;
pub mod load;

use core::f64;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

use semver::{Prerelease, Version, VersionReq};
use std::fmt::Display;
use strum::Display;

use serde::{Deserialize, Serialize};

pub const SHORTINT_MODULE_NAME: &str = "shortint";
pub const HL_MODULE_NAME: &str = "high_level_api";
pub const ZK_MODULE_NAME: &str = "zk";

/// This struct re-defines tfhe-rs parameter sets but this allows to be independent of changes made
/// into the  ParameterSet of tfhe-rs.
///
/// The idea here is to define a type that is able to carry the information of the used parameters
/// without using any tfhe-rs types.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestClassicParameterSet {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_distribution: TestDistribution,
    pub glwe_noise_distribution: TestDistribution,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: usize,
    pub ciphertext_modulus: u128,
    pub carry_modulus: usize,
    pub max_noise_level: usize,
    pub log2_p_fail: f64,
    pub encryption_key_choice: Cow<'static, str>,
    pub modulus_switch_noise_reduction_params: TestModulusSwitchType,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestMultiBitParameterSet {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_distribution: TestDistribution,
    pub glwe_noise_distribution: TestDistribution,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: usize,
    pub ciphertext_modulus: u128,
    pub carry_modulus: usize,
    pub max_noise_level: usize,
    pub log2_p_fail: f64,
    pub encryption_key_choice: Cow<'static, str>,
    pub grouping_factor: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestKS32ParameterSet {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_distribution: TestDistribution,
    pub glwe_noise_distribution: TestDistribution,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: usize,
    pub ciphertext_modulus: u128,
    pub carry_modulus: usize,
    pub max_noise_level: usize,
    pub log2_p_fail: f64,
    pub modulus_switch_noise_reduction_params: TestModulusSwitchType,
    pub post_keyswitch_ciphertext_modulus: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestModulusSwitchNoiseReductionParams {
    pub modulus_switch_zeros_count: usize,
    pub ms_bound: f64,
    pub ms_r_sigma_factor: f64,
    pub ms_input_variance: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TestModulusSwitchType {
    Standard,
    DriftTechniqueNoiseReduction(TestModulusSwitchNoiseReductionParams),
    CenteredMeanNoiseReduction,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestNoiseSquashingParams {
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub glwe_noise_distribution: TestDistribution,
    pub decomp_base_log: usize,
    pub decomp_level_count: usize,
    pub modulus_switch_noise_reduction_params: TestModulusSwitchType,
    pub message_modulus: usize,
    pub carry_modulus: usize,
    pub ciphertext_modulus: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestNoiseSquashingParamsMultiBit {
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub glwe_noise_distribution: TestDistribution,
    pub decomp_base_log: usize,
    pub decomp_level_count: usize,
    pub grouping_factor: usize,
    pub message_modulus: usize,
    pub carry_modulus: usize,
    pub ciphertext_modulus: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestNoiseSquashingCompressionParameters {
    pub packing_ks_level: usize,
    pub packing_ks_base_log: usize,
    pub packing_ks_polynomial_size: usize,
    pub packing_ks_glwe_dimension: usize,
    pub lwe_per_glwe: usize,
    pub packing_ks_key_noise_distribution: TestDistribution,
    pub message_modulus: usize,
    pub carry_modulus: usize,
    pub ciphertext_modulus: u128,
}

/// This struct re-defines tfhe-rs compression parameter sets but this allows to be independent of
/// changes made into the ParameterSet of tfhe-rs.
///
/// The idea here is to define a type that is able to carry the information of the used parameters
/// without using any tfhe-rs types.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestCompressionParameterSet {
    pub br_level: usize,
    pub br_base_log: usize,
    pub packing_ks_level: usize,
    pub packing_ks_base_log: usize,
    pub packing_ks_polynomial_size: usize,
    pub packing_ks_glwe_dimension: usize,
    pub lwe_per_glwe: usize,
    pub storage_log_modulus: usize,
    pub decompression_grouping_factor: Option<usize>,
    pub packing_ks_key_noise_distribution: TestDistribution,
}

/// Representation of a random distribution that is independent from any tfhe-rs version
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum TestDistribution {
    Gaussian { stddev: f64 },
    TUniform { bound_log2: u32 },
}

/// Re-definition of keyswitch parameters
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestKeySwitchingParams {
    pub ks_level: usize,
    pub ks_base_log: usize,
    pub destination_key: Cow<'static, str>,
}

/// Re-definition of cpk parameters
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestCompactPublicKeyEncryptionParameters {
    pub encryption_lwe_dimension: usize,
    pub encryption_noise_distribution: TestDistribution,
    pub message_modulus: usize,
    pub carry_modulus: usize,
    pub ciphertext_modulus: u128,
    pub expansion_kind: Cow<'static, str>,
    pub zk_scheme: Cow<'static, str>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestDedicatedCompactPublicKeyParameters {
    pub pke_params: TestCompactPublicKeyEncryptionParameters,
    pub ksk_params: TestKeySwitchingParams,
    pub re_randomization_parameters: Option<TestKeySwitchingParams>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestMetaNoiseSquashingParameters {
    pub parameters: TestNoiseSquashingParams,
    pub compression_parameters: Option<TestNoiseSquashingCompressionParameters>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TestReRandomizationConfiguration {
    LegacyDedicatedCompactPublicKeyWithKeySwitch,
    DerivedCompactPublicKeyWithoutKeySwitch,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestMetaParameters {
    pub compute_parameters: TestParameterSet,
    pub dedicated_compact_public_key_parameters: Option<TestDedicatedCompactPublicKeyParameters>,
    pub compression_parameters: Option<TestCompressionParameterSet>,
    pub noise_squashing_parameters: Option<TestMetaNoiseSquashingParameters>,
    pub rerand_configuration: Option<TestReRandomizationConfiguration>,
}

pub fn dir_for_version<P: AsRef<Path>>(data_dir: P, version: &str) -> PathBuf {
    let mut path = data_dir.as_ref().to_path_buf();
    path.push(version.replace('.', "_"));

    path
}

pub trait TestType {
    /// The tfhe-rs module where this type reside
    fn module(&self) -> String;

    /// The Type that is tested
    fn target_type(&self) -> String;

    /// The name of the file to be tested, without path or extension
    /// (they will be inferred)
    fn test_filename(&self) -> String;

    fn success(&self, format: load::DataFormat) -> load::TestSuccess {
        load::TestSuccess {
            module: self.module(),
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            format,
        }
    }

    fn failure<E: Display>(&self, error: E, format: load::DataFormat) -> load::TestFailure {
        load::TestFailure {
            module: self.module(),
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            source_error: format!("{}", error),
            format,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShortintClientKeyTest {
    pub test_filename: Cow<'static, str>,
    pub parameters: TestParameterSet,
}

impl TestType for ShortintClientKeyTest {
    fn module(&self) -> String {
        SHORTINT_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ClientKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShortintCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_value: u64,
}

impl TestType for ShortintCiphertextTest {
    fn module(&self) -> String {
        SHORTINT_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "Ciphertext".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlClientKeyTest {
    pub test_filename: Cow<'static, str>,
    pub parameters: TestParameterSet,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TestParameterSet {
    TestClassicParameterSet(TestClassicParameterSet),
    TestMultiBitParameterSet(TestMultiBitParameterSet),
    TestKS32ParameterSet(TestKS32ParameterSet),
}

#[allow(dead_code)]
impl TestParameterSet {
    pub const fn from_classic(value: TestClassicParameterSet) -> Self {
        Self::TestClassicParameterSet(value)
    }
    pub const fn from_multi(value: TestMultiBitParameterSet) -> Self {
        Self::TestMultiBitParameterSet(value)
    }

    pub const fn polynomial_size(&self) -> usize {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                test_classic_parameter_set.polynomial_size
            }
            TestParameterSet::TestMultiBitParameterSet(test_multi_bit_parameter_set) => {
                test_multi_bit_parameter_set.polynomial_size
            }
            TestParameterSet::TestKS32ParameterSet(test_ks32_parameter_set) => {
                test_ks32_parameter_set.polynomial_size
            }
        }
    }

    pub const fn glwe_dimension(&self) -> usize {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                test_classic_parameter_set.glwe_dimension
            }
            TestParameterSet::TestMultiBitParameterSet(test_multi_bit_parameter_set) => {
                test_multi_bit_parameter_set.glwe_dimension
            }
            TestParameterSet::TestKS32ParameterSet(test_ks32_parameter_set) => {
                test_ks32_parameter_set.glwe_dimension
            }
        }
    }

    pub const fn lwe_noise_distribution(&self) -> TestDistribution {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                test_classic_parameter_set.lwe_noise_distribution
            }
            TestParameterSet::TestMultiBitParameterSet(test_multi_bit_parameter_set) => {
                test_multi_bit_parameter_set.lwe_noise_distribution
            }
            TestParameterSet::TestKS32ParameterSet(test_ks32_parameter_set) => {
                test_ks32_parameter_set.lwe_noise_distribution
            }
        }
    }

    pub const fn ciphertext_modulus(&self) -> u128 {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                test_classic_parameter_set.ciphertext_modulus
            }
            TestParameterSet::TestMultiBitParameterSet(test_multi_bit_parameter_set) => {
                test_multi_bit_parameter_set.ciphertext_modulus
            }
            TestParameterSet::TestKS32ParameterSet(test_ks32_parameter_set) => {
                test_ks32_parameter_set.ciphertext_modulus
            }
        }
    }

    pub const fn message_modulus(&self) -> usize {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                test_classic_parameter_set.message_modulus
            }
            TestParameterSet::TestMultiBitParameterSet(test_multi_bit_parameter_set) => {
                test_multi_bit_parameter_set.message_modulus
            }
            TestParameterSet::TestKS32ParameterSet(test_ks32_parameter_set) => {
                test_ks32_parameter_set.message_modulus
            }
        }
    }

    pub const fn carry_modulus(&self) -> usize {
        match self {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                test_classic_parameter_set.carry_modulus
            }
            TestParameterSet::TestMultiBitParameterSet(test_multi_bit_parameter_set) => {
                test_multi_bit_parameter_set.carry_modulus
            }
            TestParameterSet::TestKS32ParameterSet(test_ks32_parameter_set) => {
                test_ks32_parameter_set.carry_modulus
            }
        }
    }
}

impl TestType for HlClientKeyTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ClientKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlServerKeyTest {
    pub test_filename: Cow<'static, str>,
    pub client_key_filename: Cow<'static, str>,
    pub rerand_cpk_filename: Option<Cow<'static, str>>,
    pub compressed: bool,
}

impl TestType for HlServerKeyTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ServerKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlPublicKeyTest {
    pub test_filename: Cow<'static, str>,
    pub client_key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub compact: bool,
}

impl TestType for HlPublicKeyTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PublicKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub clear_value: u64,
}

impl TestType for HlCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheUint".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlSignedCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub clear_value: i64,
}

impl TestType for HlSignedCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheInt".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlBoolCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub clear_value: bool,
}

impl TestType for HlBoolCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheBool".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum DataKind {
    Bool,
    Signed,
    Unsigned,
}

/// Info needed to be able to verify a pke proven compact list
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PkeZkProofAuxiliaryInfo {
    pub public_key_filename: Cow<'static, str>,
    pub params_filename: Cow<'static, str>,
    pub metadata: Cow<'static, str>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlHeterogeneousCiphertextListTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub proof_info: Option<PkeZkProofAuxiliaryInfo>,
    pub clear_values: Cow<'static, [u64]>,
    pub data_kinds: Cow<'static, [DataKind]>,
}

impl TestType for HlHeterogeneousCiphertextListTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "CompactCiphertextList".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlCompressedSquashedNoiseCiphertextListTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_values: Cow<'static, [u64]>,
    pub data_kinds: Cow<'static, [DataKind]>,
}

impl TestType for HlCompressedSquashedNoiseCiphertextListTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "SquashedNoiseCiphertextList".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlSquashedNoiseUnsignedCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_value: u64,
}

impl TestType for HlSquashedNoiseUnsignedCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "SquashedNoiseFheUint".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlSquashedNoiseSignedCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_value: i64,
}

impl TestType for HlSquashedNoiseSignedCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "SquashedNoiseFheInt".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlSquashedNoiseBoolCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_value: bool,
}

impl TestType for HlSquashedNoiseBoolCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "SquashedNoiseFheBool".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkPkePublicParamsTest {
    pub test_filename: Cow<'static, str>,
    pub lwe_dimension: usize,
    pub max_num_cleartext: usize,
    pub noise_bound: usize,
    pub ciphertext_modulus: u128,
    pub plaintext_modulus: usize,
    pub padding_bit_count: usize,
}

impl TestType for ZkPkePublicParamsTest {
    fn module(&self) -> String {
        ZK_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "CompactPkePublicParams".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlCompressedKVStoreTest {
    pub kv_store_file_name: Cow<'static, str>,
    pub client_key_file_name: Cow<'static, str>,
    pub server_key_file_name: Cow<'static, str>,
    pub num_elements: usize,
}

impl TestType for HlCompressedKVStoreTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "CompressedKVStore".to_string()
    }

    fn test_filename(&self) -> String {
        self.kv_store_file_name.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlCompressedXofKeySetTest {
    pub compressed_xof_key_set_file_name: Cow<'static, str>,
    pub client_key_file_name: Cow<'static, str>,
}

impl TestType for HlCompressedXofKeySetTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "CompressedXofKeySet".to_string()
    }

    fn test_filename(&self) -> String {
        self.compressed_xof_key_set_file_name.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadata {
    // Shortint
    ShortintCiphertext(ShortintCiphertextTest),
    ShortintClientKey(ShortintClientKeyTest),

    // Hl
    HlCiphertext(HlCiphertextTest),
    HlSignedCiphertext(HlSignedCiphertextTest),
    HlBoolCiphertext(HlBoolCiphertextTest),
    HlHeterogeneousCiphertextList(HlHeterogeneousCiphertextListTest),
    HlClientKey(HlClientKeyTest),
    HlServerKey(HlServerKeyTest),
    HlPublicKey(HlPublicKeyTest),
    ZkPkePublicParams(ZkPkePublicParamsTest), /* We place it in the hl folder since it is
                                               * currently used with hl tests: */
    HlSquashedNoiseUnsignedCiphertext(HlSquashedNoiseUnsignedCiphertextTest),
    HlSquashedNoiseSignedCiphertext(HlSquashedNoiseSignedCiphertextTest),
    HlSquashedNoiseBoolCiphertext(HlSquashedNoiseBoolCiphertextTest),
    HlCompressedSquashedNoiseCiphertextList(HlCompressedSquashedNoiseCiphertextListTest),
    HlCompressedKVStoreTest(HlCompressedKVStoreTest),
    HlCompressedXofKeySet(HlCompressedXofKeySetTest),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Testcase {
    pub tfhe_version_min: String,
    pub tfhe_module: String,
    pub metadata: TestMetadata,
}

impl Testcase {
    pub fn is_valid_for_version(&self, version: &str) -> bool {
        let mut tfhe_version = Version::parse(version).unwrap();

        // Removes the pre-release tag because matches will always return
        tfhe_version.pre = Prerelease::EMPTY;

        let req = format!(">={}", self.tfhe_version_min);
        let min_version = VersionReq::parse(&req).unwrap();

        min_version.matches(&tfhe_version)
    }

    pub fn skip(&self) -> load::TestSkipped {
        load::TestSkipped {
            module: self.tfhe_module.to_string(),
            test_name: self.metadata.to_string(),
        }
    }
}
