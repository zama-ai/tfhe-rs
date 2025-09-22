use core::f64;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

#[cfg(feature = "load")]
use semver::{Prerelease, Version, VersionReq};
#[cfg(feature = "load")]
use std::fmt::Display;
use strum::Display;

use serde::{Deserialize, Serialize};

#[cfg(feature = "generate")]
pub mod data_0_10;
#[cfg(feature = "generate")]
pub mod data_0_11;
#[cfg(feature = "generate")]
pub mod data_0_8;
#[cfg(feature = "generate")]
pub mod data_1_0;
#[cfg(feature = "generate")]
pub mod data_1_1;
#[cfg(feature = "generate")]
pub mod data_1_3;
#[cfg(feature = "generate")]
pub mod generate;
#[cfg(feature = "load")]
pub mod load;

const DATA_DIR: &str = "data";

pub const SHORTINT_MODULE_NAME: &str = "shortint";
pub const HL_MODULE_NAME: &str = "high_level_api";
pub const ZK_MODULE_NAME: &str = "zk";

/// This struct re-defines tfhe-rs parameter sets but this allows to be independent of changes made
/// into the  ParameterSet of tfhe-rs.
///
/// The idea here is to define a type that is able to carry the information of the used parameters
/// without using any tfhe-rs types.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestParameterSet {
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
    pub modulus_switch_noise_reduction_params: Option<TestModulusSwitchNoiseReductionParams>,
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
    pub packing_ks_key_noise_distribution: TestDistribution,
}

/// Representation of a random distribution that is independent from any tfhe-rs version
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TestDistribution {
    Gaussian { stddev: f64 },
    TUniform { bound_log2: u32 },
}

pub fn dir_for_version<P: AsRef<Path>>(data_dir: P, version: &str) -> PathBuf {
    let mut path = data_dir.as_ref().to_path_buf();
    path.push(version.replace('.', "_"));

    path
}

pub fn data_dir<P: AsRef<Path>>(root: P) -> PathBuf {
    let mut path = PathBuf::from(root.as_ref());
    path.push(DATA_DIR);

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

    #[cfg(feature = "load")]
    fn success(&self, format: load::DataFormat) -> load::TestSuccess {
        load::TestSuccess {
            module: self.module(),
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            format,
        }
    }

    #[cfg(feature = "load")]
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
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Testcase {
    pub tfhe_version_min: String,
    pub tfhe_module: String,
    pub metadata: TestMetadata,
}

#[cfg(feature = "load")]
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
