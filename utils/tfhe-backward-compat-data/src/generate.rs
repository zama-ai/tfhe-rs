use std::borrow::Cow;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use bincode::Options;
use semver::Version;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::*;

pub const PRNG_SEED: u128 = 0xdeadbeef;

/// Valid parameter set that can be used in tfhe operations
pub const VALID_TEST_PARAMS: TestParameterSet =
    TestParameterSet::TestClassicParameterSet(TestClassicParameterSet {
        lwe_dimension: 761,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::Gaussian {
            stddev: 6.36835566258815e-06,
        },
        glwe_noise_distribution: TestDistribution::Gaussian {
            stddev: 3.1529322391500584e-16,
        },
        pbs_base_log: 23,
        pbs_level: 1,
        ks_base_log: 3,
        ks_level: 5,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -40.05,
        ciphertext_modulus: 1 << 64,
        encryption_key_choice: Cow::Borrowed("big"),
        modulus_switch_noise_reduction_params: TestModulusSwitchType::Standard,
    });

pub const VALID_TEST_PARAMS_TUNIFORM: TestParameterSet =
    TestParameterSet::TestClassicParameterSet(TestClassicParameterSet {
        lwe_dimension: 887,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 46 },
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
        pbs_base_log: 22,
        pbs_level: 1,
        ks_base_log: 3,
        ks_level: 5,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -64.138,
        ciphertext_modulus: 1 << 64,
        encryption_key_choice: Cow::Borrowed("big"),
        modulus_switch_noise_reduction_params: TestModulusSwitchType::Standard,
    });

pub const VALID_TEST_PARAMS_KS32_TUNIFORM: TestParameterSet =
    TestParameterSet::TestKS32ParameterSet(TestKS32ParameterSet {
        lwe_dimension: 918,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 13 },
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
        pbs_base_log: 23,
        pbs_level: 1,
        ks_base_log: 4,
        ks_level: 4,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -129.358380844,
        ciphertext_modulus: 1 << 64,
        modulus_switch_noise_reduction_params: TestModulusSwitchType::DriftTechniqueNoiseReduction(
            TestModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: 1449,
                ms_bound: 67108864f64,
                ms_r_sigma_factor: 13.179851302864899f64,
                ms_input_variance: 2.63039392929833E-7f64,
            },
        ),
        post_keyswitch_ciphertext_modulus: 1 << 32,
    });

/// Those parameters are insecure and are used to generate small legacy public keys
pub const INSECURE_SMALL_PK_TEST_PARAMS: TestParameterSet =
    TestParameterSet::TestClassicParameterSet(TestClassicParameterSet {
        lwe_dimension: 10,
        glwe_dimension: 4,
        polynomial_size: 512,
        lwe_noise_distribution: TestDistribution::Gaussian {
            stddev: 1.499_900_593_439_687_3e-6,
        },
        glwe_noise_distribution: TestDistribution::Gaussian {
            stddev: 2.845267479601915e-15,
        },
        pbs_base_log: 23,
        pbs_level: 1,
        ks_base_log: 5,
        ks_level: 3,
        message_modulus: 2,
        carry_modulus: 2,
        max_noise_level: 3,
        log2_p_fail: -64.05,
        ciphertext_modulus: 1 << 64,
        encryption_key_choice: Cow::Borrowed("small"),
        modulus_switch_noise_reduction_params: TestModulusSwitchType::Standard,
    });

/// Those parameters are insecure and are used to generate small legacy public keys
pub const INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION: TestParameterSet =
    TestParameterSet::TestClassicParameterSet(TestClassicParameterSet {
        lwe_dimension: 2,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 45 },
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
        pbs_base_log: 23,
        pbs_level: 1,
        ks_base_log: 4,
        ks_level: 4,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -129.15284804376165,
        ciphertext_modulus: 1 << 64,
        encryption_key_choice: Cow::Borrowed("big"),
        modulus_switch_noise_reduction_params: TestModulusSwitchType::DriftTechniqueNoiseReduction(
            TestModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: 2,
                ms_bound: 288230376151711744f64,
                ms_r_sigma_factor: 13.179852282053789f64,
                ms_input_variance: 2.63039184094559e-7f64,
            },
        ),
    });

/// Same as [`INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION`] but with lwe_dimension bumped to 64
pub const INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION_LWE_DIM_64: TestParameterSet =
    TestParameterSet::TestClassicParameterSet(TestClassicParameterSet {
        lwe_dimension: 64,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 45 },
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
        pbs_base_log: 23,
        pbs_level: 1,
        ks_base_log: 4,
        ks_level: 4,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -129.15284804376165,
        ciphertext_modulus: 1 << 64,
        encryption_key_choice: Cow::Borrowed("big"),
        modulus_switch_noise_reduction_params: TestModulusSwitchType::DriftTechniqueNoiseReduction(
            TestModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: 2,
                ms_bound: 288230376151711744f64,
                ms_r_sigma_factor: 13.179852282053789f64,
                ms_input_variance: 2.63039184094559e-7f64,
            },
        ),
    });

/// Those parameters are insecure and are used to generate small legacy public keys
pub const INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION: TestParameterSet =
    TestParameterSet::TestClassicParameterSet(TestClassicParameterSet {
        lwe_dimension: 2,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 45 },
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
        pbs_base_log: 23,
        pbs_level: 1,
        ks_base_log: 4,
        ks_level: 4,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -129.15284804376165,
        ciphertext_modulus: 1 << 64,
        encryption_key_choice: Cow::Borrowed("big"),
        modulus_switch_noise_reduction_params: TestModulusSwitchType::CenteredMeanNoiseReduction,
    });

/// Those parameters are insecure and are used to generate small legacy public keys
pub const INSECURE_SMALL_TEST_PARAMS_MULTI_BIT: TestParameterSet =
    TestParameterSet::from_multi(TestMultiBitParameterSet {
        lwe_dimension: 4,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 45 },
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
        pbs_base_log: 22,
        pbs_level: 1,
        ks_base_log: 3,
        ks_level: 5,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -134.345,
        ciphertext_modulus: 1 << 64,
        encryption_key_choice: Cow::Borrowed("big"),
        grouping_factor: 4,
    });

/// Those parameters are insecure and are used to generate small legacy public keys
/// Got with the above parameters for noise squashing
pub const INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION: TestNoiseSquashingParams =
    TestNoiseSquashingParams {
        glwe_dimension: 2,
        polynomial_size: 2048,
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 30 },
        decomp_base_log: 24,
        decomp_level_count: 3,
        modulus_switch_noise_reduction_params: TestModulusSwitchType::DriftTechniqueNoiseReduction(
            TestModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: 2,
                ms_bound: 288230376151711744f64,
                ms_r_sigma_factor: 13.179852282053789f64,
                ms_input_variance: 2.63039184094559e-7f64,
            },
        ),
        message_modulus: 4,
        carry_modulus: 4,
        // 0 interpreted as native modulus for u128
        ciphertext_modulus: 0,
    };

pub const TEST_PARAMS_NOISE_SQUASHING_COMPRESSION: TestNoiseSquashingCompressionParameters =
    TestNoiseSquashingCompressionParameters {
        packing_ks_level: 1,
        packing_ks_base_log: 61,
        packing_ks_polynomial_size: 1024,
        packing_ks_glwe_dimension: 6,
        lwe_per_glwe: 128,
        packing_ks_key_noise_distribution: TestDistribution::TUniform { bound_log2: 3 },
        message_modulus: 4,
        carry_modulus: 4,
        ciphertext_modulus: 0, // native modulus for u128
    };

pub const INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MULTI_BIT: TestNoiseSquashingParamsMultiBit =
    TestNoiseSquashingParamsMultiBit {
        glwe_dimension: 2,
        polynomial_size: 2048,
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 30 },
        decomp_base_log: 23,
        decomp_level_count: 3,
        grouping_factor: 4,
        message_modulus: 4,
        carry_modulus: 4,
        // 0 interpreted as native modulus for u128
        ciphertext_modulus: 0,
    };

pub const INSECURE_SMALL_TEST_PARAMS_KS32: TestParameterSet =
    TestParameterSet::TestKS32ParameterSet(TestKS32ParameterSet {
        lwe_dimension: 2,
        glwe_dimension: 1,
        polynomial_size: 2048,
        lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 13 },
        glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
        pbs_base_log: 23,
        pbs_level: 1,
        ks_base_log: 4,
        ks_level: 4,
        message_modulus: 4,
        carry_modulus: 4,
        max_noise_level: 5,
        log2_p_fail: -129.15284804376165,
        ciphertext_modulus: 1 << 64,
        modulus_switch_noise_reduction_params: TestModulusSwitchType::CenteredMeanNoiseReduction,
        post_keyswitch_ciphertext_modulus: 1 << 32,
    });

// Compression parameters for 2_2 TUniform
pub const VALID_TEST_PARAMS_TUNIFORM_COMPRESSION: TestCompressionParameterSet =
    TestCompressionParameterSet {
        br_level: 1,
        br_base_log: 23,
        packing_ks_level: 4,
        packing_ks_base_log: 4,
        packing_ks_polynomial_size: 256,
        packing_ks_glwe_dimension: 4,
        lwe_per_glwe: 256,
        storage_log_modulus: 12,
        packing_ks_key_noise_distribution: TestDistribution::TUniform { bound_log2: 42 },
        decompression_grouping_factor: None,
    };

pub const INSECURE_TEST_PARAMS_TUNIFORM_COMPRESSION_MULTIBIT: TestCompressionParameterSet =
    TestCompressionParameterSet {
        br_level: 1,
        br_base_log: 22,
        packing_ks_level: 3,
        packing_ks_base_log: 4,
        packing_ks_polynomial_size: 256,
        packing_ks_glwe_dimension: 1,
        lwe_per_glwe: 256,
        storage_log_modulus: 12,
        packing_ks_key_noise_distribution: TestDistribution::TUniform { bound_log2: 43 },
        decompression_grouping_factor: Some(4),
    };

/// Invalid parameter set to test the limits
pub const INVALID_TEST_PARAMS: TestClassicParameterSet = TestClassicParameterSet {
    lwe_dimension: usize::MAX,
    glwe_dimension: usize::MAX,
    polynomial_size: usize::MAX,
    lwe_noise_distribution: TestDistribution::Gaussian { stddev: f64::MAX },
    glwe_noise_distribution: TestDistribution::Gaussian { stddev: f64::MAX },
    pbs_base_log: usize::MAX,
    pbs_level: usize::MAX,
    ks_base_log: usize::MAX,
    ks_level: usize::MAX,
    message_modulus: usize::MAX,
    carry_modulus: usize::MAX,
    max_noise_level: usize::MAX,
    log2_p_fail: f64::MAX,
    ciphertext_modulus: u128::MAX,
    encryption_key_choice: Cow::Borrowed("big"),
    modulus_switch_noise_reduction_params: TestModulusSwitchType::Standard,
};

pub const KS_TO_SMALL_TEST_PARAMS: TestKeySwitchingParams = TestKeySwitchingParams {
    ks_level: 5,
    ks_base_log: 3,
    destination_key: Cow::Borrowed("small"),
};

/// Parameters used to create a rerand key
pub const KS_TO_BIG_TEST_PARAMS: TestKeySwitchingParams = TestKeySwitchingParams {
    ks_level: 1,
    ks_base_log: 27,
    destination_key: Cow::Borrowed("big"),
};

pub const INSECURE_DEDICATED_CPK_TEST_PARAMS: TestCompactPublicKeyEncryptionParameters =
    TestCompactPublicKeyEncryptionParameters {
        encryption_lwe_dimension: 32,
        encryption_noise_distribution: TestDistribution::TUniform { bound_log2: 42 },
        message_modulus: 4,
        carry_modulus: 4,
        ciphertext_modulus: 1 << 64,
        expansion_kind: Cow::Borrowed("requires_casting"),
        zk_scheme: Cow::Borrowed("zkv2"),
    };

pub const INSECURE_TEST_META_PARAMS: TestMetaParameters = TestMetaParameters {
    compute_parameters: INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION_LWE_DIM_64,
    dedicated_compact_public_key_parameters: Some(TestDedicatedCompactPublicKeyParameters {
        pke_params: INSECURE_DEDICATED_CPK_TEST_PARAMS,
        ksk_params: KS_TO_SMALL_TEST_PARAMS,
        re_randomization_parameters: Some(KS_TO_BIG_TEST_PARAMS),
    }),
    compression_parameters: Some(VALID_TEST_PARAMS_TUNIFORM_COMPRESSION),
    noise_squashing_parameters: Some(TestMetaNoiseSquashingParameters {
        parameters: INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION,
        compression_parameters: Some(TEST_PARAMS_NOISE_SQUASHING_COMPRESSION),
    }),
};
pub fn save_cbor<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    let path = path.as_ref();
    if path.exists() {
        panic!(
            "Error while saving {}, file already exists, \
            indicating an error in the test file organization.",
            path.display()
        );
    }
    let mut file = File::create(path).unwrap();
    ciborium::ser::into_writer(msg, &mut file).unwrap();
}

pub fn save_bcode<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    let path = path.as_ref();
    if path.exists() {
        panic!(
            "Error while saving {}, file already exists, \
            indicating an error in the test file organization.",
            path.display()
        );
    }

    let mut file = File::create(path).unwrap();
    let options = bincode::DefaultOptions::new().with_fixint_encoding();
    options.serialize_into(&mut file, msg).unwrap();
}

/// Stores the test data in `dir`, encoded in both cbor and bincode, using the provided versionize
/// function
pub fn generic_store_versioned_test<'a, Data: 'a, Vers: Serialize + 'a, P: AsRef<Path>>(
    versionize: impl FnOnce(&'a Data) -> Vers,
    msg: &'a Data,
    dir: P,
    test_filename: &str,
) {
    let versioned = versionize(msg);

    // Store in cbor
    let filename_cbor = format!("{}.cbor", test_filename);
    save_cbor(&versioned, dir.as_ref().join(filename_cbor));

    // Store in bincode
    let filename_bincode = format!("{}.bcode", test_filename);
    save_bcode(&versioned, dir.as_ref().join(filename_bincode));
}

/// Stores the auxiliary data in `dir`, encoded in cbor, using the provided versionize function
pub fn generic_store_versioned_auxiliary<'a, Data: 'a, Vers: Serialize + 'a, P: AsRef<Path>>(
    versionize: impl FnOnce(&'a Data) -> Vers,
    msg: &'a Data,
    dir: P,
    test_filename: &str,
) {
    let versioned = versionize(msg);

    // Store in cbor
    let filename_cbor = format!("{}.cbor", test_filename);
    save_cbor(&versioned, dir.as_ref().join(filename_cbor));
}

/// Store the test metadata vec for all modules into specific ron files
pub fn store_metadata<P: AsRef<Path>>(testcases: Vec<Testcase>, base_data_dir: P) {
    let mut sorted: Vec<_> = testcases
        .iter()
        .map(|data| {
            let vers = major_minor_parse(&data.tfhe_version_min);
            (vers, data)
        })
        .collect();
    sorted.sort_by_key(|(vers, _)| vers.clone());
    let sorted = sorted.iter().map(|(_, data)| *data);

    let base_data_dir = base_data_dir.as_ref();
    let shortint_testcases: Vec<Testcase> = sorted
        .clone()
        .filter(|test| test.tfhe_module == SHORTINT_MODULE_NAME)
        .cloned()
        .collect();

    store_ron(
        &shortint_testcases,
        base_data_dir.join(format!("{SHORTINT_MODULE_NAME}.ron")),
    );

    let high_level_api_testcases: Vec<Testcase> = sorted
        .filter(|test| test.tfhe_module == HL_MODULE_NAME)
        .cloned()
        .collect();

    store_ron(
        &high_level_api_testcases,
        base_data_dir.join(format!("{HL_MODULE_NAME}.ron")),
    );
}

fn store_ron<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::ser::to_string_pretty(value, ron::ser::PrettyConfig::default()).unwrap();
    fs::write(path, serialized).unwrap();
}

fn load_ron<Meta: DeserializeOwned, P: AsRef<Path>>(path: P) -> Option<Meta> {
    File::open(path)
        .map(|f| ron::de::from_reader(f).unwrap())
        .ok()
}

/// Update the metadata with data for a specific version.
///
/// All the metadata in the vec should be for the same TFHE-rs version.
/// Old metadata for this version will be removed and replaced with new data.
/// Old metadata for the other versions will not be modified.
pub fn update_metadata_for_version<P: AsRef<Path>>(testcases: Vec<Testcase>, base_data_dir: P) {
    let base_data_dir = base_data_dir.as_ref();
    let shortint_testcases: Vec<Testcase> = testcases
        .iter()
        .filter(|test| test.tfhe_module == SHORTINT_MODULE_NAME)
        .cloned()
        .collect();

    update_metadata_for_version_and_module(
        &shortint_testcases,
        base_data_dir.join(format!("{SHORTINT_MODULE_NAME}.ron")),
    );

    let high_level_api_testcases: Vec<Testcase> = testcases
        .iter()
        .filter(|test| test.tfhe_module == HL_MODULE_NAME)
        .cloned()
        .collect();

    update_metadata_for_version_and_module(
        &high_level_api_testcases,
        base_data_dir.join(format!("{HL_MODULE_NAME}.ron")),
    );
}

pub fn display_metadata(testcases: &[Testcase]) {
    let serialized =
        ron::ser::to_string_pretty(testcases, ron::ser::PrettyConfig::default()).unwrap();

    println!("{serialized}")
}

pub fn load_metadata_from_str(data: &str) -> Vec<Testcase> {
    ron::from_str(data).unwrap()
}

/// Parse a version number where only the major/minor is provided
fn major_minor_parse(vers: &str) -> Version {
    Version::parse(&format!("{}.0", vers)).unwrap()
}

fn update_metadata_for_version_and_module<P: AsRef<Path>>(new_data: &[Testcase], path: P) {
    let loaded: Vec<Testcase> = load_ron(&path).unwrap_or(Vec::new());
    let Some(updated_vers) = new_data
        .first()
        .map(|data| major_minor_parse(&data.tfhe_version_min))
    else {
        return;
    };

    let parsed = loaded.iter().map(|data| {
        let vers = major_minor_parse(&data.tfhe_version_min);
        (vers, data)
    });

    let filtered = parsed.filter(|(vers, _)| vers != &updated_vers);

    let mut complete: Vec<_> = filtered
        .chain(new_data.iter().map(|data| {
            let vers = major_minor_parse(&data.tfhe_version_min);
            assert_eq!(
                updated_vers, vers,
                "update_metadata_for_version should be called with data from a single version.\n\
Expected {updated_vers}, got {vers}"
            );
            (vers, data)
        }))
        .collect();

    complete.sort_by_key(|(vers, _)| vers.clone());

    let sorted: Vec<_> = complete.into_iter().map(|(_, data)| data).collect();
    store_ron(&sorted, path);
}

/// Generates all the data for the provided version and returns the vec of metadata
pub fn gen_all_data<Vers: TfhersVersion>(base_data_dir: &Path) -> Vec<Testcase> {
    Vers::seed_prng(PRNG_SEED);

    let shortint_tests = Vers::gen_shortint_data(base_data_dir);

    let mut tests: Vec<Testcase> = shortint_tests
        .iter()
        .map(|metadata| Testcase {
            tfhe_version_min: Vers::VERSION_NUMBER.to_string(),
            tfhe_module: SHORTINT_MODULE_NAME.to_string(),
            metadata: metadata.clone(),
        })
        .collect();

    let hl_tests = Vers::gen_hl_data(base_data_dir);

    tests.extend(hl_tests.iter().map(|metadata| Testcase {
        tfhe_version_min: Vers::VERSION_NUMBER.to_string(),
        tfhe_module: HL_MODULE_NAME.to_string(),
        metadata: metadata.clone(),
    }));

    tests
}

pub trait TfhersVersion {
    const VERSION_NUMBER: &'static str;

    fn data_dir<P: AsRef<Path>>(base_data_dir: P) -> PathBuf {
        dir_for_version(base_data_dir, Self::VERSION_NUMBER)
    }

    /// How to fix the prng seed for this version to make sure the generated testcases do not change
    /// every time we run the script
    fn seed_prng(seed: u128);

    /// Generates data for the "shortint" module for this version.
    /// This should create tfhe-rs shortint types, versionize them and store them into the version
    /// specific directory. The metadata for the generated tests should be returned in the same
    /// order that the tests will be run.
    fn gen_shortint_data<P: AsRef<Path>>(base_data_dir: P) -> Vec<TestMetadata>;

    /// Generates data for the "high_level_api" module for this version.
    /// This should create tfhe-rs HL types, versionize them and store them into the version
    /// specific directory. The metadata for the generated tests should be returned in the same
    /// order that the tests will be run.
    fn gen_hl_data<P: AsRef<Path>>(base_data_dir: P) -> Vec<TestMetadata>;
}
