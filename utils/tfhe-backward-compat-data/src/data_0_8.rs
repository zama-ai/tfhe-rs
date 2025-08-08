use std::borrow::Cow;
use std::fs::create_dir_all;

use tfhe_0_8::boolean::engine::BooleanEngine;
use tfhe_0_8::core_crypto::commons::generators::DeterministicSeeder;
use tfhe_0_8::core_crypto::commons::math::random::RandomGenerator;
use tfhe_0_8::core_crypto::prelude::{
    ActivatedRandomGenerator, CiphertextModulusLog, LweCiphertextCount, TUniform,
};
use tfhe_0_8::integer::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};
use tfhe_0_8::prelude::*;
use tfhe_0_8::shortint::engine::ShortintEngine;
use tfhe_0_8::shortint::parameters::list_compression::CompressionParameters;
use tfhe_0_8::shortint::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
    MessageModulus, PBSParameters,
};
use tfhe_0_8::zk::{CompactPkeCrs, ZkComputeLoad, ZkMSBZeroPaddingBitCount};
use tfhe_0_8::{
    generate_keys, set_server_key, shortint, ClientKey, CompactCiphertextList, CompactPublicKey,
    CompressedCiphertextListBuilder, CompressedCompactPublicKey, CompressedFheBool,
    CompressedFheInt8, CompressedFheUint8, CompressedPublicKey, ConfigBuilder, FheBool, FheInt8,
    FheUint8, ProvenCompactCiphertextList, PublicKey, Seed, ServerKey,
};

use crate::generate::{
    store_versioned_auxiliary_tfhe_0_8, store_versioned_test_tfhe_0_8, TfhersVersion,
    INSECURE_SMALL_PK_TEST_PARAMS, PRNG_SEED, VALID_TEST_PARAMS, VALID_TEST_PARAMS_TUNIFORM,
    VALID_TEST_PARAMS_TUNIFORM_COMPRESSION,
};
use crate::{
    DataKind, HlBoolCiphertextTest, HlCiphertextTest, HlClientKeyTest,
    HlHeterogeneousCiphertextListTest, HlPublicKeyTest, HlSignedCiphertextTest,
    PkeZkProofAuxiliaryInfo, ShortintCiphertextTest, ShortintClientKeyTest,
    TestClassicParameterSet, TestCompressionParameterSet, TestDistribution, TestMetadata,
    TestParameterSet, ZkPkePublicParamsTest, HL_MODULE_NAME, SHORTINT_MODULE_NAME,
};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_0_8($msg, $dir, $test_filename)
    };
}

macro_rules! store_versioned_auxiliary {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_auxiliary_tfhe_0_8($msg, $dir, $test_filename)
    };
}

impl From<TestDistribution> for DynamicDistribution<u64> {
    fn from(value: TestDistribution) -> Self {
        match value {
            TestDistribution::Gaussian { stddev } => {
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(stddev))
            }
            TestDistribution::TUniform { bound_log2 } => {
                DynamicDistribution::TUniform(TUniform::new(bound_log2))
            }
        }
    }
}

impl From<TestClassicParameterSet> for ClassicPBSParameters {
    fn from(value: TestClassicParameterSet) -> Self {
        ClassicPBSParameters {
            lwe_dimension: LweDimension(value.lwe_dimension),
            glwe_dimension: GlweDimension(value.glwe_dimension),
            polynomial_size: PolynomialSize(value.polynomial_size),
            lwe_noise_distribution: value.lwe_noise_distribution.into(),
            glwe_noise_distribution: value.glwe_noise_distribution.into(),
            pbs_base_log: DecompositionBaseLog(value.pbs_base_log),
            pbs_level: DecompositionLevelCount(value.pbs_level),
            ks_base_log: DecompositionBaseLog(value.ks_base_log),
            ks_level: DecompositionLevelCount(value.ks_level),
            message_modulus: MessageModulus(value.message_modulus),
            carry_modulus: CarryModulus(value.carry_modulus),
            max_noise_level: MaxNoiseLevel::new(value.max_noise_level),
            log2_p_fail: value.log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(value.ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*value.encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
        }
    }
}

impl From<TestParameterSet> for PBSParameters {
    fn from(value: TestParameterSet) -> Self {
        match value {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                PBSParameters::PBS(test_classic_parameter_set.into())
            }
            TestParameterSet::TestMultiBitParameterSet(_) => {
                unreachable!()
            }
        }
    }
}

impl From<TestCompressionParameterSet> for CompressionParameters {
    fn from(value: TestCompressionParameterSet) -> Self {
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
        } = value;
        Self {
            br_level: DecompositionLevelCount(br_level),
            br_base_log: DecompositionBaseLog(br_base_log),
            packing_ks_level: DecompositionLevelCount(packing_ks_level),
            packing_ks_base_log: DecompositionBaseLog(packing_ks_base_log),
            packing_ks_polynomial_size: PolynomialSize(packing_ks_polynomial_size),
            packing_ks_glwe_dimension: GlweDimension(packing_ks_glwe_dimension),
            lwe_per_glwe: LweCiphertextCount(lwe_per_glwe),
            storage_log_modulus: CiphertextModulusLog(storage_log_modulus),
            packing_ks_key_noise_distribution: packing_ks_key_noise_distribution.into(),
        }
    }
}

// Shortint test constants
const SHORTINT_CLIENT_KEY_FILENAME: &str = "client_key";

const SHORTINT_CLIENTKEY_TEST: ShortintClientKeyTest = ShortintClientKeyTest {
    test_filename: Cow::Borrowed(SHORTINT_CLIENT_KEY_FILENAME),
    // Here we use the non TUniform params for shortint to be able to check gaussian params
    parameters: VALID_TEST_PARAMS,
};
const SHORTINT_CT1_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    test_filename: Cow::Borrowed("ct1"),
    key_filename: Cow::Borrowed(SHORTINT_CLIENT_KEY_FILENAME),
    clear_value: 0,
};
const SHORTINT_CT2_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    test_filename: Cow::Borrowed("ct2"),
    key_filename: Cow::Borrowed(SHORTINT_CLIENT_KEY_FILENAME),
    clear_value: 3,
};

// HL test constants
// Batch 1
const HL_CLIENT_KEY_BATCH_1_FILENAME: &str = "batch_1_client_key";

const HL_CLIENTKEY_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    parameters: VALID_TEST_PARAMS_TUNIFORM,
};

// We use a client key with specific parameters for the pubkey since it can be very large
const HL_LEGACY_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("legacy_public_key"),
    client_key_filename: Cow::Borrowed("client_key_for_pubkey"),
    compressed: false,
    compact: false,
};

const HL_COMPRESSED_LEGACY_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("compressed_legacy_public_key"),
    client_key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    compact: false,
};

const HL_COMPACT_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("compact_public_key"),
    client_key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: false,
    compact: true,
};

const HL_COMPRESSED_COMPACT_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("compressed_compact_public_key"),
    client_key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    compact: true,
};

const HL_CT1_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct1"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: false,
    clear_value: 0,
};

const HL_CT2_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct2"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: false,
    clear_value: 255,
};

const HL_COMPRESSED_SEEDED_CT_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_seeded"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    clear_value: 255,
};

const HL_COMPRESSED_CT_MODSWITCHED_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_modswitched"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    clear_value: 255,
};

const HL_SIGNED_CT1_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct1_signed"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: false,
    clear_value: 0,
};

const HL_SIGNED_CT2_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct2_signed"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: false,
    clear_value: -127,
};

const HL_SIGNED_COMPRESSED_SEEDED_CT_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_seeded_signed"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    clear_value: 255,
};

const HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_modswitched_signed"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    clear_value: 255,
};

const HL_BOOL1_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("bool1"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: false,
    clear_value: true,
};

const HL_BOOL2_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("bool2"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: false,
    clear_value: false,
};

const HL_COMPRESSED_BOOL_SEEDED_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("compressed_seeded_bool"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    clear_value: true,
};

const HL_COMPRESSED_BOOL_MODSWITCHED_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("compressed_modswitched_bool"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_1_FILENAME),
    compressed: true,
    clear_value: true,
};

// Batch 2
const HL_CLIENT_KEY_BATCH_2_FILENAME: &str = "batch_2_client_key";

const HL_COMPACTLIST_TEST: HlHeterogeneousCiphertextListTest = HlHeterogeneousCiphertextListTest {
    test_filename: Cow::Borrowed("hl_heterogeneous_list"),
    key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_2_FILENAME),
    clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
    data_kinds: Cow::Borrowed(&[
        DataKind::Unsigned,
        DataKind::Signed,
        DataKind::Bool,
        DataKind::Bool,
    ]),
    compressed: false,
    proof_info: None,
};

const HL_PACKED_COMPACTLIST_TEST: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_packed_heterogeneous_list"),
        key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_2_FILENAME),
        clear_values: HL_COMPACTLIST_TEST.clear_values,
        data_kinds: HL_COMPACTLIST_TEST.data_kinds,
        compressed: false,
        proof_info: None,
    };

const HL_COMPRESSED_LIST_TEST: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_compressed_heterogeneous_list"),
        key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_2_FILENAME),
        clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
        data_kinds: Cow::Borrowed(&[
            DataKind::Unsigned,
            DataKind::Signed,
            DataKind::Bool,
            DataKind::Bool,
        ]),
        compressed: true,
        proof_info: None,
    };

const HL_PROVEN_COMPACTLIST_TEST: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_proven_heterogeneous_list"),
        key_filename: Cow::Borrowed(HL_CLIENT_KEY_BATCH_2_FILENAME),
        clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
        data_kinds: Cow::Borrowed(&[
            DataKind::Unsigned,
            DataKind::Signed,
            DataKind::Bool,
            DataKind::Bool,
        ]),
        compressed: false,
        proof_info: Some(PkeZkProofAuxiliaryInfo {
            public_key_filename: Cow::Borrowed("public_key"),
            params_filename: Cow::Borrowed("zk_pke_public_params"),
            metadata: Cow::Borrowed("drawkcab"),
        }),
    };

const ZK_PKE_PUBLIC_PARAMS_TEST: ZkPkePublicParamsTest = ZkPkePublicParamsTest {
    test_filename: Cow::Borrowed("zk_pke_public_params"),
    lwe_dimension: VALID_TEST_PARAMS_TUNIFORM.polynomial_size()
        * VALID_TEST_PARAMS_TUNIFORM.glwe_dimension(), // Lwe dimension of the "big" key is glwe dimension * polynomial size
    max_num_cleartext: 16,
    noise_bound: match VALID_TEST_PARAMS_TUNIFORM.lwe_noise_distribution() {
        TestDistribution::Gaussian { .. } => unreachable!(),
        TestDistribution::TUniform { bound_log2 } => bound_log2 as usize,
    },
    ciphertext_modulus: VALID_TEST_PARAMS_TUNIFORM.ciphertext_modulus(),
    plaintext_modulus: VALID_TEST_PARAMS_TUNIFORM.message_modulus()
        * VALID_TEST_PARAMS_TUNIFORM.carry_modulus()
        * 2, // *2 for padding bit
    padding_bit_count: 1,
};

const HL_CLIENT_W_COMP_KEY_BATCH_2_FILENAME: &str = "client_key_with_compression";

const HL_CLIENTKEY_WITH_COMPRESSION_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed(HL_CLIENT_W_COMP_KEY_BATCH_2_FILENAME),
    parameters: VALID_TEST_PARAMS_TUNIFORM,
};

pub struct V0_8;

impl TfhersVersion for V0_8 {
    const VERSION_NUMBER: &'static str = "0.8";

    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });

        let boolean_engine = BooleanEngine::new_from_seeder(&mut seeder);
        BooleanEngine::replace_thread_local(boolean_engine);
    }

    fn gen_shortint_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(SHORTINT_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        // generate a client key
        let shortint_client_key = shortint::ClientKey::new(SHORTINT_CLIENTKEY_TEST.parameters);

        store_versioned_test!(
            &shortint_client_key,
            &dir,
            &SHORTINT_CLIENTKEY_TEST.test_filename,
        );

        // generate ciphertexts
        let ct1 = shortint_client_key.encrypt(SHORTINT_CT1_TEST.clear_value);
        let ct2 = shortint_client_key.encrypt(SHORTINT_CT2_TEST.clear_value);

        // Serialize them
        store_versioned_test!(&ct1, &dir, &SHORTINT_CT1_TEST.test_filename);
        store_versioned_test!(&ct2, &dir, &SHORTINT_CT2_TEST.test_filename);

        vec![
            TestMetadata::ShortintClientKey(SHORTINT_CLIENTKEY_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT1_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT2_TEST),
        ]
    }

    fn gen_hl_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        let mut all_tests = vec![];

        {
            // generate keys
            let config =
                ConfigBuilder::with_custom_parameters(HL_CLIENTKEY_TEST.parameters).build();
            let (hl_client_key, hl_server_key) = generate_keys(config);

            // Here we use specific parameters to generate a smaller public key.
            // WARNING: these parameters are completely insecure
            let params_pk = INSECURE_SMALL_PK_TEST_PARAMS;
            let client_key_for_pk =
                ClientKey::generate(ConfigBuilder::with_custom_parameters(params_pk).build());

            let pub_key = PublicKey::new(&client_key_for_pk);
            let compressed_pub_key = CompressedPublicKey::new(&hl_client_key);
            let compact_pub_key = CompactPublicKey::new(&hl_client_key);
            let compressed_compact_pub_key = CompressedCompactPublicKey::new(&hl_client_key);

            store_versioned_test!(&hl_client_key, &dir, &HL_CLIENTKEY_TEST.test_filename);

            store_versioned_test!(&pub_key, &dir, &HL_LEGACY_PUBKEY_TEST.test_filename);
            store_versioned_auxiliary!(
                &client_key_for_pk,
                &dir,
                &HL_LEGACY_PUBKEY_TEST.client_key_filename,
            );

            store_versioned_test!(
                &compressed_pub_key,
                &dir,
                &HL_COMPRESSED_LEGACY_PUBKEY_TEST.test_filename,
            );
            store_versioned_test!(
                &compact_pub_key,
                &dir,
                &HL_COMPACT_PUBKEY_TEST.test_filename,
            );
            store_versioned_test!(
                &compressed_compact_pub_key,
                &dir,
                &HL_COMPRESSED_COMPACT_PUBKEY_TEST.test_filename,
            );

            set_server_key(hl_server_key);

            // generate ciphertexts
            let ct1 = FheUint8::encrypt(HL_CT1_TEST.clear_value, &hl_client_key);
            let ct2 = FheUint8::encrypt(HL_CT2_TEST.clear_value, &hl_client_key);

            let ct1_signed = FheInt8::encrypt(HL_SIGNED_CT1_TEST.clear_value, &hl_client_key);
            let ct2_signed = FheInt8::encrypt(HL_SIGNED_CT2_TEST.clear_value, &hl_client_key);

            let bool1 = FheBool::encrypt(HL_BOOL1_TEST.clear_value, &hl_client_key);
            let bool2 = FheBool::encrypt(HL_BOOL2_TEST.clear_value, &hl_client_key);

            // Generate compressed ciphertexts
            // The first one using seeded (default) method
            let compressed_ct1 = CompressedFheUint8::encrypt(
                HL_COMPRESSED_SEEDED_CT_TEST.clear_value,
                &hl_client_key,
            );
            let compressed_ct1_signed = CompressedFheInt8::encrypt(
                HL_SIGNED_COMPRESSED_SEEDED_CT_TEST.clear_value,
                &hl_client_key,
            );
            let compressed_bool1 = CompressedFheBool::encrypt(
                HL_COMPRESSED_BOOL_SEEDED_TEST.clear_value,
                &hl_client_key,
            );

            // The second one using the modulus switched method
            let compressed_ct2 = FheUint8::encrypt(
                HL_COMPRESSED_CT_MODSWITCHED_TEST.clear_value,
                &hl_client_key,
            )
            .compress();
            let compressed_ct2_signed = FheInt8::encrypt(
                HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST.clear_value,
                &hl_client_key,
            )
            .compress();
            let compressed_bool2 = CompressedFheBool::encrypt(
                HL_COMPRESSED_BOOL_MODSWITCHED_TEST.clear_value,
                &hl_client_key,
            );

            // Serialize them
            store_versioned_test!(&ct1, &dir, &HL_CT1_TEST.test_filename);
            store_versioned_test!(&ct2, &dir, &HL_CT2_TEST.test_filename);
            store_versioned_test!(
                &compressed_ct1,
                &dir,
                &HL_COMPRESSED_SEEDED_CT_TEST.test_filename,
            );
            store_versioned_test!(
                &compressed_ct2,
                &dir,
                &HL_COMPRESSED_CT_MODSWITCHED_TEST.test_filename,
            );

            store_versioned_test!(&ct1_signed, &dir, &HL_SIGNED_CT1_TEST.test_filename);
            store_versioned_test!(&ct2_signed, &dir, &HL_SIGNED_CT2_TEST.test_filename);
            store_versioned_test!(
                &compressed_ct1_signed,
                &dir,
                &HL_SIGNED_COMPRESSED_SEEDED_CT_TEST.test_filename,
            );
            store_versioned_test!(
                &compressed_ct2_signed,
                &dir,
                &HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST.test_filename,
            );

            store_versioned_test!(&bool1, &dir, &HL_BOOL1_TEST.test_filename);
            store_versioned_test!(&bool2, &dir, &HL_BOOL2_TEST.test_filename);
            store_versioned_test!(
                &compressed_bool1,
                &dir,
                &HL_COMPRESSED_BOOL_SEEDED_TEST.test_filename,
            );
            store_versioned_test!(
                &compressed_bool2,
                &dir,
                &HL_COMPRESSED_BOOL_MODSWITCHED_TEST.test_filename,
            );

            let test_batch_1 = [
                TestMetadata::HlClientKey(HL_CLIENTKEY_TEST),
                TestMetadata::HlPublicKey(HL_LEGACY_PUBKEY_TEST),
                TestMetadata::HlPublicKey(HL_COMPRESSED_LEGACY_PUBKEY_TEST),
                TestMetadata::HlPublicKey(HL_COMPACT_PUBKEY_TEST),
                TestMetadata::HlPublicKey(HL_COMPRESSED_COMPACT_PUBKEY_TEST),
                TestMetadata::HlCiphertext(HL_CT1_TEST),
                TestMetadata::HlCiphertext(HL_CT2_TEST),
                TestMetadata::HlCiphertext(HL_COMPRESSED_SEEDED_CT_TEST),
                TestMetadata::HlCiphertext(HL_COMPRESSED_CT_MODSWITCHED_TEST),
                TestMetadata::HlSignedCiphertext(HL_SIGNED_CT1_TEST),
                TestMetadata::HlSignedCiphertext(HL_SIGNED_CT2_TEST),
                TestMetadata::HlSignedCiphertext(HL_SIGNED_COMPRESSED_SEEDED_CT_TEST),
                TestMetadata::HlSignedCiphertext(HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST),
                TestMetadata::HlBoolCiphertext(HL_BOOL1_TEST),
                TestMetadata::HlBoolCiphertext(HL_BOOL2_TEST),
                TestMetadata::HlBoolCiphertext(HL_COMPRESSED_BOOL_SEEDED_TEST),
                TestMetadata::HlBoolCiphertext(HL_COMPRESSED_BOOL_MODSWITCHED_TEST),
            ];
            all_tests.extend(test_batch_1);
        }

        {
            // Generate a compact public key needed to create a compact list
            let config =
                tfhe_0_8::ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS_TUNIFORM)
                    .enable_compression(VALID_TEST_PARAMS_TUNIFORM_COMPRESSION.into())
                    .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key.clone());
            let compact_pub_key = CompactPublicKey::new(&hl_client_key);

            let mut zk_rng: RandomGenerator<ActivatedRandomGenerator> =
                RandomGenerator::new(Seed(PRNG_SEED));
            let crs = CompactPkeCrs::new(
                LweDimension(ZK_PKE_PUBLIC_PARAMS_TEST.lwe_dimension),
                ZK_PKE_PUBLIC_PARAMS_TEST.max_num_cleartext,
                TUniform::<u64>::new(ZK_PKE_PUBLIC_PARAMS_TEST.noise_bound as u32),
                CiphertextModulus::new(ZK_PKE_PUBLIC_PARAMS_TEST.ciphertext_modulus),
                ZK_PKE_PUBLIC_PARAMS_TEST.plaintext_modulus as u64,
                ZkMSBZeroPaddingBitCount(ZK_PKE_PUBLIC_PARAMS_TEST.padding_bit_count as u64),
                &mut zk_rng,
            )
            .unwrap();

            // Store the associated client key to be able to decrypt the ciphertexts in the list
            store_versioned_auxiliary!(
                &hl_client_key,
                &dir,
                &HL_PROVEN_COMPACTLIST_TEST.key_filename
            );

            store_versioned_auxiliary!(
                &compact_pub_key,
                &dir,
                &HL_PROVEN_COMPACTLIST_TEST
                    .proof_info
                    .unwrap()
                    .public_key_filename
            );

            let mut proven_builder = ProvenCompactCiphertextList::builder(&compact_pub_key);
            proven_builder
                .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[0] as u8)
                .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[1] as i8)
                .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[2] != 0)
                .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[3] != 0);

            let proven_list_packed = proven_builder
                .build_with_proof_packed(
                    crs.public_params(),
                    HL_PROVEN_COMPACTLIST_TEST
                        .proof_info
                        .unwrap()
                        .metadata
                        .as_bytes(),
                    ZkComputeLoad::Proof,
                )
                .unwrap();

            store_versioned_test!(
                crs.public_params(),
                &dir,
                &ZK_PKE_PUBLIC_PARAMS_TEST.test_filename,
            );

            store_versioned_test!(
                &proven_list_packed,
                &dir,
                &HL_PROVEN_COMPACTLIST_TEST.test_filename,
            );

            // Generate heterogeneous list data
            let mut compact_builder = CompactCiphertextList::builder(&compact_pub_key);
            compact_builder
                .push(HL_COMPACTLIST_TEST.clear_values[0] as u8)
                .push(HL_COMPACTLIST_TEST.clear_values[1] as i8)
                .push(HL_COMPACTLIST_TEST.clear_values[2] != 0)
                .push(HL_COMPACTLIST_TEST.clear_values[3] != 0);

            let compact_list_packed = compact_builder.build_packed();
            let compact_list = compact_builder.build();

            let mut compressed_builder = CompressedCiphertextListBuilder::new();
            compressed_builder
                .push(FheUint8::encrypt(
                    HL_COMPRESSED_LIST_TEST.clear_values[0] as u8,
                    &hl_client_key,
                ))
                .push(FheInt8::encrypt(
                    HL_COMPRESSED_LIST_TEST.clear_values[1] as i8,
                    &hl_client_key,
                ))
                .push(FheBool::encrypt(
                    HL_COMPRESSED_LIST_TEST.clear_values[2] != 0,
                    &hl_client_key,
                ))
                .push(FheBool::encrypt(
                    HL_COMPRESSED_LIST_TEST.clear_values[3] != 0,
                    &hl_client_key,
                ));
            let compressed_list = compressed_builder.build().unwrap();

            store_versioned_test!(
                &compact_list_packed,
                &dir,
                &HL_PACKED_COMPACTLIST_TEST.test_filename,
            );
            store_versioned_test!(&compact_list, &dir, &HL_COMPACTLIST_TEST.test_filename);
            store_versioned_test!(
                &compressed_list,
                &dir,
                &HL_COMPRESSED_LIST_TEST.test_filename,
            );

            store_versioned_test!(
                &hl_client_key,
                &dir,
                &HL_CLIENTKEY_WITH_COMPRESSION_TEST.test_filename,
            );

            let test_batch_2 = [
                TestMetadata::HlHeterogeneousCiphertextList(HL_COMPACTLIST_TEST),
                TestMetadata::HlHeterogeneousCiphertextList(HL_PACKED_COMPACTLIST_TEST),
                TestMetadata::HlHeterogeneousCiphertextList(HL_COMPRESSED_LIST_TEST),
                TestMetadata::HlHeterogeneousCiphertextList(HL_PROVEN_COMPACTLIST_TEST),
                TestMetadata::ZkPkePublicParams(ZK_PKE_PUBLIC_PARAMS_TEST),
                TestMetadata::HlClientKey(HL_CLIENTKEY_WITH_COMPRESSION_TEST),
            ];

            all_tests.extend(test_batch_2);
        }

        all_tests
    }
}
