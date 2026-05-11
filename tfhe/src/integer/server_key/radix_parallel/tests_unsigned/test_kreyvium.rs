use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::TestParameters;
use crate::transciphering::ciphers::kreyvium::KreyviumPlainState;
use crate::transciphering::StreamCipher;
use rand::Rng;
use std::fmt::Write;
use std::sync::Arc;

fn encrypt_bits(cks: &RadixClientKey, bits: &[u64]) -> RadixCiphertext {
    RadixCiphertext::from(
        bits.iter()
            .map(|&bit| cks.encrypt_one_block(bit))
            .collect::<Vec<_>>(),
    )
}

fn decrypt_bits(cks: &RadixClientKey, ct: &RadixCiphertext) -> Vec<u8> {
    ct.blocks
        .iter()
        .map(|block| cks.decrypt_one_block(block) as u8)
        .collect()
}

fn bits_to_hex(bits: &[u8]) -> String {
    let mut result = String::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (j, &b) in chunk.iter().enumerate() {
            if b == 1 {
                byte |= 1 << j;
            }
        }
        write!(result, "{byte:02X}").unwrap();
    }
    result
}

fn parse_hex_to_bits(s: &str) -> Vec<u64> {
    let mut bits = Vec::new();
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).unwrap();
        for j in 0..8 {
            bits.push(((byte >> j) & 1) as u64);
        }
    }
    bits
}

/// Tests the full FHE Kreyvium implementation against a known standard test vector.
/// This verifies that the homomorphic circuit produces the exact same hex output as standard
/// Kreyvium.
pub fn kreyvium_test_vector_1_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, usize),
        crate::Result<RadixCiphertext>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let key_hex = "0053A6F94C9FF24598EB000000000000";
    let iv_hex = "0D74DB42A91077DE45AC000000000000";
    let expected_out_hex = "D1F0303482061111";

    let key_bits = parse_hex_to_bits(key_hex);
    let iv_bits = parse_hex_to_bits(iv_hex);

    let ct_key = encrypt_bits(&cks, &key_bits);
    let ct_iv = encrypt_bits(&cks, &iv_bits);

    let num_steps = 64;
    let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();

    let decrypted_bits = decrypt_bits(&cks, &output_radix);
    let hex_string = bits_to_hex(&decrypted_bits);

    assert_eq!(hex_string, expected_out_hex);
}

/// Fuzzy comparison test between the FHE Kreyvium implementation and the CPU reference.
/// Runs with random Keys and IVs to ensure general correctness beyond standard test vectors.
pub fn kreyvium_comparison_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, usize),
        crate::Result<RadixCiphertext>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let num_runs = 1;
    let num_steps = 64 * 50;

    let mut rng = rand::thread_rng();

    for _ in 0..num_runs {
        let mut key_bits = vec![0u64; 128];
        let mut iv_bits = vec![0u64; 128];

        for i in 0..128 {
            key_bits[i] = rng.gen_range(0..2);
            iv_bits[i] = rng.gen_range(0..2);
        }

        let ct_key = encrypt_bits(&cks, &key_bits);
        let ct_iv = encrypt_bits(&cks, &iv_bits);

        let key_bool: [bool; 128] = std::array::from_fn(|i| key_bits[i] == 1);
        let iv_bool: [bool; 128] = std::array::from_fn(|i| iv_bits[i] == 1);
        let mut ref_kreyvium = KreyviumPlainState::new(key_bool, iv_bool);
        let ref_bytes = ref_kreyvium.next_keystream_bits(num_steps);
        let cpu_output = ref_bytes
            .iter()
            .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1))
            .take(num_steps)
            .collect::<Vec<_>>();

        let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();
        let fhe_output = decrypt_bits(&cks, &output_radix);

        assert_eq!(fhe_output.len(), cpu_output.len());
        assert_eq!(fhe_output, cpu_output);
    }
}

/// Integration test verifying the correctness of the stateful FHE Kreyvium implementation by
/// comparing consecutive keystream chunks against a cleartext CPU reference.
pub fn kreyvium_stateful_comparison_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, &'a [usize]),
        crate::Result<Vec<RadixCiphertext>>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let step_chunks = vec![64, 128, 64, 192];
    let total_steps: usize = step_chunks.iter().sum();

    let mut rng = rand::thread_rng();

    let mut key_bits = vec![0u64; 128];
    let mut iv_bits = vec![0u64; 128];

    for i in 0..128 {
        key_bits[i] = rng.gen_range(0..2);
        iv_bits[i] = rng.gen_range(0..2);
    }

    let ct_key = encrypt_bits(&cks, &key_bits);
    let ct_iv = encrypt_bits(&cks, &iv_bits);

    let key_bool: [bool; 128] = std::array::from_fn(|i| key_bits[i] == 1);
    let iv_bool: [bool; 128] = std::array::from_fn(|i| iv_bits[i] == 1);
    let mut ref_kreyvium = KreyviumPlainState::new(key_bool, iv_bool);
    let ref_bytes = ref_kreyvium.next_keystream_bits(total_steps);
    let cpu_output = ref_bytes
        .iter()
        .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1))
        .take(total_steps)
        .collect::<Vec<_>>();

    let output_radixes = executor.execute((&ct_key, &ct_iv, &step_chunks)).unwrap();

    let mut fhe_output = Vec::new();
    for out_radix in output_radixes {
        fhe_output.extend(decrypt_bits(&cks, &out_radix));
    }

    assert_eq!(fhe_output.len(), cpu_output.len());
    assert_eq!(fhe_output, cpu_output);
}
