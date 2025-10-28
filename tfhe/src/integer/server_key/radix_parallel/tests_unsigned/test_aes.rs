#![cfg(feature = "gpu")]

use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::TestParameters;
use std::sync::Arc;

const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn plain_key_expansion(key: u64) -> Vec<u64> {
    const RCON: [u32; 10] = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1B000000, 0x36000000,
    ];
    // 64-bit key (2 words) * 11 rounds = 22 words
    const KEY_WORDS: usize = 2;
    const TOTAL_WORDS: usize = 22;

    let mut words = [0u32; TOTAL_WORDS];
    for (i, word) in words.iter_mut().enumerate().take(KEY_WORDS) {
        *word = (key >> (32 - (i * 32))) as u32;
    }

    for i in KEY_WORDS..TOTAL_WORDS {
        let mut temp = words[i - 1];
        if i % KEY_WORDS == 0 {
            temp = temp.rotate_left(8);
            let mut sub_bytes = 0u32;
            for j in 0..4 {
                let byte = (temp >> (24 - j * 8)) as u8;
                sub_bytes |= (S_BOX[byte as usize] as u32) << (24 - j * 8);
            }
            temp = sub_bytes ^ RCON[i / KEY_WORDS - 1];
        }
        words[i] = words[i - KEY_WORDS] ^ temp;
    }
    words
        .chunks_exact(KEY_WORDS)
        .map(|chunk| ((chunk[0] as u64) << 32) | (chunk[1] as u64))
        .collect()
}
fn sub_bytes(state: &mut [u8; 8]) {
    for byte in state.iter_mut() {
        *byte = S_BOX[*byte as usize];
    }
}
fn shift_rows(state: &mut [u8; 8]) {
    // 4x2 state
    // Row 0: s0, s1 (no shift)
    // Row 1: s2, s3 (shift 1)
    // Row 2: s4, s5 (shift 2 -> no shift)
    // Row 3: s6, s7 (shift 3 -> shift 1)
    let original = *state;
    state[2] = original[3];
    state[3] = original[2];
    state[6] = original[7];
    state[7] = original[6];
}
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}
fn mix_columns(state: &mut [u8; 8]) {
    let original = *state;
    // 2 columns
    for i in 0..2 {
        let col = i * 4;
        state[col] = gmul(original[col], 2)
            ^ gmul(original[col + 1], 3)
            ^ original[col + 2]
            ^ original[col + 3];
        state[col + 1] = original[col]
            ^ gmul(original[col + 1], 2)
            ^ gmul(original[col + 2], 3)
            ^ original[col + 3];
        state[col + 2] = original[col]
            ^ original[col + 1]
            ^ gmul(original[col + 2], 2)
            ^ gmul(original[col + 3], 3);
        state[col + 3] = gmul(original[col], 3)
            ^ original[col + 1]
            ^ original[col + 2]
            ^ gmul(original[col + 3], 2);
    }
}
fn add_round_key(state: &mut [u8; 8], round_key: u64) {
    let key_bytes = round_key.to_be_bytes();
    for i in 0..8 {
        state[i] ^= key_bytes[i];
    }
}
fn plain_aes_encrypt_block(block_bytes: &mut [u8; 8], expanded_keys: &[u64]) {
    add_round_key(block_bytes, expanded_keys[0]);
    for round_key in expanded_keys.iter().take(10).skip(1) {
        sub_bytes(block_bytes);
        shift_rows(block_bytes);
        mix_columns(block_bytes);
        add_round_key(block_bytes, *round_key);
    }
    sub_bytes(block_bytes);
    shift_rows(block_bytes);
    add_round_key(block_bytes, expanded_keys[10]);
}
fn plain_aes_ctr(num_aes_inputs: usize, iv: u64, key: u64) -> Vec<u64> {
    let expanded_keys = plain_key_expansion(key);
    let mut results = Vec::with_capacity(num_aes_inputs);
    for i in 0..num_aes_inputs {
        let counter_value = iv.wrapping_add(i as u64);
        let mut block = counter_value.to_be_bytes();
        plain_aes_encrypt_block(&mut block, &expanded_keys);
        results.push(u64::from_be_bytes(block));
    }
    results
}

fn internal_aes_fixed_parallelism_test<P, E>(param: P, mut executor: E, num_aes_inputs: usize)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, u64, usize, usize),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let key: u64 = 0x2b7e151628aed2a6;
    let iv: u64 = 0xf0f1f2f3f4f5f6f7;

    let plain_results = plain_aes_ctr(num_aes_inputs, iv, key);

    let ctxt_key = cks.encrypt_u64_for_aes_ctr(key);
    let ctxt_iv = cks.encrypt_u64_for_aes_ctr(iv);

    for sbox_parallelism in [1, 2, 4, 8, 16] {
        let encrypted_result =
            executor.execute((&ctxt_key, &ctxt_iv, 0, num_aes_inputs, sbox_parallelism));
        let fhe_results = cks.decrypt_u64_from_aes_ctr(&encrypted_result, num_aes_inputs);
        assert_eq!(fhe_results, plain_results);
    }
}

pub fn aes_fixed_parallelism_1_input_test<P, E>(param: P, executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, u64, usize, usize),
        RadixCiphertext,
    >,
{
    internal_aes_fixed_parallelism_test(param, executor, 1);
}

pub fn aes_fixed_parallelism_2_inputs_test<P, E>(param: P, executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, u64, usize, usize),
        RadixCiphertext,
    >,
{
    internal_aes_fixed_parallelism_test(param, executor, 2);
}

pub fn aes_dynamic_parallelism_many_inputs_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, u64, usize),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let key: u64 = 0x2b7e151628aed2a6;
    let iv: u64 = 0xf0f1f2f3f4f5f6f7;

    let ctxt_key = cks.encrypt_u64_for_aes_ctr(key);
    let ctxt_iv = cks.encrypt_u64_for_aes_ctr(iv);

    for num_aes_inputs in [4, 8, 16, 32] {
        let plain_results = plain_aes_ctr(num_aes_inputs, iv, key);
        let encrypted_result = executor.execute((&ctxt_key, &ctxt_iv, 0, num_aes_inputs));
        let fhe_results = cks.decrypt_u64_from_aes_ctr(&encrypted_result, num_aes_inputs);
        assert_eq!(fhe_results, plain_results);
    }
}
