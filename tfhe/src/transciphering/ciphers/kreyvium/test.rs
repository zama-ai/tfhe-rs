use std::fmt::Write;

use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::prelude::*;
use crate::transciphering::ciphers::kreyvium::{
    KreyviumEncryptedKey, KreyviumFheStream, KreyviumPlainStream,
};
use crate::transciphering::{trans_cipher_2_2, StreamCipher, Transcipherer};

fn get_hexadecimal_string_from_bytes(bytes: &[u8]) -> String {
    let mut hexadecimal = String::new();
    for test in bytes {
        write!(hexadecimal, "{test:02X?}").expect("writing to a String is infallible");
    }
    hexadecimal
}

fn hex_to_bytes_16(hex: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for i in (0..hex.len()).step_by(2) {
        bytes[i >> 1] = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
    }
    bytes
}

fn bytes_to_bits_lsb_first(bytes: &[u8; 16]) -> [bool; 128] {
    let mut bits = [false; 128];
    for (b, &byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            bits[8 * b + j] = ((byte >> j) & 1) == 1;
        }
    }
    bits
}

#[test]
fn kreyvium_test_plain() {
    let cases = [
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "26DCF1F4BC0F1922",
        ),
        (
            "01000000000000000000000000000000",
            "00000000000000000000000000000000",
            "4FD421D4DA3D2C8A",
        ),
        (
            "00000000000000000000000000000000",
            "01000000000000000000000000000000",
            "C9217BA0D762ACA1",
        ),
        (
            "0053A6F94C9FF24598EB000000000000",
            "0D74DB42A91077DE45AC000000000000",
            "D1F0303482061111",
        ),
    ];

    for (key_hex, iv_hex, expected) in cases {
        let key = hex_to_bytes_16(key_hex);
        let iv = bytes_to_bits_lsb_first(&hex_to_bytes_16(iv_hex));

        let mut kreyvium = KreyviumPlainStream::new(key.into(), iv);
        let vec = kreyvium.next_keystream_bits(64);

        let hexadecimal = get_hexadecimal_string_from_bytes(&vec);
        assert_eq!(hexadecimal, expected, "key={key_hex} iv={iv_hex}");
    }
}

#[test]
fn kreyvium_plain_encrypt_decrypt_round_trip() {
    use rand::{Rng, SeedableRng};

    let seed: u64 = rand::thread_rng().gen();
    println!("kreyvium_encrypt_decrypt_round_trip seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let key: [bool; 128] = std::array::from_fn(|_| rng.gen());
    let iv: [bool; 128] = std::array::from_fn(|_| rng.gen());

    let message: Vec<u8> = (0..37).map(|_| rng.gen()).collect();

    let mut enc_stream = KreyviumPlainStream::new(key.into(), iv);
    let encrypted = enc_stream.encrypt(&message);
    assert_eq!(encrypted.len(), message.len());

    let mut dec_stream = KreyviumPlainStream::new(key.into(), iv);
    let decrypted = dec_stream.decrypt(&encrypted);

    assert_eq!(decrypted, message);
}

fn kreyvium_fhe_keystream_known_answer(params: ClassicPBSParameters) {
    let (client_key, server_key) = gen_keys(params);

    let key_bytes = hex_to_bytes_16("0053A6F94C9FF24598EB000000000000");
    let iv_bytes = hex_to_bytes_16("0D74DB42A91077DE45AC000000000000");

    let mut key_bits = [0u64; 128];
    for (b, &byte) in key_bytes.iter().enumerate() {
        for j in 0..8 {
            key_bits[8 * b + j] = ((byte >> j) & 1) as u64;
        }
    }

    let mut iv_bits = [0u64; 128];
    for (b, &byte) in iv_bytes.iter().enumerate() {
        for j in 0..8 {
            iv_bits[8 * b + j] = ((byte >> j) & 1) as u64;
        }
    }

    let output = "D1F0303482061111";

    let cipher_key: KreyviumEncryptedKey = key_bits.map(|x| client_key.encrypt(x)).into();

    let mut kreyvium = KreyviumFheStream::new(cipher_key, iv_bits, &server_key);

    let cts = kreyvium.next_keystream_bits(&server_key, 64);

    // Each keystream Ciphertext encodes the bit in its low bit only; the
    // high message bit is garbage when (m, c) > (2, 2) (see
    // `KreyviumFheStream::new` doc).
    let mut bytes = vec![0u8; 8];
    for (i, ct) in cts.iter().enumerate() {
        if client_key.decrypt(ct) % 2 == 1 {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }

    let hexadecimal = get_hexadecimal_string_from_bytes(&bytes);
    assert_eq!(output, hexadecimal);
}

#[test]
fn kreyvium_test_fhe() {
    kreyvium_fhe_keystream_known_answer(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

/// Tests the `round_naive` fallback path under params where the
/// optimized 2_2 round would overshoot the noise budget.
#[test]
fn kreyvium_test_fhe_1_1() {
    kreyvium_fhe_keystream_known_answer(TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
}

/// End-to-end round trip: random Kreyvium key + IV, random 64-bit input,
/// symmetric Kreyvium encrypt, FHE keystream, trans-cipher,
/// decrypt, expect the recovered u64 to match the original input.
#[test]
fn kreyvium_test_round_trip() {
    use rand::{Rng, SeedableRng};

    let seed: u64 = rand::thread_rng().gen();
    println!("kreyvium_test_round_trip seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let (client_key, server_key) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    const N_ITER: usize = 2;
    for iter in 0..N_ITER {
        // Random Kreyvium key and IV (already in unpacked-bit form), plus a
        // random 64-bit input.
        let key_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
        let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
        let input: u64 = rng.gen();

        // Symmetric Kreyvium encrypt: plain keystream XOR input bytes
        // (LSB-first within each byte, matching `to_le_bytes`).
        let mut sym_stream = KreyviumPlainStream::new(key_bits.into(), iv_bits);
        let sym_cipher = sym_stream.encrypt(&input.to_le_bytes());

        // FHE side: encrypt the same key bits, run FHE stream, trans-cipher.
        let cipher_key: KreyviumEncryptedKey =
            key_bits.map(|b| client_key.encrypt(b as u64)).into();
        let iv_bits_u64 = iv_bits.map(|b| b as u64);

        let mut fhe_stream = KreyviumFheStream::new(cipher_key, iv_bits_u64, &server_key);
        let keystream = fhe_stream.next_keystream_bits(&server_key, 64);

        let chunks = trans_cipher_2_2(&server_key, &keystream, &sym_cipher);

        // Decrypt each clean 2-bit chunk back into bits 2i and 2i+1 of u64.
        let result: u64 = chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| (client_key.decrypt(chunk) & 0b11) << (2 * i))
            .sum();

        assert_eq!(
            result, input,
            "round-trip mismatch (seed={seed}, iter={iter})"
        );
    }
}

/// `skip(n)` then producing `m` bits matches the last `m` bits of `n + m`
/// from a fresh stream.
#[test]
fn kreyvium_skip_plain() {
    use rand::{Rng, SeedableRng};

    let seed: u64 = rand::thread_rng().gen();
    println!("kreyvium_plain_skip_forward seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let key: [bool; 128] = std::array::from_fn(|_| rng.gen());
    let iv: [bool; 128] = std::array::from_fn(|_| rng.gen());

    let mut full = KreyviumPlainStream::new(key.into(), iv);
    let full_keystream = full.next_keystream_bits(128);

    let mut skipped = KreyviumPlainStream::new(key.into(), iv);
    assert_eq!(skipped.current_counter(), 0);
    skipped.skip(64);
    assert_eq!(skipped.current_counter(), 64);

    let tail = skipped.next_keystream_bits(64);
    assert_eq!(skipped.current_counter(), 128);
    assert_eq!(tail, full_keystream[8..16]);
}

/// FHE side: `skip` advances the counter and subsequent generation continues
/// from the new position.
#[test]
fn kreyvium_skip_fhe() {
    use rand::{Rng, SeedableRng};

    let seed: u64 = rand::thread_rng().gen();
    println!("kreyvium_skip_fhe seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let (client_key, server_key) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    let key_bits: [u64; 128] = std::array::from_fn(|_| rng.gen_range(0..2));
    let iv_bits: [u64; 128] = std::array::from_fn(|_| rng.gen_range(0..2));

    let cipher_key: KreyviumEncryptedKey = key_bits.map(|x| client_key.encrypt(x)).into();
    let mut k = KreyviumFheStream::new(cipher_key, iv_bits, &server_key);

    assert_eq!(k.current_counter(), 0);

    k.skip(&server_key, 64);
    assert_eq!(k.current_counter(), 64);

    let _ = k.next_keystream_bits(&server_key, 64);
    assert_eq!(k.current_counter(), 128);
}
