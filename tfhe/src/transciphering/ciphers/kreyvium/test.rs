use std::fmt::Write;

use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
};
use crate::shortint::prelude::*;
use crate::transciphering::ciphers::kreyvium::{
    KreyviumFheStream, KreyviumPlainKey, KreyviumPlainStream,
};
use crate::transciphering::{apply_keystream, StreamCipher, Transcipherer};

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

struct KreyviumTestVector {
    key: &'static str,
    iv: &'static str,
    expected: &'static str,
}

const KREYVIUM_TV_ZERO: KreyviumTestVector = KreyviumTestVector {
    key: "00000000000000000000000000000000",
    iv: "00000000000000000000000000000000",
    expected: "26DCF1F4BC0F1922",
};

const KREYVIUM_TV_KEY_BIT: KreyviumTestVector = KreyviumTestVector {
    key: "01000000000000000000000000000000",
    iv: "00000000000000000000000000000000",
    expected: "4FD421D4DA3D2C8A",
};

const KREYVIUM_TV_IV_BIT: KreyviumTestVector = KreyviumTestVector {
    key: "00000000000000000000000000000000",
    iv: "01000000000000000000000000000000",
    expected: "C9217BA0D762ACA1",
};

const KREYVIUM_TV_STANDARD: KreyviumTestVector = KreyviumTestVector {
    key: "0053A6F94C9FF24598EB000000000000",
    iv: "0D74DB42A91077DE45AC000000000000",
    expected: "D1F0303482061111",
};

#[test]
fn kreyvium_test_plain() {
    let cases = [
        KREYVIUM_TV_ZERO,
        KREYVIUM_TV_KEY_BIT,
        KREYVIUM_TV_IV_BIT,
        KREYVIUM_TV_STANDARD,
    ];

    for KreyviumTestVector { key, iv, expected } in cases {
        let key_bytes = hex_to_bytes_16(key);
        let iv_bytes = hex_to_bytes_16(iv);

        let mut kreyvium = KreyviumPlainStream::new(key_bytes, iv_bytes);
        let vec = kreyvium.next_keystream_bits(64);

        let hexadecimal = get_hexadecimal_string_from_bytes(&vec);
        assert_eq!(hexadecimal, expected, "key={key} iv={iv}");
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

    let mut enc_stream = KreyviumPlainStream::new(key, iv);
    let encrypted = enc_stream.encrypt(&message);
    assert_eq!(encrypted.len(), message.len());

    let mut dec_stream = KreyviumPlainStream::new(key, iv);
    let decrypted = dec_stream.decrypt(&encrypted);

    assert_eq!(decrypted, message);
}

fn kreyvium_fhe_keystream_known_answer(params: ClassicPBSParameters) {
    let (client_key, server_key) = gen_keys(params);

    let KreyviumTestVector { key, iv, expected } = KREYVIUM_TV_STANDARD;
    let key_bytes = hex_to_bytes_16(key);
    let iv_bytes = hex_to_bytes_16(iv);

    let cipher_key = KreyviumPlainKey::from(key_bytes).encrypt(&client_key);

    let mut kreyvium = KreyviumFheStream::new(cipher_key, iv_bytes, &server_key);

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
    assert_eq!(expected, hexadecimal);
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

#[test]
fn kreyvium_test_fhe_3_3() {
    kreyvium_fhe_keystream_known_answer(TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128);
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
        let mut sym_stream = KreyviumPlainStream::new(key_bits, iv_bits);
        let sym_cipher = sym_stream.encrypt(&input.to_le_bytes());

        // FHE side: encrypt the same key bits, run FHE stream, trans-cipher.
        let cipher_key = KreyviumPlainKey::from(key_bits).encrypt(&client_key);

        let mut fhe_stream = KreyviumFheStream::new(cipher_key, iv_bits, &server_key);
        let keystream = fhe_stream.next_keystream_bits(&server_key, 64);

        let chunks = apply_keystream(&server_key, &keystream, &sym_cipher);

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

    let mut full = KreyviumPlainStream::new(key, iv);
    let full_keystream = full.next_keystream_bits(128);

    let mut skipped = KreyviumPlainStream::new(key, iv);
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

    let key_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
    let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());

    let cipher_key = KreyviumPlainKey::from(key_bits).encrypt(&client_key);
    let mut k = KreyviumFheStream::new(cipher_key, iv_bits, &server_key);

    assert_eq!(k.current_counter(), 0);

    k.skip(&server_key, 64);
    assert_eq!(k.current_counter(), 64);

    let _ = k.next_keystream_bits(&server_key, 64);
    assert_eq!(k.current_counter(), 128);
}
