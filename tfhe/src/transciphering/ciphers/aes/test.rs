use super::sbox::sbox;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::prelude::*;
use crate::transciphering::ciphers::aes::{
    AesFheRoundKeys, AesFheState, AesIv, AesPlainKey, AesPlainState,
};
use crate::transciphering::{StreamCipher, Transcipherer};
use rand::{Rng, SeedableRng};
use rayon::prelude::*;

const PARAM: ClassicPBSParameters = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
const KEY: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
const IV: u128 = 0x6bc1bee22e409f96e93d7e117393172a;
const EXPECTED: u128 = 0x3ad77bb40d7a3660a89ecaf32466ef97;

// NIST SP 800-38A F.5.1 CTR-AES128 vectors (same key as `KEY`)
const CTR_IV: u128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff;
const CTR_KEYSTREAM: [u128; 4] = [
    0xec8cdf7398607cb0f2d21675ea9ea1e4,
    0x362b7c3c6773516318a077d7fc5073ae,
    0x6a2cc3787889374fbeb4c81b17ba6c44,
    0xe89c399ff0f198c6d40a31db156cabfe,
];

fn decrypt_u128(cks: &ClientKey, bits: &[Ciphertext; 128]) -> u128 {
    let mut bytes = [0u8; 16];
    for (i, ct) in bits.iter().enumerate() {
        let bit = (cks.decrypt(ct) & 1) as u8;
        bytes[i / 8] |= bit << (i % 8);
    }
    u128::from_be_bytes(bytes)
}

fn plain_aes_ctr_keystream(key: u128, iv: u128, n_blocks: usize) -> Vec<u128> {
    let mut stream = AesPlainState::new(key, iv);
    let bytes = stream.next_keystream_bits(128 * n_blocks);
    (0..n_blocks)
        .map(|i| {
            let block_bytes: [u8; 16] = bytes[16 * i..16 * (i + 1)]
                .try_into()
                .expect("16 bytes per block");
            u128::from_be_bytes(block_bytes)
        })
        .collect()
}

fn decrypt_block(cks: &ClientKey, bits: &[Ciphertext]) -> u128 {
    decrypt_u128(
        cks,
        bits.try_into()
            .expect("decrypt_block expects exactly 128 ciphertexts"),
    )
}

fn gen_random_key_iv() -> (u128, u128) {
    let test_name = std::thread::current()
        .name()
        .unwrap_or("unknown")
        .to_string();
    let seed: u64 = rand::thread_rng().gen();
    println!("{test_name}: gen_random_key_iv seed={seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let key: u128 = rng.gen();
    let iv: u128 = rng.gen();
    (key, iv)
}

/// The three `AesIv::from` impls use different byte conventions (`u128` native,
/// `[u8; 16]` big-endian, `[bool; 128]` LSB-first), so each is fed the matching
/// representation of the same `u128`. All must round-trip back through
/// `to_u128()` to the original value.
#[test]
fn aes_iv_from_conversions_round_trip() {
    for v in [
        0u128,
        u128::MAX,
        0x0123456789abcdeffedcba9876543210,
        IV,
        CTR_IV,
    ] {
        let from_u128 = AesIv::from(v);
        let from_bytes = AesIv::from(v.to_be_bytes());
        let ne = v.to_le_bytes();
        let bools: [bool; 128] = std::array::from_fn(|i| (ne[i / 8] >> (i % 8)) & 1 == 1);
        let from_bools = AesIv::from(bools);

        assert_eq!(from_u128.to_u128(), v, "From<u128> round-trip failed");
        assert_eq!(from_bytes.to_u128(), v, "From<[u8; 16]> round-trip failed");
        assert_eq!(
            from_bools.to_u128(),
            v,
            "From<[bool; 128]> round-trip failed"
        );
    }
}

#[test]
fn aes_plain_key_conversions_are_homogeneous() {
    for v in [0u128, u128::MAX, 0x0123456789abcdeffedcba9876543210, KEY] {
        // AES/NIST byte order: bits[0] is the first (most-significant) key byte.
        let key_bytes = v.to_be_bytes();

        let from_u128 = AesPlainKey::from(v);
        let from_bytes = AesPlainKey::from(key_bytes);
        let from_bools = AesPlainKey::from(from_u128.expand());

        // (1) all three describe the same key.
        assert_eq!(
            from_u128.expand(),
            from_bytes.expand(),
            "From<u128> and From<[u8; 16]> disagree"
        );
        assert_eq!(
            from_u128.expand(),
            from_bools.expand(),
            "From<u128> and From<[bool; 128]> disagree"
        );

        // (2) the csprng transport hands the cipher the AES key bytes unchanged.
        assert_eq!(
            from_u128.to_csprng_key_u128().to_ne_bytes(),
            key_bytes,
            "csprng key transport altered the key bytes"
        );
    }
}

/// Anchor the plain side to the NIST SP 800-38A AES-128 vector. The other
/// tests use `AesPlainStream` as oracle.
#[test]
fn plain_aes_matches_nist_vector() {
    let got = plain_aes_ctr_keystream(KEY, IV, 1)[0];
    assert_eq!(
        got, EXPECTED,
        "\n  got      = 0x{got:032x}\n  expected = 0x{EXPECTED:032x}"
    );
}

/// NIST CTR-AES128 known-answer test on the plain stream
#[test]
fn plain_aes_ctr_byte_order_nist() {
    let got = plain_aes_ctr_keystream(KEY, CTR_IV, CTR_KEYSTREAM.len());
    for (i, expected) in CTR_KEYSTREAM.iter().enumerate() {
        assert_eq!(
            got[i], *expected,
            "block {i} differs\n  got      = 0x{:032x}\n  expected = 0x{expected:032x}",
            got[i]
        );
    }
}

/// Reference AES S-box
const REFERENCE_AES_SBOX: [u8; 256] = [
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

#[test]
fn fhe_sbox_exhaustive() {
    let (cks, sks) = gen_keys(PARAM);
    let flush_lut = sks.generate_lookup_table(|x: u64| x & 1);

    let mismatches: Vec<(u8, u8, u8)> = REFERENCE_AES_SBOX
        .into_par_iter()
        .enumerate()
        .filter_map(|(b, expected)| {
            let b = b as u8;
            let mut bits: [Ciphertext; 8] = std::array::from_fn(|j| {
                let mut c = cks.encrypt(((b >> j) & 1) as u64);
                c.degree = Degree::new(1);
                c
            });
            sbox(&sks, &flush_lut, &mut bits);
            let got = (0..8u8).fold(0u8, |acc, j| {
                acc | (((cks.decrypt(&bits[j as usize]) & 1) as u8) << j)
            });
            (got != expected).then_some((b, got, expected))
        })
        .collect();

    assert!(
        mismatches.is_empty(),
        "FHE S-box mismatches (input, got, expected): {mismatches:02x?}"
    );
}

#[test]
fn aes_fhe_known_answer() {
    let (cks, sks) = gen_keys(PARAM);

    let enc_key = AesPlainKey::from(KEY).encrypt(&cks);
    let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
    let mut stream = AesFheState::new(fhe_key, IV);

    let keystream = stream.next_keystream_bits(&sks, 128);
    let got = decrypt_block(&cks, &keystream.into_raw_parts());

    assert_eq!(
        got, EXPECTED,
        "\n  got      = 0x{got:032x}\n  expected = 0x{EXPECTED:032x}"
    );
    assert_eq!(stream.current_counter(), 128);
}

/// FHE counterpart of [`plain_aes_ctr_byte_order_nist`]
#[test]
fn aes_fhe_ctr_byte_order_nist() {
    let (cks, sks) = gen_keys(PARAM);

    let enc_key = AesPlainKey::from(KEY).encrypt(&cks);
    let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
    let mut stream = AesFheState::new(fhe_key, CTR_IV);

    let n_blocks = CTR_KEYSTREAM.len();
    let keystream = stream.next_keystream_bits(&sks, 128 * n_blocks);
    let bits = keystream.into_raw_parts();

    for (i, expected) in CTR_KEYSTREAM.iter().enumerate() {
        let got = decrypt_block(&cks, &bits[128 * i..128 * (i + 1)]);
        assert_eq!(
            got, *expected,
            "block {i} differs\n  got      = 0x{got:032x}\n  expected = 0x{expected:032x}"
        );
    }
    assert_eq!(stream.current_counter(), (128 * n_blocks) as u64);
}

#[test]
fn aes_fhe_matches_plain_random() {
    let (cks, sks) = gen_keys(PARAM);
    let (key, iv) = gen_random_key_iv();
    let n_blocks: usize = 2;

    let plain = plain_aes_ctr_keystream(key, iv, n_blocks);

    let enc_key = AesPlainKey::from(key).encrypt(&cks);
    let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
    let mut stream = AesFheState::new(fhe_key, iv);

    let keystream = stream.next_keystream_bits(&sks, 128 * n_blocks);
    let bits = keystream.into_raw_parts();

    for (i, expected) in plain.iter().enumerate() {
        let got = decrypt_block(&cks, &bits[128 * i..128 * (i + 1)]);
        assert_eq!(
            got, *expected,
            "block {i} differs\n  got      = 0x{got:032x}\n  expected = 0x{expected:032x}"
        );
    }
}

#[test]
fn aes_transcipher_round_trip() {
    let (cks, sks) = gen_keys(PARAM);
    let (key, iv) = gen_random_key_iv();

    let message: [u8; 16] = *b"Hello world!1234";

    let mut plain_stream = AesPlainState::new(key, iv);
    let sym_cipher = plain_stream.encrypt(&message);

    let enc_key = AesPlainKey::from(key).encrypt(&cks);
    let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
    let mut fhe_stream = AesFheState::new(fhe_key, iv);
    let fhe_cipher = fhe_stream.transcipher(&sks, &sym_cipher).unwrap();

    // `apply_keystream` in `2_2` packs two output bits per ciphertext, so 128
    // message bits decode from 64 ciphertexts.
    let mut recovered = [0u8; 16];
    for (i, ct) in fhe_cipher.iter().enumerate() {
        let val = cks.decrypt(ct) & 3;
        let bit_lo = (val & 1) as u8;
        let bit_hi = ((val >> 1) & 1) as u8;
        let idx_lo = 2 * i;
        let idx_hi = 2 * i + 1;
        recovered[idx_lo / 8] |= bit_lo << (idx_lo % 8);
        recovered[idx_hi / 8] |= bit_hi << (idx_hi % 8);
    }

    assert_eq!(
        recovered, message,
        "\n  got      = {recovered:02x?}\n  expected = {message:02x?}"
    );
}

/// Compare `n_bits` of FHE keystream (one single-bit ciphertext per bit)
/// against the plain reference, bit for bit (LSB-first within each byte).
fn assert_keystream_matches(
    cks: &ClientKey,
    fhe_bits: &[Ciphertext],
    plain_bytes: &[u8],
    n_bits: usize,
) {
    assert_eq!(fhe_bits.len(), n_bits, "expected {n_bits} keystream bits");
    for (i, ct) in fhe_bits.iter().enumerate() {
        let got = (cks.decrypt(ct) & 1) as u8;
        let expected = (plain_bytes[i / 8] >> (i % 8)) & 1;
        assert_eq!(got, expected, "keystream bit {i} differs");
    }
}

#[test]
fn aes_fhe_seek() {
    let (cks, sks) = gen_keys(PARAM);

    let (key, iv) = gen_random_key_iv();
    let enc_key = AesPlainKey::from(key).encrypt(&cks);
    let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
    let mut fhe_stream = AesFheState::new(fhe_key, iv);
    let mut plain_stream = AesPlainState::new(key, iv);

    // Counter bookkeeping: forward and backward seeks update the position.
    assert_eq!(fhe_stream.current_counter(), 0);
    fhe_stream.seek(&sks, 192);
    assert_eq!(fhe_stream.current_counter(), 192);

    // After seeking both streams to the same mid-block position, the FHE
    // keystream must match the plain reference bit for bit. Starting at bit 64
    // (mid block 0) and spanning 192 bits exercises the `skip_head` /
    // multi-block path post-seek.
    fhe_stream.seek(&sks, 64);
    plain_stream.seek(64);
    assert_eq!(fhe_stream.current_counter(), 64);

    let n_bits = 192;
    let fhe_bits = fhe_stream
        .next_keystream_bits(&sks, n_bits)
        .into_raw_parts();
    let plain_bytes = plain_stream.next_keystream_bits(n_bits);
    assert_keystream_matches(&cks, &fhe_bits, &plain_bytes, n_bits);
    assert_eq!(fhe_stream.current_counter(), 64 + n_bits as u64);
}

#[test]
fn aes_fhe_non_byte_aligned_n_bits() {
    let (cks, sks) = gen_keys(PARAM);
    let (key, iv) = gen_random_key_iv();

    let enc_key = AesPlainKey::from(key).encrypt(&cks);
    let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
    let mut fhe_stream = AesFheState::new(fhe_key, iv);
    let mut plain_stream = AesPlainState::new(key, iv);

    // 100 bits is not byte-aligned: exercises the `take(n_bits)` truncation on
    // the FHE side and the trailing partial byte on the plain side.
    let n_bits = 100;
    let fhe_bits = fhe_stream
        .next_keystream_bits(&sks, n_bits)
        .into_raw_parts();
    let plain_bytes = plain_stream.next_keystream_bits(n_bits);
    assert_keystream_matches(&cks, &fhe_bits, &plain_bytes, n_bits);
    assert_eq!(fhe_stream.current_counter(), n_bits as u64);
}
