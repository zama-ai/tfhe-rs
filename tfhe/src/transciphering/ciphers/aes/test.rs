use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::prelude::*;
use crate::transciphering::ciphers::aes::{
    decrypt_u128, encrypt_u128, AesFheKey, AesFheStream, AesPlainStream,
};
use crate::transciphering::{StreamCipher, Transcipherer};

const PARAM: ClassicPBSParameters = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

fn plain_aes_ctr_keystream(key: u128, iv: u128, n_blocks: usize) -> Vec<u128> {
    let mut stream = AesPlainStream::new(key, iv);
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

/// Anchor the plain side to the NIST SP 800-38A AES-128 vector. The other
/// tests use `AesPlainStream` as oracle.
#[test]
fn plain_aes_matches_nist_vector() {
    let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    let iv: u128 = 0x6bc1bee22e409f96e93d7e117393172a;
    let expected: u128 = 0x3ad77bb40d7a3660a89ecaf32466ef97;

    let got = plain_aes_ctr_keystream(key, iv, 1)[0];
    assert_eq!(
        got, expected,
        "\n  got      = 0x{got:032x}\n  expected = 0x{expected:032x}"
    );
}

#[test]
fn aes_fhe_known_answer() {
    let (cks, sks) = gen_keys(PARAM);

    let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    let iv: u128 = 0x6bc1bee22e409f96e93d7e117393172a;
    let expected: u128 = 0x3ad77bb40d7a3660a89ecaf32466ef97;

    let enc_key = encrypt_u128(&cks, key);
    let fhe_key = AesFheKey::new(&sks, &enc_key);
    let mut stream = AesFheStream::new(fhe_key, iv);

    let keystream = stream.next_keystream_bits(&sks, 128);
    let got = decrypt_block(&cks, &keystream.into_raw_parts());

    assert_eq!(
        got, expected,
        "\n  got      = 0x{got:032x}\n  expected = 0x{expected:032x}"
    );
    assert_eq!(stream.current_counter(), 128);
}

#[test]
fn aes_fhe_matches_plain_random() {
    use rand::{Rng, SeedableRng};

    let seed: u64 = rand::thread_rng().gen();
    println!("aes_fhe_matches_plain_random seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let (cks, sks) = gen_keys(PARAM);

    let key: u128 = rng.gen();
    let iv: u128 = rng.gen();
    let n_blocks: usize = 2;

    let plain = plain_aes_ctr_keystream(key, iv, n_blocks);

    let enc_key = encrypt_u128(&cks, key);
    let fhe_key = AesFheKey::new(&sks, &enc_key);
    let mut stream = AesFheStream::new(fhe_key, iv);

    let keystream = stream.next_keystream_bits(&sks, 128 * n_blocks);
    let bits = keystream.into_raw_parts();

    for (i, expected) in plain.iter().enumerate() {
        let got = decrypt_block(&cks, &bits[128 * i..128 * (i + 1)]);
        assert_eq!(
            got, *expected,
            "block {i} differs (seed={seed})\n  got      = 0x{got:032x}\n  expected = 0x{expected:032x}"
        );
    }
}

#[test]
fn aes_transcipher_round_trip() {
    let (cks, sks) = gen_keys(PARAM);

    let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    let iv: u128 = 0x6bc1bee22e409f96e93d7e117393172a;
    let message: [u8; 16] = *b"Hello world!1234";

    let mut plain_stream = AesPlainStream::new(key, iv);
    let sym_cipher = plain_stream.encrypt(&message);

    let enc_key = encrypt_u128(&cks, key);
    let fhe_key = AesFheKey::new(&sks, &enc_key);
    let mut fhe_stream = AesFheStream::new(fhe_key, iv);
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

    let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    let iv: u128 = 0x6bc1bee22e409f96e93d7e117393172a;

    let enc_key = encrypt_u128(&cks, key);
    let fhe_key = AesFheKey::new(&sks, &enc_key);
    let mut fhe_stream = AesFheStream::new(fhe_key, iv);
    let mut plain_stream = AesPlainStream::new(key, iv);

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

    let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    let iv: u128 = 0x6bc1bee22e409f96e93d7e117393172a;

    let enc_key = encrypt_u128(&cks, key);
    let fhe_key = AesFheKey::new(&sks, &enc_key);
    let mut fhe_stream = AesFheStream::new(fhe_key, iv);
    let mut plain_stream = AesPlainStream::new(key, iv);

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
