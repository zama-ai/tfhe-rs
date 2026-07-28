use rand::{Rng, SeedableRng};

use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
};
use crate::shortint::prelude::*;
use crate::transciphering::ciphers::kreyvium::KreyviumPlainState;
use crate::transciphering::ciphers::one_time_pad::fhe::{
    OneTimePadFheSecretMask, OneTimePadFheState,
};
use crate::transciphering::ciphers::one_time_pad::{
    OneTimePadPlainSecretMask, OneTimePadPlainState,
};
use crate::transciphering::{
    InsufficientKeystream, StreamCipher, StreamCipherKind, TranscipherError, Transcipherer,
};

/// Reference implementation: LSB-first bit `first_bit + i` of `mask` becomes LSB-first bit
/// `i` of the output, one bit at a time
fn reference_keystream(mask: &[u8], first_bit: usize, n_bits: usize) -> Vec<u8> {
    let mut out = vec![0u8; n_bits.div_ceil(8)];
    for i in 0..n_bits {
        let abs_idx = first_bit + i;
        let bit = (mask[abs_idx / 8] >> (abs_idx % 8)) & 1;
        out[i / 8] |= bit << (i % 8);
    }
    out
}

#[test]
fn one_time_pad_keystream_all_offsets_and_lengths() {
    let max_byte_count = 3usize;
    let max_bit_count = max_byte_count * 8;

    let seed: u64 = rand::thread_rng().gen();
    println!("one_time_pad_keystream_all_offsets_and_lengths seed={seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mask_bytes: Vec<u8> = (0..max_byte_count).map(|_| rng.gen()).collect();

    for max_bit_count in 1..=max_bit_count {
        println!("max_bit_count={max_bit_count}");

        let mut otp = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(
            // to_vec for tests, don't do that in production
            mask_bytes[..max_bit_count.div_ceil(8)].to_vec(),
            max_bit_count,
        ));

        // Exhaustively check every (start offset, length) pair
        for start in 0..max_bit_count {
            for output_bit_count in 0..=(max_bit_count - start) {
                println!("start={start}, output_bit_count={output_bit_count}");
                otp.seek(start as u64);

                let keystream_bits = otp.next_keystream_bits(output_bit_count).unwrap();

                if !output_bit_count.is_multiple_of(8) {
                    // Check the upper bits of the last byte are properly 0 and not leaking some
                    // secret values
                    let bits_in_last_byte = (output_bit_count % 8).try_into().unwrap();
                    // e.g. we have 3 bits in the last byte
                    // MSB repr (to be easier to think about the shift)
                    // [x,x,x,x,x,2,1,0]
                    // u8::MAX << 3 == 0b1111_1000
                    // & =>
                    // [x,x,x,x,x,0,0,0]
                    // the upper "x" should be 0 which is what the assert checks for
                    assert_eq!(
                        keystream_bits.last().copied().unwrap()
                            & (u8::MAX.checked_shl(bits_in_last_byte).unwrap()),
                        0,
                        "keystream_bits {keystream_bits:?}, \
                        start {start}, output_bit_count {output_bit_count}, mask {mask_bytes:?}"
                    );
                }

                assert_eq!(
                    keystream_bits,
                    reference_keystream(&mask_bytes, start, output_bit_count),
                    "start {start}, output_bit_count {output_bit_count}, mask {mask_bytes:02X?}"
                );
                assert_eq!(otp.current_counter(), (start + output_bit_count) as u64);
            }
        }
    }
}

#[test]
fn one_time_pad_random_draws() {
    let seed: u64 = rand::thread_rng().gen();
    println!("one_time_pad_random_draws seed={seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let mask_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    // Cloning for tests, don't do that in production
    let ref_bytes = mask_bytes.clone();
    let bit_count = 8 * mask_bytes.len();

    let mut otp = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(mask_bytes, bit_count));

    let mut remaining = bit_count;

    while remaining != 0 {
        let n_bits = rng.gen_range(0..=remaining);

        println!("n_bits: {n_bits}");

        let start = bit_count - remaining;
        assert_eq!(otp.current_counter(), start as u64);
        assert_eq!(
            otp.next_keystream_bits(n_bits).unwrap(),
            reference_keystream(&ref_bytes, start, n_bits),
            "start {start}, n_bits {n_bits}, mask {ref_bytes:02X?}"
        );
        remaining -= n_bits;
        assert_eq!(otp.remaining_bits(), remaining as u64);
    }

    assert_eq!(otp.remaining_bits(), 0);
    assert_eq!(otp.current_counter(), bit_count as u64);
}

#[test]
fn one_time_pad_encrypt_decrypt() {
    let mut rng = rand::thread_rng();
    let mask_bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    let bit_count = 8 * mask_bytes.len();
    let data: Vec<u8> = (0..5).map(|_| rng.gen()).collect();

    let mut otp = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(mask_bytes, bit_count));

    let encrypted = otp.encrypt(&data).unwrap();
    otp.seek(encrypted.encryption_counter());
    assert_eq!(otp.decrypt(&encrypted).unwrap(), data);
}

#[test]
fn one_time_pad_next_bits_beyond_remaining_errors() {
    let mut otp = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(vec![0u8; 2], 16));
    assert!(matches!(
        otp.next_keystream_bits(17),
        Err(InsufficientKeystream)
    ));
}

// ========== FHE tests below ==========

/// Decrypt `fhe_bits` (one single-bit ciphertext per bit) and compare them,
/// bit for bit, against plain keystream bytes (LSB-first within each byte).
/// Also checks the [`Transcipherer::next_keystream_bits`] contract: each
/// ciphertext is a clean single-bit encryption (degree <= 1, value in {0, 1})
/// Also checks ciphertexts have strictly nominal noise, if checks are made
/// on trivial ciphertexts update this function accordingly.
fn assert_fhe_keystream_matches_plain(
    cks: &ClientKey,
    fhe_bits: &[Ciphertext],
    plain_bytes: &[u8],
    expected_bit_count: usize,
    ctx: &str,
) {
    assert_eq!(
        fhe_bits.len(),
        expected_bit_count,
        "{ctx}: expected one ciphertext per keystream bit"
    );
    for (i, ct) in fhe_bits.iter().enumerate() {
        assert!(
            ct.degree.get() <= 1,
            "{ctx}: keystream bit {i} is not a single bit (degree {})",
            ct.degree.get()
        );
        assert!(
            ct.noise_level() == NoiseLevel::NOMINAL,
            "{ctx}: keystream bit {i} exceeds nominal noise (level {:?})",
            ct.noise_level()
        );
        let got = cks.decrypt_message_and_carry(ct);
        assert!(
            got <= 1,
            "{ctx}: keystream bit {i} decrypts to non-boolean value {got}"
        );
        let expected = ((plain_bytes[i / 8] >> (i % 8)) & 1) as u64;
        assert_eq!(got, expected, "{ctx}: keystream bit {i} differs");
    }
}

/// Decode the output of [`Transcipherer::transcipher`]: each ciphertext packs
/// up to `m = log2(message_modulus)` plaintext bits, LSB-first across the
/// stream, the last ciphertext possibly holding fewer. Returns
/// `n_bits.div_ceil(8)` bytes.
fn decrypt_transciphered_bytes(
    cks: &ClientKey,
    cts: &[Ciphertext],
    expected_bit_count: usize,
) -> Vec<u8> {
    let message_bits = cks.parameters().message_modulus().0.ilog2() as usize;
    assert_eq!(
        cts.len(),
        expected_bit_count.div_ceil(message_bits),
        "unexpected transciphered ciphertext count for {expected_bit_count} bits"
    );
    let mut bytes = vec![0u8; expected_bit_count.div_ceil(8)];

    let plaintexts: Vec<u64> = cts.iter().map(|ct| cks.decrypt(ct)).collect();

    for bit_idx in 0..expected_bit_count {
        let plaintext_idx = bit_idx / message_bits;
        let idx_in_plaintext = bit_idx % message_bits;
        let out_byte_idx = bit_idx / 8;
        let idx_in_out_byte = bit_idx % 8;

        bytes[out_byte_idx] |=
            (((plaintexts[plaintext_idx] >> idx_in_plaintext) & 1) as u8) << idx_in_out_byte;
    }

    bytes
}

/// FHE keystream == plain keystream for every (start offset, length) pair.
///
/// `bit_count` is deliberately not a multiple of 8 so that
/// [`OneTimePadPlainSecretMask::encrypt`] has to deal with a partial trailing
/// mask byte. Seeks both sides before every draw, so this test isolates mask
/// encryption/slicing from counter bookkeeping (covered separately).
#[test]
fn one_time_pad_fhe_keystream_matches_plain_all_offsets_and_lengths() {
    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    let seed: u64 = rand::thread_rng().gen();
    println!("one_time_pad_fhe_keystream_matches_plain_all_offsets_and_lengths seed={seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let byte_count = 3usize;
    let max_bit_count = byte_count * 8;
    let mask_bytes: Vec<u8> = (0..byte_count).map(|_| rng.gen()).collect();

    for max_bit_count in 0..=max_bit_count {
        // to_vec for tests, don't do that in production
        let curr_mask_bytes = mask_bytes[..max_bit_count.div_ceil(8)].to_vec();
        let plain_mask = OneTimePadPlainSecretMask::new(curr_mask_bytes, max_bit_count);
        let fhe_mask = plain_mask.encrypt(&cks);
        let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
        let mut plain_otp = OneTimePadPlainState::new(plain_mask);

        for start in 0..max_bit_count {
            for output_bit_count in 0..=(max_bit_count - start) {
                plain_otp.seek(start as u64);
                fhe_otp.seek(&sks, start as u64);

                let plain_bytes = plain_otp.next_keystream_bits(output_bit_count).unwrap();
                let fhe_bits = fhe_otp
                    .next_keystream_bits(&sks, output_bit_count)
                    .unwrap()
                    .into_raw_parts();

                assert_fhe_keystream_matches_plain(
                    &cks,
                    &fhe_bits,
                    &plain_bytes,
                    output_bit_count,
                    &format!("start={start}, output_bit_count={output_bit_count}"),
                );
            }
        }
    }
}

/// Back-to-back draws must return consecutive mask segments and advance
/// `current_counter` / `remaining_bits` exactly like the plain side does.
#[test]
fn one_time_pad_fhe_sequential_draws_advance_counter() {
    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    let seed: u64 = rand::thread_rng().gen();
    println!("one_time_pad_fhe_sequential_draws_advance_counter seed={seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let mask_bytes: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
    let bit_count = 8 * mask_bytes.len();

    let plain_mask = OneTimePadPlainSecretMask::new(mask_bytes, bit_count);
    let fhe_mask = plain_mask.encrypt(&cks);
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    let mut plain_otp = OneTimePadPlainState::new(plain_mask);

    assert_eq!(fhe_otp.current_counter(), 0);
    assert_eq!(fhe_otp.remaining_bits(), 64);

    let first_fhe = fhe_otp
        .next_keystream_bits(&sks, 24)
        .unwrap()
        .into_raw_parts();
    let first_plain = plain_otp.next_keystream_bits(24).unwrap();
    assert_eq!(
        fhe_otp.current_counter(),
        24,
        "next_keystream_bits must advance the counter"
    );
    assert_eq!(fhe_otp.remaining_bits(), 40);
    assert_fhe_keystream_matches_plain(&cks, &first_fhe, &first_plain, 24, "first draw");

    // Zero-bit draw: empty keystream, counter untouched.
    assert!(fhe_otp
        .next_keystream_bits(&sks, 0)
        .unwrap()
        .into_raw_parts()
        .is_empty());
    assert_eq!(fhe_otp.current_counter(), 24);

    let second_fhe = fhe_otp
        .next_keystream_bits(&sks, 40)
        .unwrap()
        .into_raw_parts();
    let second_plain = plain_otp.next_keystream_bits(40).unwrap();
    assert_eq!(fhe_otp.current_counter(), 64);
    assert_eq!(fhe_otp.remaining_bits(), 0);
    assert_fhe_keystream_matches_plain(&cks, &second_fhe, &second_plain, 40, "second draw");

    // Backward seek: the OTP re-emits the exact same pad bits.
    fhe_otp.seek(&sks, 24);
    assert_eq!(fhe_otp.current_counter(), 24);
    assert_eq!(fhe_otp.remaining_bits(), 40);
    let second_again = fhe_otp
        .next_keystream_bits(&sks, 40)
        .unwrap()
        .into_raw_parts();
    assert_fhe_keystream_matches_plain(&cks, &second_again, &second_plain, 40, "re-drawn second");

    // Seeking to the exact end of the mask is allowed and leaves nothing to
    // draw.
    fhe_otp.seek(&sks, bit_count as u64);
    assert_eq!(fhe_otp.remaining_bits(), 0);
    assert!(fhe_otp
        .next_keystream_bits(&sks, 0)
        .unwrap()
        .into_raw_parts()
        .is_empty());
}

/// End-to-end: the client encrypts a sequence of messages with the plain OTP,
/// the server transciphers them in order, the client decrypts the FHE blocks
/// and must recover the original bits.
///
/// The sequence contains a byte-aligned message, an empty one and a 13-bit one
/// so that both `apply_keystream` implementations get exercised on their
/// partial-block branches: under 2_2 the odd trailing keystream bit, under
/// other parameters the partial final packing chunk.
fn one_time_pad_fhe_transcipher_round_trip_impl(params: ClassicPBSParameters) {
    let seed: u64 = rand::thread_rng().gen();
    println!("one_time_pad_fhe_transcipher_round_trip seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let (cks, sks) = gen_keys(params);

    let mask_bytes: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
    let bit_count = 8 * mask_bytes.len();

    let plain_mask = OneTimePadPlainSecretMask::new(mask_bytes, bit_count);
    let fhe_mask = plain_mask.encrypt(&cks);
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    let mut plain_otp = OneTimePadPlainState::new(plain_mask);

    let msg_a: (Vec<u8>, usize) = ((0..5).map(|_| rng.gen()).collect(), 40);
    let msg_b: (Vec<u8>, usize) = (vec![], 0);
    let msg_c: (Vec<u8>, usize) = (rng.gen_range(0u16..(1 << 13)).to_le_bytes().to_vec(), 13);

    for (i, (message, n_bits)) in [msg_a, msg_b, msg_c].into_iter().enumerate() {
        let sym_cipher = plain_otp.encrypt_bits(&message, n_bits).unwrap();
        let transciphered = fhe_otp
            .transcipher(&sks, &sym_cipher)
            .unwrap_or_else(|e| panic!("transcipher failed for message {i} (seed={seed}): {e:?}"));

        let recovered = decrypt_transciphered_bytes(&cks, &transciphered, n_bits);

        assert_eq!(recovered, message, "message {i} (seed={seed})");
        assert_eq!(fhe_otp.current_counter(), plain_otp.current_counter());
    }
}

#[test]
fn one_time_pad_fhe_transcipher_round_trip() {
    one_time_pad_fhe_transcipher_round_trip_impl(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
}

/// Non-2_2 parameters fall back to `apply_keystream_naive`; the OTP is the
/// cheapest cipher to round-trip that path with (the Kreyvium 1_1/3_3 tests
/// stop at the raw keystream).
#[test]
fn one_time_pad_fhe_transcipher_round_trip_1_1() {
    one_time_pad_fhe_transcipher_round_trip_impl(
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    );
}

#[test]
fn one_time_pad_fhe_transcipher_round_trip_3_3() {
    one_time_pad_fhe_transcipher_round_trip_impl(
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    );
}

/// `transcipher` must refuse foreign-cipher and misaligned inputs with the
/// documented errors, leave the state untouched when refusing, and recover
/// through `seek`.
/// Also covers backward seek as random access to an earlier, skipped message.
#[test]
fn one_time_pad_fhe_transcipher_error_paths() {
    use rand::SeedableRng;

    let seed: u64 = rand::thread_rng().gen();
    println!("one_time_pad_fhe_transcipher_error_paths seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    let mask_bytes: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
    let bit_count = 8 * mask_bytes.len();

    let plain_mask = OneTimePadPlainSecretMask::new(mask_bytes, bit_count);
    let fhe_mask = plain_mask.encrypt(&cks);
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    assert_eq!(fhe_otp.kind(), StreamCipherKind::OneTimePad);

    let mut plain_otp = OneTimePadPlainState::new(plain_mask);

    // A ciphertext from another cipher family is refused.
    let key_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
    let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
    let kreyvium_ct = KreyviumPlainState::new(key_bits, iv_bits)
        .encrypt(&[0u8; 4])
        .unwrap();
    let err = fhe_otp
        .transcipher(&sks, &kreyvium_ct)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(
        err,
        TranscipherError::KindMismatch {
            session_kind: StreamCipherKind::OneTimePad,
            ciphertext_kind: StreamCipherKind::Kreyvium,
        }
    );

    // Client encrypts two messages; the server sees the second one first.
    let msg_1: Vec<u8> = (0..3).map(|_| rng.gen()).collect();
    let msg_2: Vec<u8> = (0..4).map(|_| rng.gen()).collect();
    let ct_1 = plain_otp.encrypt(&msg_1).unwrap(); // bits 0..24
    let ct_2 = plain_otp.encrypt(&msg_2).unwrap(); // bits 24..56

    let err = fhe_otp.transcipher(&sks, &ct_2).map(|_| ()).unwrap_err();
    assert_eq!(
        err,
        TranscipherError::CounterMismatch {
            session_counter: 0,
            ciphertext_counter: 24,
        }
    );
    // The hint points at the ciphertext's absolute counter.
    assert_eq!(
        err.to_string(),
        "stream ciphertext counter mismatch: session at 0, \
        ciphertext at 24. Call `seek(24)` to align"
    );
    // A refused transcipher must not consume keystream.
    assert_eq!(fhe_otp.current_counter(), 0);

    // Documented recovery: seek to the ciphertext's counter and retry.
    fhe_otp.seek(&sks, ct_2.encryption_counter());
    let out_2 = fhe_otp.transcipher(&sks, &ct_2).unwrap();
    assert_eq!(
        decrypt_transciphered_bytes(&cks, &out_2, 32),
        msg_2,
        "seed={seed}"
    );

    // The session (56) can also be ahead of a ciphertext (0): same error, and
    // the hint must still point at the ciphertext's counter.
    let err = fhe_otp.transcipher(&sks, &ct_1).map(|_| ()).unwrap_err();
    assert_eq!(
        err,
        TranscipherError::CounterMismatch {
            session_counter: 56,
            ciphertext_counter: 0,
        }
    );
    assert_eq!(
        err.to_string(),
        "stream ciphertext counter mismatch: session at 56, \
        ciphertext at 0. Call `seek(0)` to align"
    );

    // Backward seek gives random access to the skipped first message.
    fhe_otp.seek(&sks, ct_1.encryption_counter());
    let out_1 = fhe_otp.transcipher(&sks, &ct_1).unwrap();
    assert_eq!(
        decrypt_transciphered_bytes(&cks, &out_1, 24),
        msg_1,
        "seed={seed}"
    );
}

/// Mask constructors validate their inputs: plain masks take
/// `bit_count.div_ceil(8)` bytes; FHE mask ciphertexts must be clean
/// single-bit encryptions.
#[test]
fn one_time_pad_mask_validation() {
    let cks = ClientKey::new(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    assert!(OneTimePadPlainSecretMask::try_new(vec![0u8; 2], 17).is_err());
    assert!(OneTimePadPlainSecretMask::try_new(vec![0u8; 3], 17).is_ok());

    // Cloning for tests, don't do that in production
    let cts: Vec<Ciphertext> = (0..5).map(|_| cks.encrypt_bool(false)).collect();
    assert!(OneTimePadFheSecretMask::try_new(cts.clone()).is_ok());

    // A ciphertext that may encrypt more than a single bit is refused.
    let mut degree_cts = cts.clone();
    degree_cts[3] = cks.encrypt(2);
    assert_eq!(
        OneTimePadFheSecretMask::try_new(degree_cts).map(|_| ()),
        Err("Mask ciphertexts must encrypt single bits (degree <= 1).")
    );

    // A ciphertext with above-nominal noise is refused.
    let mut noisy_cts = cts;
    noisy_cts[3].set_noise_level(NoiseLevel::NOMINAL * 2, cks.parameters().max_noise_level());
    assert_eq!(
        OneTimePadFheSecretMask::try_new(noisy_cts).map(|_| ()),
        Err("Mask ciphertexts must have at most nominal noise.")
    );
}

// The `_sks` argument is unused by the OTP (no bootstrapping happens to draw
// keystream bits), so the error test below use the cheapest parameters to
// generate.

#[test]
fn one_time_pad_fhe_next_bits_beyond_remaining_errors() {
    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
    let fhe_mask = OneTimePadPlainSecretMask::new(vec![0u8; 2], 16).encrypt(&cks);
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    assert!(matches!(
        fhe_otp.next_keystream_bits(&sks, 17),
        Err(InsufficientKeystream)
    ));
}
