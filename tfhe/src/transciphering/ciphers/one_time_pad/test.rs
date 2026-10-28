use rand::{Rng, SeedableRng};

use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
};
use crate::shortint::parameters::TranscipheringParameters;
use crate::shortint::prelude::*;
use crate::transciphering::ciphers::kreyvium::KreyviumPlainState;
use crate::transciphering::ciphers::one_time_pad::fhe::{
    MaskGenerationError, OneTimePadFheSecretMask, OneTimePadFheState,
};
use crate::transciphering::ciphers::one_time_pad::{
    OneTimePadPlainSecretMask, OneTimePadPlainState,
};
use crate::transciphering::{
    FheKeyStream, FheKeyStreamError, InsufficientKeystream, KeyStreamLayout, StreamCipher,
    StreamCipherKind, TranscipherError, Transcipherer, TranscipheringOutputLayout,
    TranscipheringPrivateKey, TranscipheringServerKey,
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

/// Decrypt `keystream` (`bits_per_ct` keystream bits per ciphertext, LSB-first) and compare it,
/// bit for bit, against plain keystream bytes (LSB-first within each byte). The unused high bits
/// of the last ciphertext are not compared.
/// Also checks the [`Transcipherer::next_keystream_bits`] contract: the keystream layout has
/// `bits_per_ct` bits per ciphertext, and each ciphertext holds at most `bits_per_ct` bits
/// (degree and decrypted value < 2^bits_per_ct)
/// Also checks ciphertexts have strictly nominal noise, if checks are made
/// on trivial ciphertexts update this function accordingly.
fn assert_fhe_keystream_matches_plain(
    cks: &ClientKey,
    keystream: &FheKeyStream,
    bits_per_ct: usize,
    plain_bytes: &[u8],
    expected_bit_count: usize,
    ctx: &str,
) {
    assert_eq!(
        usize::from(keystream.layout().bits_per_ct().get()),
        bits_per_ct,
        "{ctx}: unexpected keystream layout"
    );
    let fhe_bits: Vec<_> = keystream.iter().collect();
    assert_eq!(
        fhe_bits.len(),
        expected_bit_count.div_ceil(bits_per_ct),
        "{ctx}: expected one ciphertext per {bits_per_ct} keystream bits"
    );
    for (i, ct) in fhe_bits.iter().enumerate() {
        assert!(
            ct.degree.get() < (1 << bits_per_ct),
            "{ctx}: keystream ciphertext {i} holds more than {bits_per_ct} bits (degree {})",
            ct.degree.get()
        );
        assert!(
            ct.noise_level() == NoiseLevel::NOMINAL,
            "{ctx}: keystream ciphertext {i} exceeds nominal noise (level {:?})",
            ct.noise_level()
        );
        let value = cks.decrypt_message_and_carry(ct);
        assert!(
            value < (1 << bits_per_ct),
            "{ctx}: keystream ciphertext {i} decrypts to {value}, more than {bits_per_ct} bits"
        );
    }
    for bit_idx in 0..expected_bit_count {
        let got = (cks.decrypt_message_and_carry(fhe_bits[bit_idx / bits_per_ct])
            >> (bit_idx % bits_per_ct))
            & 1;
        let expected = ((plain_bytes[bit_idx / 8] >> (bit_idx % 8)) & 1) as u64;
        assert_eq!(got, expected, "{ctx}: keystream bit {bit_idx} differs");
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
/// Seeks both sides before every draw, so this test isolates mask encryption/slicing from counter
/// bookkeeping (covered separately). Starts that are not aligned on a mask ciphertext are refused
/// without consuming keystream.
#[test]
fn one_time_pad_fhe_keystream_matches_plain_all_offsets_and_lengths() {
    for params in [
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    ] {
        let (cks, sks) = gen_keys(params);
        let full_space =
            KeyStreamLayout::full_space(sks.message_modulus, sks.carry_modulus).unwrap();

        for layout in [full_space, KeyStreamLayout::single_bit()] {
            one_time_pad_fhe_keystream_matches_plain_all_offsets_and_lengths_impl(
                &cks, &sks, &layout,
            );
        }
    }
}

fn one_time_pad_fhe_keystream_matches_plain_all_offsets_and_lengths_impl(
    cks: &ClientKey,
    sks: &ServerKey,
    layout: &KeyStreamLayout,
) {
    let bits_per_ct = usize::from(layout.bits_per_ct().get());

    let seed: u64 = rand::thread_rng().gen();
    println!(
        "one_time_pad_fhe_keystream_matches_plain_all_offsets_and_lengths \
        bits_per_ct={bits_per_ct} seed={seed}"
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let byte_count = 3usize;
    let max_bit_count = byte_count * 8;
    let mask_bytes: Vec<u8> = (0..byte_count).map(|_| rng.gen()).collect();

    // Mask sizes must be a multiple of the number of bits per ciphertext
    for max_bit_count in (0..=max_bit_count).step_by(bits_per_ct) {
        // to_vec for tests, don't do that in production
        let curr_mask_bytes = mask_bytes[..max_bit_count.div_ceil(8)].to_vec();
        let plain_mask = OneTimePadPlainSecretMask::new(curr_mask_bytes, max_bit_count);
        let fhe_mask = plain_mask.encrypt_with_layout(cks, layout.clone()).unwrap();
        let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
        let mut plain_otp = OneTimePadPlainState::new(plain_mask);

        for start in 0..max_bit_count {
            for output_bit_count in 0..=(max_bit_count - start) {
                let ctx = format!(
                    "bits_per_ct={bits_per_ct}, start={start}, \
                    output_bit_count={output_bit_count}, seed={seed}"
                );
                plain_otp.seek(start as u64);
                fhe_otp.seek(sks, start as u64);

                if !start.is_multiple_of(bits_per_ct) {
                    assert!(
                        matches!(
                            fhe_otp.next_keystream_bits(sks, output_bit_count),
                            Err(FheKeyStreamError::InvalidStreamCipherState)
                        ),
                        "{ctx}: unaligned draw should be refused"
                    );
                    assert_eq!(fhe_otp.current_counter(), start as u64, "{ctx}");
                    continue;
                }

                let plain_bytes = plain_otp.next_keystream_bits(output_bit_count).unwrap();
                let fhe_bits = fhe_otp.next_keystream_bits(sks, output_bit_count).unwrap();

                assert_fhe_keystream_matches_plain(
                    cks,
                    &fhe_bits,
                    bits_per_ct,
                    &plain_bytes,
                    output_bit_count,
                    &ctx,
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
    let fhe_mask = plain_mask.encrypt(&cks).unwrap();
    let bits_per_ct = usize::from(fhe_mask.layout().bits_per_ct().get());
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    let mut plain_otp = OneTimePadPlainState::new(plain_mask);

    assert_eq!(fhe_otp.current_counter(), 0);
    assert_eq!(fhe_otp.remaining_bits(), 64);

    let first_fhe = fhe_otp.next_keystream_bits(&sks, 24).unwrap();
    let first_plain = plain_otp.next_keystream_bits(24).unwrap();
    assert_eq!(
        fhe_otp.current_counter(),
        24,
        "next_keystream_bits must advance the counter"
    );
    assert_eq!(fhe_otp.remaining_bits(), 40);
    assert_fhe_keystream_matches_plain(
        &cks,
        &first_fhe,
        bits_per_ct,
        &first_plain,
        24,
        "first draw",
    );

    // Zero-bit draw: empty keystream, counter untouched.
    assert!(fhe_otp
        .next_keystream_bits(&sks, 0)
        .unwrap()
        .into_raw_parts()
        .0
        .is_empty());
    assert_eq!(fhe_otp.current_counter(), 24);

    let second_fhe = fhe_otp.next_keystream_bits(&sks, 40).unwrap();
    let second_plain = plain_otp.next_keystream_bits(40).unwrap();
    assert_eq!(fhe_otp.current_counter(), 64);
    assert_eq!(fhe_otp.remaining_bits(), 0);
    assert_fhe_keystream_matches_plain(
        &cks,
        &second_fhe,
        bits_per_ct,
        &second_plain,
        40,
        "second draw",
    );

    // Backward seek: the OTP re-emits the exact same pad bits.
    fhe_otp.seek(&sks, 24);
    assert_eq!(fhe_otp.current_counter(), 24);
    assert_eq!(fhe_otp.remaining_bits(), 40);
    let second_again = fhe_otp.next_keystream_bits(&sks, 40).unwrap();
    assert_fhe_keystream_matches_plain(
        &cks,
        &second_again,
        bits_per_ct,
        &second_plain,
        40,
        "re-drawn second",
    );

    // Seeking to the exact end of the mask is allowed and leaves nothing to
    // draw.
    fhe_otp.seek(&sks, bit_count as u64);
    assert_eq!(fhe_otp.remaining_bits(), 0);
    assert!(fhe_otp
        .next_keystream_bits(&sks, 0)
        .unwrap()
        .into_raw_parts()
        .0
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
fn one_time_pad_fhe_transcipher_round_trip_impl(
    params: ClassicPBSParameters,
    layout: Option<KeyStreamLayout>,
) {
    let seed: u64 = rand::thread_rng().gen();
    println!("one_time_pad_fhe_transcipher_round_trip seed: {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let (cks, sks) = gen_keys(params);

    let mask_bytes: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
    let bit_count = 8 * mask_bytes.len();

    let plain_mask = OneTimePadPlainSecretMask::new(mask_bytes, bit_count);
    let fhe_mask = layout
        .map_or_else(
            || plain_mask.encrypt(&cks),
            |layout| plain_mask.encrypt_with_layout(&cks, layout),
        )
        .unwrap();
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    let mut plain_otp = OneTimePadPlainState::new(plain_mask);

    let msg_a: (Vec<u8>, usize) = ((0..5).map(|_| rng.gen()).collect(), 40);
    let msg_b: (Vec<u8>, usize) = (vec![], 0);
    let msg_c: (Vec<u8>, usize) = (rng.gen_range(0u16..(1 << 13)).to_le_bytes().to_vec(), 13);

    for (i, (message, n_bits)) in [msg_a, msg_b, msg_c].into_iter().enumerate() {
        let layout = TranscipheringOutputLayout::radix(n_bits, sks.message_modulus);
        let sym_cipher = plain_otp.encrypt_bits(&message, n_bits).unwrap();
        let transciphered = fhe_otp
            .transcipher(&sks, &sym_cipher, &layout)
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
        None,
    );
}

#[test]
fn one_time_pad_fhe_transcipher_round_trip_1_1() {
    one_time_pad_fhe_transcipher_round_trip_impl(
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        None,
    );
}

/// The full space of 3_3 params (6 bits) is not a valid layout, and the 3 bits output blocks
/// can only be built from single bit keystream ciphertexts.
#[test]
fn one_time_pad_fhe_transcipher_round_trip_3_3() {
    one_time_pad_fhe_transcipher_round_trip_impl(
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        Some(KeyStreamLayout::single_bit()),
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
    let fhe_mask = plain_mask.encrypt(&cks).unwrap();
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    assert_eq!(fhe_otp.kind(), StreamCipherKind::OneTimePad);

    let mut plain_otp = OneTimePadPlainState::new(plain_mask);

    // A ciphertext from another cipher family is refused.
    let key_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
    let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
    let kreyvium_ct = KreyviumPlainState::new(key_bits, iv_bits)
        .encrypt(&[0u8; 4])
        .unwrap();
    let layout = TranscipheringOutputLayout::radix(kreyvium_ct.n_bits(), sks.message_modulus);
    let err = fhe_otp
        .transcipher(&sks, &kreyvium_ct, &layout)
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
    let layout_1 = TranscipheringOutputLayout::radix(ct_1.n_bits(), sks.message_modulus);
    let ct_2 = plain_otp.encrypt(&msg_2).unwrap(); // bits 24..56
    let layout_2 = TranscipheringOutputLayout::radix(ct_2.n_bits(), sks.message_modulus);

    let err = fhe_otp
        .transcipher(&sks, &ct_2, &layout_2)
        .map(|_| ())
        .unwrap_err();
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
    let out_2 = fhe_otp.transcipher(&sks, &ct_2, &layout_2).unwrap();
    assert_eq!(
        decrypt_transciphered_bytes(&cks, &out_2, 32),
        msg_2,
        "seed={seed}"
    );

    // The session (56) can also be ahead of a ciphertext (0): same error, and
    // the hint must still point at the ciphertext's counter.
    let err = fhe_otp
        .transcipher(&sks, &ct_1, &layout_1)
        .map(|_| ())
        .unwrap_err();
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
    let out_1 = fhe_otp.transcipher(&sks, &ct_1, &layout_1).unwrap();
    assert_eq!(
        decrypt_transciphered_bytes(&cks, &out_1, 24),
        msg_1,
        "seed={seed}"
    );
}

/// A stream ciphertext whose byte buffer does not match its bit count is refused before any
/// keystream is drawn.
#[test]
fn one_time_pad_fhe_transcipher_invalid_stream_ciphertext() {
    #[derive(serde::Serialize)]
    struct Tampered {
        kind: StreamCipherKind,
        encryption_counter: u64,
        n_bits: usize,
        bytes: Vec<u8>,
    }

    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    let fhe_mask = OneTimePadPlainSecretMask::new(vec![0u8; 16], 128)
        .encrypt(&cks)
        .unwrap();
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    let layout = TranscipheringOutputLayout::radix(64, sks.message_modulus);

    // Too short and too long buffers for 64 bits
    for n_bytes in [4, 9] {
        let tampered = bincode::serialize(&Tampered {
            kind: StreamCipherKind::OneTimePad,
            encryption_counter: 0,
            n_bits: 64,
            bytes: vec![0; n_bytes],
        })
        .unwrap();
        let tampered: crate::transciphering::StreamCiphertext =
            bincode::deserialize(&tampered).unwrap();

        let err = fhe_otp
            .transcipher(&sks, &tampered, &layout)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            err,
            TranscipherError::InvalidStreamCiphertext,
            "n_bytes {n_bytes}"
        );
        // A refused transcipher must not consume keystream.
        assert_eq!(fhe_otp.current_counter(), 0, "n_bytes {n_bytes}");
    }
}

/// Mask constructors validate their inputs: plain masks take
/// `bit_count.div_ceil(8)` bytes; FHE mask ciphertexts must be clean
/// encryptions following the mask layout.
#[test]
fn one_time_pad_mask_validation() {
    let cks = ClientKey::new(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    assert!(OneTimePadPlainSecretMask::try_new(vec![0u8; 2], 17).is_err());
    assert!(OneTimePadPlainSecretMask::try_new(vec![0u8; 3], 17).is_ok());

    // Cloning for tests, don't do that in production
    let cts: Vec<Ciphertext> = (0..5).map(|_| cks.encrypt_bool(false)).collect();
    assert!(OneTimePadFheSecretMask::try_new(cts.clone(), KeyStreamLayout::single_bit()).is_ok());

    // Single bit ciphertexts do not follow a layout with more bits per ciphertext.
    let full_space = KeyStreamLayout::full_space(
        cks.parameters().message_modulus(),
        cks.parameters().carry_modulus(),
    )
    .unwrap();
    assert!(OneTimePadFheSecretMask::try_new(cts.clone(), full_space).is_err());

    // A ciphertext that may encrypt more than a single bit is refused.
    let mut degree_cts = cts.clone();
    degree_cts[3] = cks.encrypt(2);
    assert!(OneTimePadFheSecretMask::try_new(degree_cts, KeyStreamLayout::single_bit()).is_err());

    // A ciphertext with above-nominal noise is refused.
    let mut noisy_cts = cts;
    noisy_cts[3].set_noise_level(NoiseLevel::NOMINAL * 2, cks.parameters().max_noise_level());
    assert!(OneTimePadFheSecretMask::try_new(noisy_cts, KeyStreamLayout::single_bit()).is_err());

    // The mask size must be a multiple of the number of bits per ciphertext.
    assert!(matches!(
        OneTimePadPlainSecretMask::new(vec![0u8; 2], 10).encrypt(&cks),
        Err(MaskGenerationError::InvalidMaskSize)
    ));

    // The full space of 3_3 params (6 bits) is not a valid layout.
    let cks_3_3 = ClientKey::new(TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128);
    assert!(matches!(
        OneTimePadPlainSecretMask::new(vec![0u8; 2], 16).encrypt(&cks_3_3),
        Err(MaskGenerationError::IncompatibleParameters)
    ));
}

#[test]
fn one_time_pad_fhe_secret_mask_conformance() {
    use crate::conformance::ParameterSetConformant;
    use crate::shortint::AtomicPatternParameters;

    let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let cks = ClientKey::new(params);
    let conformance_params = AtomicPatternParameters::from(params).to_shortint_conformance_param();

    let plain_mask = OneTimePadPlainSecretMask::new(vec![0xAB; 2], 16);
    let mask = plain_mask.encrypt(&cks).unwrap();
    assert!(mask.is_conformant(&conformance_params));
    let single_bit_mask = plain_mask
        .encrypt_with_layout(&cks, KeyStreamLayout::single_bit())
        .unwrap();
    assert!(single_bit_mask.is_conformant(&conformance_params));

    // A layout that does not fit in the parameters is refused at encryption.
    let cks_1_1 = ClientKey::new(TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
    let layout_4 = KeyStreamLayout::new(4.try_into().unwrap()).unwrap();
    assert!(matches!(
        plain_mask.encrypt_with_layout(&cks_1_1, layout_4),
        Err(MaskGenerationError::IncompatibleParameters)
    ));

    // Same serialized form as the mask, with a raw layout
    #[derive(serde::Serialize)]
    struct Tampered {
        secret_mask: Vec<Ciphertext>,
        bits_per_ct: u8,
    }

    let tamper = |bits_per_ct| {
        bincode::serialize(&Tampered {
            secret_mask: mask.ciphertexts().to_vec(),
            bits_per_ct,
        })
        .unwrap()
    };

    let untampered: OneTimePadFheSecretMask = bincode::deserialize(&tamper(4)).unwrap();
    assert!(untampered.is_conformant(&conformance_params));

    // A layout with 0 bits per ciphertext cannot be deserialized.
    assert!(bincode::deserialize::<OneTimePadFheSecretMask>(&tamper(0)).is_err());

    // An invalid layout, or one that does not match the ciphertexts, is refused by conformance.
    for bits_per_ct in [1, 2, 3, 8, 200] {
        let tampered: OneTimePadFheSecretMask = bincode::deserialize(&tamper(bits_per_ct)).unwrap();
        assert!(!tampered.is_conformant(&conformance_params));
    }
}

// The `_sks` argument is unused by the OTP (no bootstrapping happens to draw
// keystream bits), so the error test below use the cheapest parameters to
// generate.

#[test]
fn one_time_pad_fhe_next_bits_beyond_remaining_errors() {
    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
    let fhe_mask = OneTimePadPlainSecretMask::new(vec![0u8; 2], 16)
        .encrypt(&cks)
        .unwrap();
    let mut fhe_otp = OneTimePadFheState::new(fhe_mask);
    assert!(matches!(
        fhe_otp.next_keystream_bits(&sks, 17),
        Err(FheKeyStreamError::Insufficient(_))
    ));
}

/// `OneTimePadFheSecretMask::decrypt` must be the exact inverse of
/// `OneTimePadPlainSecretMask::encrypt`, including the bit order they agree on.
#[test]
fn one_time_pad_fhe_mask_encrypt_decrypt_round_trip() {
    let (cks, _sks) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    // Byte-aligned and not, since the mask carries an explicit bit count.
    for bit_count in [64usize, 12] {
        let byte_count = bit_count.div_ceil(8);

        // All-zeros and all-ones catch a dropped mask, the asymmetric pattern
        // catches a reversed bit or byte order.
        for bytes in [
            vec![0x00u8; byte_count],
            vec![0xFFu8; byte_count],
            (0..byte_count)
                .map(|i| 0x1Fu8.wrapping_mul(i as u8 + 1))
                .collect(),
        ] {
            let plain = OneTimePadPlainSecretMask::new(bytes.clone(), bit_count);
            let recovered = plain.encrypt(&cks).unwrap().decrypt(&cks);

            // The mask has no accessor for its bytes, so equality is checked through the
            // keystream: two masks that drive the same state produce the same ciphertext.
            let value = vec![0u8; byte_count];
            let from_plain = OneTimePadPlainState::new(plain)
                .encrypt_bits(&value, bit_count)
                .unwrap();
            let from_recovered = OneTimePadPlainState::new(recovered)
                .encrypt_bits(&value, bit_count)
                .unwrap();

            assert_eq!(
                from_recovered.bytes(),
                from_plain.bytes(),
                "OTP mask did not survive the encrypt/decrypt round trip \
                 for {bit_count} bits of {bytes:02x?}"
            );
        }
    }
}

/// Check that masks generated with the same seed but different size share the same prefix
#[test]
fn one_time_pad_fhe_new_random_prefix() {
    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    let private_key = TranscipheringPrivateKey::new(&cks, TranscipheringParameters::SameAsCompute);
    let transciphering_key = TranscipheringServerKey::new(&private_key, &cks).unwrap();

    let seed: [u8; 32] = rand::thread_rng().gen();
    println!("one_time_pad_fhe_new_random_prefix seed={seed:02x?}");

    let decrypted_mask = |n_bits| -> Vec<u64> {
        OneTimePadFheSecretMask::new_random(seed.as_slice(), &transciphering_key, &sks, n_bits)
            .unwrap()
            .ciphertexts()
            .iter()
            .map(|ct| cks.decrypt_message_and_carry(ct))
            .collect()
    };

    // 4 bits per ciphertext with 2_2 params
    let short = decrypted_mask(16);
    let long = decrypted_mask(40);

    assert_eq!(short.len(), 4);
    assert_eq!(long.len(), 10);
    assert_eq!(short, long[..4], "seed={seed:02x?}");

    // The mask size must be a multiple of the number of bits per ciphertext.
    assert!(matches!(
        OneTimePadFheSecretMask::new_random(seed.as_slice(), &transciphering_key, &sks, 6),
        Err(MaskGenerationError::InvalidMaskSize)
    ));
}

#[test]
fn one_time_pad_plain_secret_mask_conformance() {
    use crate::conformance::ParameterSetConformant;
    use crate::transciphering::{
        OneTimePadPlainSecretMask, OneTimePadPlainSecretMaskConformanceParams,
    };

    let params = |n_bits| OneTimePadPlainSecretMaskConformanceParams { n_bits };

    let mask = OneTimePadPlainSecretMask::new(vec![0xAB; 8], 64);
    assert!(mask.is_conformant(&params(64)));
    assert!(!mask.is_conformant(&params(32)));

    // `try_new` rejects the inconsistent mask, so it can only be built through deserialization.
    assert!(OneTimePadPlainSecretMask::try_new(vec![0xAB; 4], 64).is_err());

    #[derive(serde::Serialize)]
    struct Tampered {
        secret_mask: Vec<u8>,
        bit_count: usize,
    }

    let tampered = bincode::serialize(&Tampered {
        secret_mask: vec![0xAB; 4],
        bit_count: 64,
    })
    .unwrap();
    let tampered: OneTimePadPlainSecretMask = bincode::deserialize(&tampered).unwrap();
    assert!(!tampered.is_conformant(&params(64)));
}
