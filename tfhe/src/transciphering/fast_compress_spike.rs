//! THROWAWAY SPIKE — delete once the decision is made.
//!
//! Compares, for OTP transciphering into a compressed list:
//!   * `naive`: the trait's `transcipher_and_compress` (PBS-based `apply_keystream`,
//!     ~one 0.5 PBS per bit in 2_2), then compress.
//!   * `fast` : linear-only XOR-with-clear (conditional flip) + linear packing,
//!     **no PBS**, then compress.
//!
//! INSECURE: the fast path forges the shortint noise metadata back to nominal so
//! the existing compression asserts (`noise_level == NOMINAL`, `carry_is_empty`)
//! accept the actually-noisier linearly-packed ciphertexts. Timing is
//! noise-independent, so the comparison is valid; the roundtrip decrypt check is a
//! (light) empirical signal on whether the real noise survives compression at
//! these params. A real pfail measurement needs many more samples.

use std::time::Instant;

use rand::Rng;
use rayon::prelude::*;

use crate::core_crypto::prelude::{lwe_ciphertext_add_assign, lwe_ciphertext_opposite_assign};
use crate::shortint::ciphertext::{Ciphertext, CompressedCiphertextList, Degree};
use crate::shortint::list_compression::CompressionKey;
use crate::shortint::parameters::test_params::{
    TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::{gen_keys, ServerKey, ShortintParameterSet};
use crate::transciphering::{
    apply_keystream, FheKeyStream, PreGenedOtpPlainSecretMask, PreGenedOtpPlainState, StreamCipher,
    StreamCiphertext,
};

/// LSB-first bit `i` of `bytes`.
fn bit_at(bytes: &[u8], i: usize) -> u64 {
    ((bytes[i / 8] >> (i % 8)) & 1) as u64
}

/// Fast path: XOR the clear stream ciphertext into the encrypted mask with linear
/// ops only, pack `m = log2(message_modulus)` bits per output ciphertext, forge the
/// noise metadata, then compress. Assumes `message_modulus == carry_modulus` and
/// `keystream.len()` a multiple of `m` (true for the sizes used below).
fn fast_apply_and_compress(
    sks: &ServerKey,
    comp_key: &CompressionKey,
    keystream: &[Ciphertext],
    input: &StreamCiphertext,
) -> CompressedCiphertextList {
    let m = sks.message_modulus.0.ilog2() as usize;
    let one = sks.create_trivial(1);
    let input_bytes = input.bytes();

    let packed: Vec<Ciphertext> = keystream
        .chunks(m)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            let mut out: Option<Ciphertext> = None;
            for (j, k) in chunk.iter().enumerate() {
                let bit_idx = chunk_idx * m + j;

                // XOR keystream bit with the clear input bit. XOR with a known bit is a
                // conditional flip: value -> 1 - value when the clear bit is 1, identity
                // otherwise. The flip is linear (negate + add trivial 1), noise preserved.
                let mut bit = k.clone();
                if bit_at(input_bytes, bit_idx) == 1 {
                    lwe_ciphertext_opposite_assign(&mut bit.ct);
                    lwe_ciphertext_add_assign(&mut bit.ct, &one.ct);
                }

                // Shift into message position j (linear) and accumulate.
                let shifted = if j == 0 {
                    bit
                } else {
                    sks.unchecked_scalar_mul(&bit, 1u8 << j)
                };
                match &mut out {
                    None => out = Some(shifted),
                    Some(acc) => sks.unchecked_add_assign(acc, &shifted),
                }
            }

            let mut out = out.unwrap();
            // INSECURE: forge metadata so compression accepts the noisier packed ct.
            out.degree = Degree::new(sks.message_modulus.0 - 1);
            out.set_noise_level_to_nominal();
            out
        })
        .collect();

    comp_key.compress_ciphertexts_into_list(&packed)
}

/// Same XOR+pack-by-PBS as `apply_keystream_2_2`, but parallelized with a plain
/// `par_chunks` (like the diagnostic) instead of `par_chunks_exact().enumerate().chain()`.
/// Used to measure the *properly-parallelized* PBS baseline. Assumes even keystream len.
fn parallel_pbs_apply(
    sks: &ServerKey,
    keystream: &[Ciphertext],
    input: &StreamCiphertext,
) -> Vec<Ciphertext> {
    let luts: [_; 4] = std::array::from_fn(|i| {
        let i_lo = (i & 1) as u64;
        let i_hi = ((i >> 1) & 1) as u64;
        sks.generate_lookup_table_bivariate(move |k0, k1| ((k0 & 1) ^ i_lo) | (((k1 & 1) ^ i_hi) << 1))
    });
    let input_bytes = input.bytes();
    keystream
        .par_chunks(2)
        .enumerate()
        .map(|(i, pair)| {
            let i_lo = bit_at(input_bytes, 2 * i);
            let i_hi = bit_at(input_bytes, 2 * i + 1);
            let s = (i_lo | (i_hi << 1)) as usize;
            sks.unchecked_apply_lookup_table_bivariate(&pair[0], &pair[1], &luts[s])
        })
        .collect()
}

/// Decompress every block and recompose the `m`-bit messages into the original bytes.
fn decompress_to_bytes(
    decomp_key: &crate::shortint::list_compression::DecompressionKey,
    cks: &crate::shortint::ClientKey,
    list: &CompressedCiphertextList,
    m: usize,
    n_bits: usize,
) -> Vec<u8> {
    let mut bytes = vec![0u8; n_bits.div_ceil(8)];
    for block_idx in 0..list.len() {
        let ct = decomp_key.unpack(list, block_idx).unwrap();
        let value = cks.decrypt(&ct);
        for j in 0..m {
            let bit_idx = block_idx * m + j;
            if bit_idx < n_bits {
                bytes[bit_idx / 8] |= (((value >> j) & 1) as u8) << (bit_idx % 8);
            }
        }
    }
    bytes
}

/// Isolate PBS throughput: does `par_chunks` actually parallelize bivariate PBS on
/// this machine, and what is a single 2_2 bivariate PBS worth?
#[test]
fn spike_pbs_parallelism() {
    let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let (cks, sks) = gen_keys::<ShortintParameterSet>(params.into());

    println!("\nrayon threads: {}", rayon::current_num_threads());

    let n_pairs = 256usize;
    let cts: Vec<Ciphertext> = (0..2 * n_pairs)
        .map(|i| cks.encrypt_bool(i % 2 == 0))
        .collect();
    let lut = sks.generate_lookup_table_bivariate(|a, b| (a & 1) | ((b & 1) << 1));

    // serial
    let t = Instant::now();
    let _serial: Vec<_> = cts
        .chunks(2)
        .map(|c| sks.unchecked_apply_lookup_table_bivariate(&c[0], &c[1], &lut))
        .collect();
    let serial = t.elapsed();

    // parallel
    let t = Instant::now();
    let _par: Vec<_> = cts
        .par_chunks(2)
        .map(|c| sks.unchecked_apply_lookup_table_bivariate(&c[0], &c[1], &lut))
        .collect();
    let par = t.elapsed();

    println!(
        "{n_pairs} bivariate PBS:\n  \
         serial: {serial:?}  (~{:?}/PBS)\n  \
         par   : {par:?}\n  \
         par speedup: {:.1}x\n",
        serial / n_pairs as u32,
        serial.as_secs_f64() / par.as_secs_f64()
    );
}

#[test]
fn spike_otp_fast_vs_naive() {
    let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_params = TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let (cks, sks) = gen_keys::<ShortintParameterSet>(params.into());
    let priv_comp = cks.new_compression_private_key(comp_params);
    let (comp_key, decomp_key) = cks.new_compression_decompression_keys(&priv_comp);

    let m = sks.message_modulus.0.ilog2() as usize;
    let n_bits = 512usize;
    let n_bytes = n_bits / 8;

    let mut rng = rand::thread_rng();
    let mask_bytes: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();
    let input_bytes: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();

    // Client: encrypt the input with plain OTP -> stream ciphertext (input ^ mask).
    let mut plain_state =
        PreGenedOtpPlainState::new(PreGenedOtpPlainSecretMask::new(mask_bytes.clone(), n_bits));
    let stream_ct = plain_state.encrypt_bits(&input_bytes, n_bits);

    // Server: FHE-encrypt the mask bits (one clean boolean ct per bit).
    let mask_cts: Vec<Ciphertext> = (0..n_bits)
        .map(|i| cks.encrypt_bool(bit_at(&mask_bytes, i) == 1))
        .collect();

    // Warm up (allocations, thread pool) before timing.
    let _ = fast_apply_and_compress(&sks, &comp_key, &mask_cts, &stream_ct);

    // ---- naive, split into apply (PBS) and compress ----
    let keystream = FheKeyStream::from_raw_parts(mask_cts.clone());
    let t = Instant::now();
    let naive_blocks = apply_keystream(&sks, &keystream, &stream_ct);
    let naive_apply_dt = t.elapsed();
    let t = Instant::now();
    let naive_list = comp_key.compress_ciphertexts_into_list(&naive_blocks);
    let naive_compress_dt = t.elapsed();
    let naive_dt = naive_apply_dt + naive_compress_dt;

    // ---- naive with a properly-parallelized PBS apply (par_chunks) ----
    let t = Instant::now();
    let fixed_blocks = parallel_pbs_apply(&sks, &mask_cts, &stream_ct);
    let fixed_apply_dt = t.elapsed();
    let t = Instant::now();
    let _fixed_list = comp_key.compress_ciphertexts_into_list(&fixed_blocks);
    let fixed_compress_dt = t.elapsed();
    let fixed_dt = fixed_apply_dt + fixed_compress_dt;

    // ---- fast ----
    let t = Instant::now();
    let fast_list = fast_apply_and_compress(&sks, &comp_key, &mask_cts, &stream_ct);
    let fast_dt = t.elapsed();

    // ---- correctness ----
    let naive_bytes = decompress_to_bytes(&decomp_key, &cks, &naive_list, m, n_bits);
    let fast_bytes = decompress_to_bytes(&decomp_key, &cks, &fast_list, m, n_bits);
    assert_eq!(naive_bytes, input_bytes, "naive path lost the plaintext");
    assert_eq!(
        fast_bytes, input_bytes,
        "fast path lost the plaintext (noise survived? or a logic bug)"
    );

    println!(
        "\nOTP transcipher_and_compress, {n_bits} bits (2_2):\n  \
         naive (current)      : {naive_dt:?}  (apply {naive_apply_dt:?} + compress {naive_compress_dt:?})\n  \
         naive (par_chunks fix): {fixed_dt:?}  (apply {fixed_apply_dt:?} + compress {fixed_compress_dt:?})\n  \
         fast  (linear)       : {fast_dt:?}\n  \
         speedup vs current   : {:.1}x\n  \
         speedup vs fixed     : {:.1}x  <-- the honest number\n",
        naive_dt.as_secs_f64() / fast_dt.as_secs_f64(),
        fixed_dt.as_secs_f64() / fast_dt.as_secs_f64(),
    );
}
