use std::num::NonZeroU8;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{check_valid_cuda_malloc_assert_oom, CudaStreams};
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::gen_keys_radix_gpu;
use crate::integer::gpu::server_key::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::transciphering::{
    apply_keystream, get_apply_keystream_size_on_gpu, CudaFheKeyStream,
};
use crate::integer::{RadixCiphertext, RadixClientKey};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use crate::shortint::MessageModulus;
use crate::transciphering::{
    KeyStreamLayout, OneTimePadPlainSecretMask, OneTimePadPlainState, StreamCipher,
    StreamCiphertext, TranscipherError, TranscipheringOutputLayout, TranscipheringOutputLayoutBits,
};

create_gpu_parameterized_test!(integer_gpu_apply_keystream {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128,
});

create_gpu_parameterized_test!(integer_gpu_apply_keystream_errors {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn nz(v: u8) -> NonZeroU8 {
    NonZeroU8::new(v).unwrap()
}

/// Random LSB-first bits, with the unused bits of the last byte set to 0
fn random_bits(rng: &mut impl Rng, n_bits: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..n_bits.div_ceil(8)).map(|_| rng.gen()).collect();
    truncate_bits(&mut bytes, n_bits);
    bytes
}

/// Keeps the first n_bits bits, the unused bits of the last byte set to 0
fn truncate_bits(bytes: &mut Vec<u8>, n_bits: usize) {
    bytes.truncate(n_bits.div_ceil(8));
    if !n_bits.is_multiple_of(8) {
        *bytes.last_mut().unwrap() &= (1u8 << (n_bits % 8)) - 1;
    }
}

/// Reads len LSB-first bits from bit start
fn read_bits(bytes: &[u8], start: usize, len: usize) -> u64 {
    (0..len).fold(0, |acc, i| {
        let bit = (bytes[(start + i) / 8] >> ((start + i) % 8)) & 1;
        acc | (u64::from(bit) << i)
    })
}

/// The layout of a list of parts, each one aligned on 8 bits like in an input package. A part is
/// a boolean if its size is 0, a radix of this size otherwise.
fn aligned_parts(parts: &[usize], msg_mod: MessageModulus) -> TranscipheringOutputLayout {
    let mut layout = TranscipheringOutputLayout::new();
    for &n_bits in parts {
        let part = if n_bits == 0 {
            TranscipheringOutputLayout::boolean()
        } else {
            TranscipheringOutputLayout::radix(n_bits, msg_mod).unwrap()
        };
        layout.push_aligned(part, nz(8));
    }
    layout
}

/// Encrypts the keystream bits with the degree of the layout, as a cipher would produce them
fn encrypt_keystream(
    cks: &RadixClientKey,
    keystream_bits: &[u8],
    stream_layout: KeyStreamLayout,
    ct_count: usize,
    streams: &CudaStreams,
) -> CudaFheKeyStream {
    let bits_per_ct = usize::from(stream_layout.bits_per_ct().get());
    let blocks: Vec<_> = (0..ct_count)
        .map(|i| {
            let mut ct = cks.as_ref().key.unchecked_encrypt(read_bits(
                keystream_bits,
                i * bits_per_ct,
                bits_per_ct,
            ));
            ct.degree = stream_layout.expected_degree();
            ct
        })
        .collect();
    let stream =
        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&RadixCiphertext::from(blocks), streams);
    CudaFheKeyStream::from_raw_parts(stream, stream_layout)
}

/// A random plaintext encrypted with a one time pad, and the FHE keystream of this pad. The unused
/// high bits of the last keystream ct are random, as with a real mask.
fn one_time_pad_input(
    rng: &mut impl Rng,
    cks: &RadixClientKey,
    stream_layout: KeyStreamLayout,
    n_bits: usize,
    streams: &CudaStreams,
) -> (Vec<u8>, StreamCiphertext, CudaFheKeyStream) {
    let ct_count = n_bits.div_ceil(usize::from(stream_layout.bits_per_ct().get()));
    let keystream_bits = random_bits(rng, stream_layout.bit_length(ct_count));
    let keystream = encrypt_keystream(cks, &keystream_bits, stream_layout, ct_count, streams);

    let mut pad = keystream_bits;
    truncate_bits(&mut pad, n_bits);
    let plaintext = random_bits(rng, n_bits);
    let input = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(pad, n_bits))
        .encrypt_bits(&plaintext, n_bits)
        .unwrap();

    (plaintext, input, keystream)
}

/// The keystream is the encrypted pad of the input, so the output blocks must decrypt to the
/// plaintext bits of the blocks of the output layout
fn integer_gpu_apply_keystream<P>(param: P)
where
    P: Into<TestParameters>,
{
    let streams = CudaStreams::new_multi_gpu();
    let (cks, sks) = gen_keys_radix_gpu(param.into(), 1, &streams);
    let (msg_mod, carry_mod) = (sks.message_modulus, sks.carry_modulus);

    let seed: u64 = rand::thread_rng().gen();
    let mut rng = StdRng::seed_from_u64(seed);

    let single_bit = KeyStreamLayout::single_bit();
    let full_space = KeyStreamLayout::full_space(msg_mod, carry_mod).unwrap();
    let two_bits = KeyStreamLayout::try_new(nz(2)).unwrap();
    let cases = [
        // Integer types with a 1 bit keystream, as Kreyvium and AES produce
        (
            "single bit keystream, boolean",
            single_bit.clone(),
            TranscipheringOutputLayout::boolean(),
        ),
        (
            "single bit keystream, radix of 64 bits",
            single_bit.clone(),
            TranscipheringOutputLayout::radix(64, msg_mod).unwrap(),
        ),
        // The cases of the CPU test, covering the extraction and linear combination paths, with
        // keystream cts partially used or fully skipped
        (
            "full space keystream, radix of 14 bits",
            full_space.clone(),
            TranscipheringOutputLayout::radix(14, msg_mod).unwrap(),
        ),
        (
            "full space keystream, [u8, bool, u4] aligned on 8",
            full_space,
            aligned_parts(&[8, 0, 4], msg_mod),
        ),
        (
            "2 bits keystream, [bool, u16, bool] aligned on 8",
            two_bits,
            aligned_parts(&[0, 16, 0], msg_mod),
        ),
        (
            "single bit keystream, [bool, u8] aligned on 8",
            single_bit,
            aligned_parts(&[0, 8], msg_mod),
        ),
    ];

    for (name, stream_layout, output_layout) in cases {
        if !stream_layout.can_fit(msg_mod, carry_mod) {
            continue;
        }
        let ctx = format!("{name} (seed={seed})");
        let n_bits = output_layout.bit_length();
        let (plaintext, input, keystream) =
            one_time_pad_input(&mut rng, &cks, stream_layout, n_bits, &streams);

        let size = get_apply_keystream_size_on_gpu(
            &sks,
            keystream.layout(),
            &input,
            &output_layout,
            &streams,
        )
        .unwrap();
        assert!(size > 0, "{ctx}");
        check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));

        let output = apply_keystream(&sks, &keystream, &input, &output_layout, &streams).unwrap();
        let output = <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(output)
            .to_radix_ciphertext(&streams);

        let mut start = 0;
        let mut expected_blocks = Vec::new();
        for entry in output_layout.entries() {
            if let TranscipheringOutputLayoutBits::Block(width) = entry {
                let width = usize::from(width.get());
                expected_blocks.push((read_bits(&plaintext, start, width), width));
            }
            start += entry.len();
        }

        assert_eq!(output.blocks.len(), expected_blocks.len(), "{ctx}");
        for (i, (ct, (expected, width))) in output.blocks.iter().zip(expected_blocks).enumerate() {
            assert_eq!(
                cks.as_ref().key.decrypt_message_and_carry(ct),
                expected,
                "{ctx}: block {i}"
            );
            assert_eq!(ct.noise_level(), NoiseLevel::NOMINAL, "{ctx}: block {i}");
            assert!(
                ct.degree.get() < 1 << width,
                "{ctx}: block {i} of width {width} has degree {:?}",
                ct.degree
            );
        }
    }

    // An empty input does not reach the backend
    let empty_input = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(vec![], 0))
        .encrypt_bits(&[], 0)
        .unwrap();
    assert_eq!(
        get_apply_keystream_size_on_gpu(
            &sks,
            &KeyStreamLayout::single_bit(),
            &empty_input,
            &TranscipheringOutputLayout::new(),
            &streams
        ),
        Ok(0)
    );
}

/// Invalid keystreams and output layouts get the CPU errors before reaching the backend, where
/// they would be panics
fn integer_gpu_apply_keystream_errors<P>(param: P)
where
    P: Into<TestParameters>,
{
    let streams = CudaStreams::new_multi_gpu();
    let (cks, sks) = gen_keys_radix_gpu(param.into(), 1, &streams);
    let msg_mod = sks.message_modulus;
    let mut rng = StdRng::seed_from_u64(rand::thread_rng().gen());

    let single_bit = KeyStreamLayout::single_bit;
    let radix_8 = TranscipheringOutputLayout::radix(8, msg_mod).unwrap();
    let apply = |keystream: &CudaFheKeyStream, input: &StreamCiphertext, layout| {
        apply_keystream(&sks, keystream, input, layout, &streams).err()
    };
    // The size getter has no keystream cts, it only gets the errors of the layouts
    let size = |keystream: &CudaFheKeyStream, input: &StreamCiphertext, layout| {
        get_apply_keystream_size_on_gpu(&sks, keystream.layout(), input, layout, &streams).err()
    };

    // Output layout not matching the input length
    let (_, input, keystream) = one_time_pad_input(&mut rng, &cks, single_bit(), 8, &streams);
    let radix_16 = TranscipheringOutputLayout::radix(16, msg_mod).unwrap();
    assert_eq!(
        apply(&keystream, &input, &radix_16),
        Some(TranscipherError::InvalidOutputLayout)
    );
    assert_eq!(
        size(&keystream, &input, &radix_16),
        Some(TranscipherError::InvalidOutputLayout)
    );

    // [bool, u2, bool] on 2 bit keystream cts: the u2 takes one bit from each of two cts, which a
    // single PBS cannot extract
    let (_, input, keystream) = one_time_pad_input(
        &mut rng,
        &cks,
        KeyStreamLayout::try_new(nz(2)).unwrap(),
        4,
        &streams,
    );
    let mut unaligned = TranscipheringOutputLayout::boolean();
    unaligned
        .push_aligned(
            TranscipheringOutputLayout::radix(2, msg_mod).unwrap(),
            nz(1),
        )
        .push_aligned(TranscipheringOutputLayout::boolean(), nz(1));
    assert_eq!(
        apply(&keystream, &input, &unaligned),
        Some(TranscipherError::InvalidOutputLayout)
    );
    assert_eq!(
        size(&keystream, &input, &unaligned),
        Some(TranscipherError::InvalidOutputLayout)
    );

    // Keystream without the number of cts needed for the input
    let (_, input, _) = one_time_pad_input(&mut rng, &cks, single_bit(), 8, &streams);
    let (_, _, short_keystream) = one_time_pad_input(&mut rng, &cks, single_bit(), 7, &streams);
    assert_eq!(
        apply(&short_keystream, &input, &radix_8),
        Some(TranscipherError::InvalidKeystream)
    );

    // Keystream cts holding more bits than the plaintext space
    let (_, input, _) = one_time_pad_input(&mut rng, &cks, single_bit(), 8, &streams);
    let eight_bits = KeyStreamLayout::try_new(nz(8)).unwrap();
    let wide_keystream = encrypt_keystream(&cks, &[0], eight_bits, 1, &streams);
    assert_eq!(
        size(&wide_keystream, &input, &radix_8),
        Some(TranscipherError::InvalidKeystream)
    );
    assert_eq!(
        apply(&wide_keystream, &input, &radix_8),
        Some(TranscipherError::InvalidKeystream)
    );

    // Keystream cts with a degree or a noise level not matching the keystream contract
    let (_, input, keystream) = one_time_pad_input(&mut rng, &cks, single_bit(), 8, &streams);
    let (mut stream, layout) = keystream.into_raw_parts();
    stream.as_mut().info.blocks[1].degree = Degree::new(3);
    assert_eq!(
        apply(
            &CudaFheKeyStream::from_raw_parts(stream, layout),
            &input,
            &radix_8
        ),
        Some(TranscipherError::InvalidKeystream)
    );

    let (_, input, keystream) = one_time_pad_input(&mut rng, &cks, single_bit(), 8, &streams);
    let (mut stream, layout) = keystream.into_raw_parts();
    stream.as_mut().info.blocks[1].noise_level = NoiseLevel(4);
    assert_eq!(
        apply(
            &CudaFheKeyStream::from_raw_parts(stream, layout),
            &input,
            &radix_8
        ),
        Some(TranscipherError::InvalidKeystream)
    );
}
