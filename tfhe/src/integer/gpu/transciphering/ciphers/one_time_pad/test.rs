use std::num::NonZeroU8;

use rand::Rng;

use super::{CudaOneTimePadFheSecretMask, CudaOneTimePadState};
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::server_key::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::transciphering::CudaIntegerTranscipherer;
use crate::integer::gpu::{CudaOprfServerKey, CudaServerKey};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::oprf::ExpandedOprfServerKey;
use crate::integer::{ClientKey, IntegerKeyKind};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use crate::shortint::Ciphertext;
use crate::transciphering::{
    CompressedOneTimePadFheSecretMask, CompressedTranscipheringServerKey, KeyStreamLayout,
    MaskGenerationError, OneTimePadFheSecretMask, OneTimePadFheState, OneTimePadPlainSecretMask,
    Transcipherer, TranscipheringPrivateKey,
};

create_gpu_parameterized_test!(integer_gpu_one_time_pad_new_random {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

create_gpu_parameterized_test!(integer_gpu_one_time_pad_state_matches_cpu {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

/// GPU OPRF key with the parameters of the computation key
fn gpu_oprf_key(cks: &ClientKey, streams: &CudaStreams) -> CudaOprfServerKey {
    let private_key =
        TranscipheringPrivateKey::new(&cks.key, TranscipheringParameters::SameAsCompute);
    let expanded_key = CompressedTranscipheringServerKey::new(&private_key, &cks.key)
        .unwrap()
        .expand();
    CudaOprfServerKey::from_expanded_cpu(
        &ExpandedOprfServerKey::from_raw_parts(expanded_key.into_raw_parts()),
        streams,
    )
}

/// For a seed and an OPRF key, the GPU mask must hold the bits of the CPU mask, and a bad size or
/// layout must give the CPU error.
fn integer_gpu_one_time_pad_new_random<P>(param: P)
where
    P: Into<TestParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param.into(), IntegerKeyKind::Radix);
    let streams = CudaStreams::new_multi_gpu();
    let cuda_sks = CudaServerKey::new(&cks, &streams);

    let decrypted = |mask: &OneTimePadFheSecretMask| -> Vec<u64> {
        mask.ciphertexts()
            .iter()
            .map(|ct| cks.key.decrypt_message_and_carry(ct))
            .collect()
    };

    for transciphering_params in [
        TranscipheringParameters::SameAsCompute,
        TranscipheringParameters::DedicatedOprf(OprfParameters {
            lwe_dimension: LweDimension(600),
        }),
    ] {
        // CPU and GPU OPRF keys from the same key material
        let private_key = TranscipheringPrivateKey::new(&cks.key, transciphering_params);
        let expanded_key = CompressedTranscipheringServerKey::new(&private_key, &cks.key)
            .unwrap()
            .expand();
        let cpu_oprf_key = expanded_key.to_fourier();
        let gpu_oprf_key = CudaOprfServerKey::from_expanded_cpu(
            &ExpandedOprfServerKey::from_raw_parts(expanded_key.into_raw_parts()),
            &streams,
        );

        let seed: [u8; 32] = rand::thread_rng().gen();
        println!("integer_gpu_one_time_pad_new_random {transciphering_params:?} seed={seed:02x?}");

        // to_cpu goes through OneTimePadFheSecretMask::new, which checks the degree and noise of
        // each ciphertext
        let check_same_mask = |gpu_mask: CudaOneTimePadFheSecretMask,
                               cpu_mask: OneTimePadFheSecretMask| {
            let gpu_mask = gpu_mask.to_cpu(&streams);
            assert_eq!(
                gpu_mask.layout().bits_per_ct(),
                cpu_mask.layout().bits_per_ct()
            );
            assert_eq!(
                decrypted(&gpu_mask),
                decrypted(&cpu_mask),
                "{transciphering_params:?}, bits per ct: {}, seed={seed:02x?}",
                cpu_mask.layout().bits_per_ct()
            );
        };

        let n_bits = 64;

        for bits_per_ct in [1, 2, 4] {
            let layout = KeyStreamLayout::try_new(NonZeroU8::new(bits_per_ct).unwrap()).unwrap();
            let gpu_mask = CudaOneTimePadFheSecretMask::new_random_with_layout(
                seed.as_slice(),
                &gpu_oprf_key,
                &cuda_sks,
                n_bits,
                layout.clone(),
                &streams,
            )
            .unwrap();
            let cpu_mask = OneTimePadFheSecretMask::new_random_with_layout(
                seed.as_slice(),
                &cpu_oprf_key,
                &sks.key,
                n_bits,
                layout,
            )
            .unwrap();
            check_same_mask(gpu_mask, cpu_mask);
        }

        // Default layout: the message space
        let gpu_mask = CudaOneTimePadFheSecretMask::new_random(
            seed.as_slice(),
            &gpu_oprf_key,
            &cuda_sks,
            n_bits,
            &streams,
        )
        .unwrap();
        let cpu_mask =
            OneTimePadFheSecretMask::new_random(seed.as_slice(), &cpu_oprf_key, &sks.key, n_bits)
                .unwrap();
        check_same_mask(gpu_mask, cpu_mask);

        // An empty mask, as on CPU
        let empty_mask = CudaOneTimePadFheSecretMask::new_random(
            seed.as_slice(),
            &gpu_oprf_key,
            &cuda_sks,
            0,
            &streams,
        )
        .unwrap();
        let empty_mask = empty_mask.to_cpu(&streams);
        assert!(empty_mask.ciphertexts().is_empty());
        // Back to the GPU, without any ciphertext to copy
        let empty_mask = CudaOneTimePadFheSecretMask::from_cpu(&empty_mask, &cuda_sks, &streams);
        assert!(empty_mask.to_cpu(&streams).ciphertexts().is_empty());

        // 5 bits do not fill ciphertexts of 2 bits, and the backend counts the bits of a mask on
        // 32 bits
        for invalid_n_bits in [5, 1 << 32] {
            assert!(matches!(
                CudaOneTimePadFheSecretMask::new_random(
                    seed.as_slice(),
                    &gpu_oprf_key,
                    &cuda_sks,
                    invalid_n_bits,
                    &streams
                ),
                Err(MaskGenerationError::InvalidMaskSize)
            ));
        }

        // 8 bits per ciphertext do not fit in the message and carry space
        let too_wide = KeyStreamLayout::try_new(NonZeroU8::new(8).unwrap()).unwrap();
        assert!(matches!(
            CudaOneTimePadFheSecretMask::new_random_with_layout(
                seed.as_slice(),
                &gpu_oprf_key,
                &cuda_sks,
                n_bits,
                too_wide,
                &streams
            ),
            Err(MaskGenerationError::IncompatibleParameters)
        ));
    }
}

/// Both states start from one mask and go through one list of operations. The GPU state must
/// return the keystream, counter and errors of the CPU state at each step.
fn integer_gpu_one_time_pad_state_matches_cpu<P>(param: P)
where
    P: Into<TestParameters>,
{
    enum Op {
        Draw(usize),
        Skip(usize),
    }

    let (cks, sks) = KEY_CACHE.get_from_params(param.into(), IntegerKeyKind::Radix);
    let streams = CudaStreams::new_multi_gpu();
    let cuda_sks = CudaServerKey::new(&cks, &streams);
    let oprf_key = gpu_oprf_key(&cks, &streams);

    let seed: [u8; 32] = rand::thread_rng().gen();
    println!("integer_gpu_one_time_pad_state_matches_cpu seed={seed:02x?}");

    // 16 ciphertexts of 2 bits
    let mask = CudaOneTimePadFheSecretMask::new_random(
        seed.as_slice(),
        &oprf_key,
        &cuda_sks,
        32,
        &streams,
    )
    .unwrap();
    let mut cpu = OneTimePadFheState::new(mask.to_cpu(&streams));
    let mut gpu = CudaOneTimePadState::new(mask);

    let ops = [
        Op::Draw(8),
        Op::Draw(0),
        // Leaves the counter in the middle of a ciphertext
        Op::Draw(5),
        Op::Draw(4),
        Op::Skip(3),
        // Up to the end of the mask
        Op::Draw(16),
        Op::Draw(1),
        // Past the end of the mask
        Op::Skip(4),
        Op::Draw(4),
    ];

    let blocks = |cts: &[Ciphertext]| -> Vec<_> {
        cts.iter()
            .map(|ct| {
                (
                    cks.key.decrypt_message_and_carry(ct),
                    ct.degree,
                    ct.noise_level(),
                )
            })
            .collect()
    };

    for (i, op) in ops.into_iter().enumerate() {
        match op {
            Op::Draw(n_bits) => {
                match (
                    cpu.next_keystream_bits(&sks.key, n_bits),
                    gpu.next_keystream_bits(&cuda_sks, n_bits, &streams),
                ) {
                    (Ok(cpu_keystream), Ok(gpu_keystream)) => {
                        let (cpu_cts, cpu_layout) = cpu_keystream.into_raw_parts();
                        let (gpu_stream, gpu_layout) = gpu_keystream.into_raw_parts();
                        assert_eq!(gpu_layout.bits_per_ct(), cpu_layout.bits_per_ct());
                        let gpu_cts = gpu_stream.to_radix_ciphertext(&streams).blocks;
                        assert_eq!(
                            blocks(&gpu_cts),
                            blocks(&cpu_cts),
                            "op {i}, seed={seed:02x?}"
                        );
                    }
                    (Err(cpu_err), Err(gpu_err)) => assert_eq!(gpu_err, cpu_err, "op {i}"),
                    (cpu_res, gpu_res) => panic!(
                        "op {i}: CPU ok: {}, GPU ok: {}",
                        cpu_res.is_ok(),
                        gpu_res.is_ok()
                    ),
                }
            }
            Op::Skip(n_bits) => {
                cpu.seek(&sks.key, cpu.current_counter() + n_bits as u64);
                gpu.skip(&cuda_sks, n_bits, &streams);
            }
        }
        assert_eq!(gpu.current_counter(), cpu.current_counter(), "op {i}");
        assert_eq!(gpu.remaining_bits(), cpu.remaining_bits(), "op {i}");
    }
}

/// Both devices must refuse, with the same error
fn assert_same_error<T, U>(cpu: crate::Result<T>, gpu: crate::Result<U>) {
    match (cpu, gpu) {
        (Err(cpu_err), Err(gpu_err)) => assert_eq!(gpu_err.to_string(), cpu_err.to_string()),
        (cpu_res, gpu_res) => panic!("CPU ok: {}, GPU ok: {}", cpu_res.is_ok(), gpu_res.is_ok()),
    }
}

/// A mask compressed on one device must decompress on both devices into the bits of the mask. A
/// mask or a compressed mask refused on CPU must be refused on GPU with the CPU error.
#[test]
fn integer_gpu_one_time_pad_compressed_mask() {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_params = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let (cks, _) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let streams = CudaStreams::new_multi_gpu();
    let cuda_sks = CudaServerKey::new(&cks, &streams);
    let oprf_key = gpu_oprf_key(&cks, &streams);

    let private_compression_key = cks.new_compression_private_key(comp_params);
    let (compressed_compression_key, compressed_decompression_key) =
        cks.new_compressed_compression_decompression_keys(&private_compression_key);
    let gpu_comp_key = compressed_compression_key.decompress_to_cuda(&streams);
    let gpu_decomp_key = compressed_decompression_key.decompress_to_cuda(
        cks.parameters().glwe_dimension(),
        cks.parameters().polynomial_size(),
        cks.parameters().message_modulus(),
        cks.parameters().carry_modulus(),
        cks.parameters().ciphertext_modulus(),
        &streams,
    );
    let cpu_comp_key = compressed_compression_key.decompress().key;
    let cpu_decomp_key = compressed_decompression_key.decompress().key;

    let seed: [u8; 32] = rand::thread_rng().gen();
    println!("integer_gpu_one_time_pad_compressed_mask seed={seed:02x?}");

    let new_random = |n_bits: u64| {
        CudaOneTimePadFheSecretMask::new_random(
            seed.as_slice(),
            &oprf_key,
            &cuda_sks,
            n_bits,
            &streams,
        )
        .unwrap()
    };
    let gpu_decompress = |compressed: &CompressedOneTimePadFheSecretMask| {
        CudaOneTimePadFheSecretMask::decompress(compressed, &gpu_decomp_key, &streams)
    };

    // 7 ciphertexts, then enough ciphertexts of 2 bits to fill a GLWE and start a second one
    let two_glwes_bits = 2 * (comp_params.lwe_per_glwe().0 as u64 + 3);
    for n_bits in [14, two_glwes_bits] {
        let gpu_mask = new_random(n_bits);
        let cpu_mask = gpu_mask.to_cpu(&streams);
        let expected = cpu_mask.decrypt(&cks.key);

        for (compressed_on, compressed) in [
            ("CPU", cpu_mask.compress(&cpu_comp_key).unwrap()),
            ("GPU", gpu_mask.compress(&gpu_comp_key, &streams).unwrap()),
        ] {
            assert_eq!(compressed.layout(), cpu_mask.layout());

            let on_cpu = compressed.decompress(&cpu_decomp_key).unwrap();
            let on_gpu = gpu_decompress(&compressed).unwrap().to_cpu(&streams);
            for (decompressed_on, decompressed) in [("CPU", on_cpu), ("GPU", on_gpu)] {
                assert!(
                    decompressed.decrypt(&cks.key) == expected,
                    "{n_bits} bits, compressed on {compressed_on}, decompressed on \
                    {decompressed_on}, seed={seed:02x?}"
                );
            }
        }
    }

    // Compression only keeps the message part, so other layouts are refused
    for layout in [
        KeyStreamLayout::full_space(cuda_sks.message_modulus, cuda_sks.carry_modulus).unwrap(),
        KeyStreamLayout::single_bit(),
    ] {
        let gpu_mask = CudaOneTimePadFheSecretMask::new_random_with_layout(
            seed.as_slice(),
            &oprf_key,
            &cuda_sks,
            16,
            layout,
            &streams,
        )
        .unwrap();
        assert_same_error(
            gpu_mask.to_cpu(&streams).compress(&cpu_comp_key),
            gpu_mask.compress(&gpu_comp_key, &streams),
        );
    }

    // Decompression requires equal message and carry moduli, so a mask using the message space of
    // other parameters is refused
    let cks_1_2 = crate::shortint::ClientKey::new(
        TEST_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
    );
    let cpu_mask = OneTimePadPlainSecretMask::new(vec![0xAB; 2], 16)
        .encrypt(&cks_1_2)
        .unwrap();
    assert_same_error(
        cpu_mask.compress(&cpu_comp_key),
        CudaOneTimePadFheSecretMask::from_cpu(&cpu_mask, &cuda_sks, &streams)
            .compress(&gpu_comp_key, &streams),
    );

    // A stored mask that declares 1 bit per ciphertext while its ciphertexts hold 2 bits
    let compressed = new_random(16).compress(&gpu_comp_key, &streams).unwrap();
    let wrong_layout = CompressedOneTimePadFheSecretMask::from_compressed_list(
        compressed.compressed_list().clone(),
        KeyStreamLayout::single_bit(),
    );
    assert_same_error(
        wrong_layout.decompress(&cpu_decomp_key),
        gpu_decompress(&wrong_layout),
    );

    // An empty mask goes through the whole flow
    let compressed = new_random(0).compress(&gpu_comp_key, &streams).unwrap();
    for decompressed in [
        compressed.decompress(&cpu_decomp_key).unwrap(),
        gpu_decompress(&compressed).unwrap().to_cpu(&streams),
    ] {
        assert!(decompressed.ciphertexts().is_empty());
    }
}
