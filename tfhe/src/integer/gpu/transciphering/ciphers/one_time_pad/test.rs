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
    CompressedTranscipheringServerKey, KeyStreamLayout, MaskGenerationError,
    OneTimePadFheSecretMask, OneTimePadFheState, Transcipherer, TranscipheringPrivateKey,
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

        // Default layout: the full message and carry space
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
        assert!(empty_mask.to_cpu(&streams).ciphertexts().is_empty());

        // The mask size must be a multiple of the number of bits per ciphertext
        assert!(matches!(
            CudaOneTimePadFheSecretMask::new_random(
                seed.as_slice(),
                &gpu_oprf_key,
                &cuda_sks,
                6,
                &streams
            ),
            Err(MaskGenerationError::InvalidMaskSize)
        ));

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

    // 8 ciphertexts of 4 bits
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
                        assert_eq!(
                            gpu_keystream.layout().bits_per_ct(),
                            cpu_layout.bits_per_ct()
                        );
                        let gpu_cts = gpu_keystream
                            .as_radix()
                            .to_radix_ciphertext(&streams)
                            .blocks;
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
