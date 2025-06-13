use crate::core_crypto::algorithms::lwe_encryption::allocate_and_encrypt_new_lwe_ciphertext;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::noise_formulas::generalized_modulus_switch::generalized_modulus_switch_additive_variance;
use crate::core_crypto::commons::noise_formulas::lwe_keyswitch::{
    keyswitch_additive_variance_132_bits_security_gaussian,
    keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_multi_bit_programmable_bootstrap::{
    multi_bit_pbs_variance_132_bits_security_gaussian_gf_2_fft_mul,
    multi_bit_pbs_variance_132_bits_security_gaussian_gf_3_fft_mul,
    multi_bit_pbs_variance_132_bits_security_gaussian_gf_4_fft_mul,
    multi_bit_pbs_variance_132_bits_security_tuniform_gf_2_fft_mul,
    multi_bit_pbs_variance_132_bits_security_tuniform_gf_3_fft_mul,
    multi_bit_pbs_variance_132_bits_security_tuniform_gf_4_fft_mul,
};
use crate::core_crypto::commons::noise_formulas::lwe_packing_keyswitch::{
    packing_keyswitch_additive_variance_132_bits_security_gaussian,
    packing_keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap::{
    pbs_variance_132_bits_security_gaussian, pbs_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap_128::{
    pbs_128_variance_132_bits_security_gaussian, pbs_128_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};

use crate::core_crypto::commons::noise_formulas::modulus_switch::{
    modulus_switch_additive_variance, modulus_switch_multi_bit_additive_variance,
};

use crate::core_crypto::commons::noise_formulas::secure_noise::{
    minimal_lwe_variance_for_132_bits_security_gaussian,
    minimal_lwe_variance_for_132_bits_security_tuniform,
};
use crate::core_crypto::commons::parameters::MonomialDegree;

use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, clopper_pearson_exact_confidence_interval, equivalent_pfail_gaussian_noise,
    mean_confidence_interval, normality_test_f64, variance, variance_confidence_interval,
};
use crate::core_crypto::entities::{LweCiphertext, Plaintext};
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::prelude::misc::torus_modular_diff;
use crate::core_crypto::prelude::test::{round_decode, TestResources};
use crate::integer::tests::create_parameterized_test;
use crate::shortint::ciphertext::NoiseLevel;

use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::CompressionPrivateKeys;

use crate::shortint::parameters::list_compression::CompressionParameters;

use crate::shortint::parameters::{
    CiphertextModulus, DynamicDistribution, EncryptionKeyChoice, NoiseSquashingParameters,
    ShortintParameterSet, COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key, generate_programmable_bootstrap_glwe_lut,
    par_allocate_and_generate_new_lwe_bootstrap_key, GlweSecretKey,
};
use crate::shortint::server_key::tests::noise_distribution::atomic_pattern::{
    mean_and_variance_check, CompressionSpecialPfailCase, DecryptionAndNoiseResult, NoiseSample,
    PBS128InputBRParams,
};
use crate::shortint::server_key::tests::noise_distribution::{
    scalar_multiplication_variance, should_run_long_pfail_tests, should_use_one_key_per_sample,
};
use crate::shortint::server_key::ModulusSwitchNoiseReductionKey;
use crate::shortint::{CarryModulus, ClientKey, MessageModulus, PBSParameters};

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::glwe_sample_extraction::cuda_extract_lwe_samples_from_glwe_ciphertext_list;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{
    add_lwe_ciphertext_vector_plaintext_scalar_async, cuda_improve_noise_modulus_switch_ciphertext,
    cuda_keyswitch_lwe_ciphertext, cuda_lwe_ciphertext_plaintext_sub_assign,
    cuda_modulus_switch_ciphertext, cuda_modulus_switch_multi_bit_ciphertext,
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
    cuda_programmable_bootstrap_128_lwe_ciphertext,
    cuda_programmable_bootstrap_128_lwe_ciphertext_async,
    cuda_programmable_bootstrap_lwe_ciphertext,
    cuda_programmable_bootstrap_lwe_ciphertext_no_ms_noise_reduction, CudaStreams,
};
use crate::core_crypto::prelude::{
    decrypt_lwe_ciphertext, Cleartext, LweBskGroupingFactor, LweCiphertextCount,
    LweCiphertextOwned, LweDimension, LweSecretKey,
};
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;

use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    gen_keys_radix_gpu, unchecked_small_scalar_mul_integer_async, CudaServerKey,
};
use crate::integer::RadixClientKey;

use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::numeric::CastInto;
use itertools::Itertools;
use rayon::prelude::*;

pub fn decrypt_multi_bit_lwe_ciphertext(
    lwe_secret_key: &LweSecretKey<&[u64]>,
    lwe_dimension: LweDimension,
    grouping_factor: LweBskGroupingFactor,
    lwe_ciphertext: &LweCiphertext<Vec<u64>>,
    mod_switched_array: &[u64],
) -> u64 {
    let mut result = *lwe_ciphertext.get_body().data;

    for loop_idx in 0..(lwe_dimension.0 / grouping_factor.0) {
        let mask_start_idx = loop_idx * grouping_factor.0;
        let mask_stop_idx = mask_start_idx + grouping_factor.0;

        let lwe_key_bits = &lwe_secret_key.as_ref()[mask_start_idx..mask_stop_idx];

        let num_elem = (1 << grouping_factor.0) - 1 as usize;
        let mod_switched_array_slice =
            &mod_switched_array[loop_idx * num_elem..(loop_idx + 1) * num_elem];

        let selector = {
            let mut selector = 0usize;
            for bit in lwe_key_bits.iter() {
                let bit: usize = (*bit).cast_into();
                selector <<= 1;
                selector |= bit;
            }
            if selector == 0 {
                None
            } else {
                Some(selector - 1)
            }
        };

        if let Some(selector) = selector {
            let mod_switched = mod_switched_array_slice[selector];
            result = result.wrapping_sub(mod_switched);
        }
    }
    result
}

fn multi_bit_pbs_variance_132_bits_security_tuniform(
    input_lwe_dimension: LweDimension,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    decomposition_base: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    modulus: f64,
    grouping_factor: u32,
) -> Variance {
    match grouping_factor {
        2 => multi_bit_pbs_variance_132_bits_security_tuniform_gf_2_fft_mul(
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            decomposition_base,
            decomposition_level_count,
            modulus,
        ),
        3 => multi_bit_pbs_variance_132_bits_security_tuniform_gf_3_fft_mul(
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            decomposition_base,
            decomposition_level_count,
            modulus,
        ),
        4 => multi_bit_pbs_variance_132_bits_security_tuniform_gf_4_fft_mul(
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            decomposition_base,
            decomposition_level_count,
            modulus,
        ),
        _ => panic!("Unsupported grouping factor for multi bit PBS"),
    }
}

fn multi_bit_pbs_variance_132_bits_security_gaussian(
    input_lwe_dimension: LweDimension,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    decomposition_base: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    modulus: f64,
    grouping_factor: u32,
) -> Variance {
    match grouping_factor {
        2 => multi_bit_pbs_variance_132_bits_security_gaussian_gf_2_fft_mul(
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            decomposition_base,
            decomposition_level_count,
            modulus,
        ),
        3 => multi_bit_pbs_variance_132_bits_security_gaussian_gf_3_fft_mul(
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            decomposition_base,
            decomposition_level_count,
            modulus,
        ),
        4 => multi_bit_pbs_variance_132_bits_security_gaussian_gf_4_fft_mul(
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            decomposition_base,
            decomposition_level_count,
            modulus,
        ),
        _ => panic!("Unsupported grouping factor for multi bit PBS"),
    }
}

fn noise_check_shortint_classic_pbs_before_pbs_after_encryption_noise_gpu<P>(parameters_set: P)
where
    P: Into<PBSParameters>,
{
    let params = parameters_set.into();

    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let modulus_as_f64 = if params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        params.ciphertext_modulus().get_custom_modulus() as f64
    };
    let shortint_parameters_set: ShortintParameterSet = params.into();
    let encryption_noise = shortint_parameters_set.encryption_noise_distribution();

    let gpu_index = 0;
    let my_streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    // Generate the client key and the server key:
    let (single_radix_cks, single_sks) = gen_keys_radix_gpu(params, num_blocks, &my_streams);

    let small_lwe_secret_key = match &single_radix_cks.as_ref().key.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ap_ck) => todo!(),
    };

    // Variance after encryption
    let encryption_variance = match encryption_noise {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let input_ks_lwe_dimension = single_sks.key_switching_key.input_key_lwe_dimension();
    let output_ks_lwe_dimension = single_sks.key_switching_key.output_key_lwe_dimension();
    let ks_decomp_base_log = single_sks.key_switching_key.decomposition_base_log();
    let ks_decomp_level_count = single_sks.key_switching_key.decomposition_level_count();

    // Compute expected variance after encryption and the first compute loop until blind rotation,
    // we check the noise before entering the blind rotation
    //
    // For a big key encryption that is:
    // Encrypt -> x MaxNoiseLevel -> KS -> MS (-> BR)
    let scalar_for_multiplication = params.max_noise_level().get();

    let expected_variance_after_multiplication =
        scalar_multiplication_variance(encryption_variance, scalar_for_multiplication);

    // The keyswitching key uses the noise from the lwe_noise_distribution
    let ks_additive_variance = match params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_ks =
        Variance(expected_variance_after_multiplication.0 + ks_additive_variance.0);

    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_input_modulus = 1u64 << br_input_modulus_log.0;
    let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;

    let ms_additive_var: Variance = match &single_sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(_d_bsk) => modulus_switch_additive_variance(
            output_ks_lwe_dimension,
            modulus_as_f64,
            br_input_modulus as f64,
        ),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            modulus_switch_multi_bit_additive_variance(
                output_ks_lwe_dimension,
                modulus_as_f64,
                br_input_modulus as f64,
                d_multibit_bsk.grouping_factor.0 as f64,
            )
        }
    };

    let expected_variance_after_ms = Variance(expected_variance_after_ks.0 + ms_additive_var.0);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples = vec![];
    let num_ct_blocks = 1;
    let num_runs = 1000u32;
    let num_streams = 16 as u32;
    let vec_local_streams = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(0)))
        .collect::<Vec<_>>();
    for msg in 0..cleartext_modulus {
        let current_noise_samples: Vec<_> = (0..num_runs)
            .into_par_iter()
            .map(|index| {
                let stream_index: usize = (index % num_streams).try_into().unwrap();
                let streams = &vec_local_streams[stream_index];
                let thread_cks: crate::integer::client_key::RadixClientKey;
                let thread_sks: CudaServerKey;
                let (cks, sks) = if should_use_one_key_per_sample() {
                    (thread_cks, thread_sks) = gen_keys_radix_gpu(params, num_blocks, streams);
                    (&thread_cks, &thread_sks)
                } else {
                    (&single_radix_cks, &single_sks)
                };
                let ct = cks.encrypt(0u16);

                let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, streams);

                let big_lwe_dim = params.polynomial_size().0 * params.glwe_dimension().0;
                unsafe {
                    unchecked_small_scalar_mul_integer_async(
                        streams,
                        &mut d_ct.ciphertext,
                        scalar_for_multiplication,
                    );
                }
                streams.synchronize();

                // Put the message back in after mul to have our msg in a noisy ct
                let tmp = d_ct.duplicate(streams);
                let encoded_msg = sks.encoding().encode(Cleartext(msg));
                unsafe {
                    add_lwe_ciphertext_vector_plaintext_scalar_async(
                        streams,
                        &mut d_ct.as_mut().d_blocks.0.d_vec,
                        &tmp.as_ref().d_blocks.0.d_vec,
                        encoded_msg.0,
                        LweDimension(big_lwe_dim),
                        num_ct_blocks as u32,
                    );
                }
                streams.synchronize();

                let after_ks_lwe_aux = LweCiphertext::new(
                    0u64,
                    sks.key_switching_key.output_key_lwe_size(),
                    sks.key_switching_key.ciphertext_modulus(),
                );
                let mut d_after_ks =
                    CudaLweCiphertextList::from_lwe_ciphertext(&after_ks_lwe_aux, streams);

                let h_indexes = &[u64::ZERO];
                let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(1, streams, 0) };
                let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(1, streams, 0) };
                unsafe {
                    d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), streams, 0);
                    d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), streams, 0);
                }
                streams.synchronize();

                cuda_keyswitch_lwe_ciphertext(
                    &sks.key_switching_key,
                    &d_ct.as_mut().d_blocks,
                    &mut d_after_ks,
                    &d_input_indexes,
                    &d_output_indexes,
                    streams,
                );

                let mut d_after_ms = CudaLweCiphertextList::from_cuda_vec(
                    d_after_ks.0.d_vec,
                    LweCiphertextCount(1),
                    params.ciphertext_modulus(),
                );
                let mut mod_switched_array: Vec<u64> = match &sks.bootstrapping_key {
                    CudaBootstrappingKey::Classic(_d_bsk) => Vec::with_capacity(0),
                    CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                        let mod_switched_array_size = (2_u32
                            .pow(d_multibit_bsk.grouping_factor.0.try_into().unwrap())
                            as usize
                            - 1)
                            * d_multibit_bsk.input_lwe_dimension.0;
                        vec![0; mod_switched_array_size]
                    }
                };

                match &sks.bootstrapping_key {
                    CudaBootstrappingKey::Classic(_d_bsk) => {
                        cuda_modulus_switch_ciphertext(
                            &mut d_after_ms,
                            br_input_modulus_log.0 as u32,
                            streams,
                        );
                    }
                    CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                        let mod_switched_array_size = (2_u32
                            .pow(d_multibit_bsk.grouping_factor.0.try_into().unwrap())
                            as usize
                            - 1)
                            * d_multibit_bsk.input_lwe_dimension.0;

                        let mut d_mod_switched_array = unsafe {
                            CudaVec::<u64>::new_async(mod_switched_array_size, streams, 0)
                        };
                        cuda_modulus_switch_multi_bit_ciphertext(
                            &mut d_mod_switched_array,
                            &mut d_after_ms,
                            br_input_modulus_log.0 as u32,
                            params.polynomial_size().0 as u32,
                            d_multibit_bsk.grouping_factor.0 as u32,
                            streams,
                        );
                        unsafe {
                            d_mod_switched_array.copy_to_cpu_async(
                                &mut mod_switched_array,
                                streams,
                                0,
                            );
                        }
                        streams.synchronize();
                    }
                };

                let after_ms_list = d_after_ms.to_lwe_ciphertext_list(streams);
                let mut after_ms = LweCiphertext::from_container(
                    after_ms_list.into_container(),
                    params.ciphertext_modulus(),
                );

                let decrypted = match &sks.bootstrapping_key {
                    CudaBootstrappingKey::Classic(_d_bsk) => {
                        for val in after_ms.as_mut() {
                            *val <<= shift_to_map_to_native;
                        }
                        decrypt_lwe_ciphertext(&small_lwe_secret_key, &after_ms).0
                    }
                    CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                        for val in mod_switched_array.iter_mut() {
                            *val <<= shift_to_map_to_native;
                        }
                        decrypt_multi_bit_lwe_ciphertext(
                            &small_lwe_secret_key,
                            output_ks_lwe_dimension,
                            d_multibit_bsk.grouping_factor,
                            &after_ms,
                            &mod_switched_array,
                        )
                    }
                };

                let delta = (1u64 << 63) / (cleartext_modulus);
                let expected_plaintext = msg * delta;

                // We apply the modulus on the cleartext + the padding bit
                let decoded = round_decode(decrypted, delta) % (2 * cleartext_modulus);
                assert_eq!(decoded, msg);

                torus_modular_diff(expected_plaintext, decrypted, after_ms.ciphertext_modulus())
            })
            .collect();

        noise_samples.extend(current_noise_samples);
    }

    let measured_mean = arithmetic_mean(&noise_samples);
    let measured_variance = variance(&noise_samples);

    let mean_ci = mean_confidence_interval(
        noise_samples.len() as f64,
        measured_mean,
        measured_variance.get_standard_dev(),
        0.99,
    );

    let variance_ci =
        variance_confidence_interval(noise_samples.len() as f64, measured_variance, 0.99);

    let expected_mean = 0.0;

    println!("measured_variance={measured_variance:?}");
    println!("expected_variance_after_ms={expected_variance_after_ms:?}");
    println!("variance_lower_bound={:?}", variance_ci.lower_bound());
    println!("variance_upper_bound={:?}", variance_ci.upper_bound());
    println!("measured_mean={measured_mean:?}");
    println!("expected_mean={expected_mean:?}");
    println!("mean_lower_bound={:?}", mean_ci.lower_bound());
    println!("mean_upper_bound={:?}", mean_ci.upper_bound());

    let pbs_input_lwe_dimension = match &single_sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(d_bsk) => d_bsk.input_lwe_dimension(),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => d_multibit_bsk.input_lwe_dimension(),
    };

    // Expected mean is 0
    assert!(mean_ci.mean_is_in_interval(expected_mean));
    // We want to be smaller but secure or in the interval
    if measured_variance <= expected_variance_after_ms {
        let noise_for_security = match params.lwe_noise_distribution() {
            DynamicDistribution::Gaussian(_) => {
                minimal_lwe_variance_for_132_bits_security_gaussian(
                    pbs_input_lwe_dimension,
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    pbs_input_lwe_dimension,
                    modulus_as_f64,
                )
            }
        };

        if !variance_ci.variance_is_in_interval(expected_variance_after_ms) {
            println!(
                "\n==========\n\
                Warning: noise formula might be over estimating the noise.\n\
                ==========\n"
            );
        }

        assert!(measured_variance >= noise_for_security);
    } else {
        assert!(variance_ci.variance_is_in_interval(expected_variance_after_ms));
    }

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.01); println!("{}", normality_check.p_value);
    // assert!(normality_check.null_hypothesis_is_valid);
}

create_parameterized_test!(
    noise_check_shortint_classic_pbs_before_pbs_after_encryption_noise_gpu {
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    }
);

fn classic_pbs_atomic_pattern_inner_helper_gpu(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
    streams: &CudaStreams,
) -> (DecryptionAndNoiseResult, DecryptionAndNoiseResult) {
    assert!(params.pbs_only());
    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let num_ct_blocks = 1;
    let thread_cks: &crate::integer::client_key::ClientKey;
    let thread_sks: CudaServerKey;
    let thread_radix_cks: RadixClientKey;
    let (cks, sks) = if should_use_one_key_per_sample() {
        (thread_radix_cks, thread_sks) = gen_keys_radix_gpu(params, num_ct_blocks, streams);
        thread_cks = thread_radix_cks.as_ref();

        (&thread_cks.key, &thread_sks)
    } else {
        // If we don't want to use per thread keys (to go faster), we use those single keys for all
        // threads
        (single_cks, single_sks)
    };

    let small_lwe_secret_key = match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ap_ck) => todo!(),
    };

    let identity_lut = sks.generate_lookup_table(|x| x);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;

    let delta = (1u64 << 63) / cleartext_modulus;
    let native_mod_plaintext = Plaintext(msg * delta);

    // We want to encrypt the ciphertext under modulus 2N but then use the native
    // modulus to simulate a noiseless mod switch as input
    let mut rsc = TestResources::new();
    let d_input_pbs_lwe_ct = {
        let ms_modulus = CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();
        let no_noise_dist = DynamicDistribution::new_gaussian(Variance(0.0));

        let ms_delta = ms_modulus.get_custom_modulus() as u64 / (2 * cleartext_modulus);

        let ms_plaintext = Plaintext(msg * ms_delta);

        let simulated_mod_switch_ct = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_secret_key,
            ms_plaintext,
            no_noise_dist,
            ms_modulus,
            &mut rsc.encryption_random_generator,
        );

        let raw_data = simulated_mod_switch_ct.into_container();
        // Now get the noiseless mod switched encryption under the proper modulus
        // The power of 2 modulus are always encrypted in the MSBs, so this is fine
        let h_ct = LweCiphertext::from_container(raw_data, params.ciphertext_modulus());
        let d_ct = CudaLweCiphertextList::from_lwe_ciphertext(&h_ct, streams);
        d_ct
    };

    let mut after_pbs_shortint_ct: CudaUnsignedRadixCiphertext =
        sks.create_trivial_zero_radix(num_ct_blocks, streams);

    // Need to generate the required indexes for the PBS
    let mut lut_vector_indexes: Vec<u64> = vec![u64::ZERO; num_ct_blocks];
    for (i, ind) in lut_vector_indexes.iter_mut().enumerate() {
        *ind = <usize as CastInto<u64>>::cast_into(i);
    }
    let mut d_lut_vector_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    unsafe { d_lut_vector_indexes.copy_from_cpu_async(&lut_vector_indexes, streams, 0) };
    let lwe_indexes_usize: Vec<usize> = (0..num_ct_blocks).collect_vec();
    let lwe_indexes = lwe_indexes_usize
        .iter()
        .map(|&x| <usize as CastInto<u64>>::cast_into(x))
        .collect_vec();
    let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    unsafe {
        d_input_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
        d_output_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
    }

    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&identity_lut.acc, streams);

    match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(d_bsk) => {
            cuda_programmable_bootstrap_lwe_ciphertext(
                &d_input_pbs_lwe_ct,
                &mut after_pbs_shortint_ct.as_mut().d_blocks,
                &d_accumulator,
                &d_lut_vector_indexes,
                &d_output_indexes,
                &d_input_indexes,
                LweCiphertextCount(num_ct_blocks),
                d_bsk,
                streams,
            );
        }
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                &d_input_pbs_lwe_ct,
                &mut after_pbs_shortint_ct.as_mut().d_blocks,
                &d_accumulator,
                &d_lut_vector_indexes,
                &d_output_indexes,
                &d_input_indexes,
                d_multibit_bsk,
                streams,
            );
        }
    }
    after_pbs_shortint_ct.ciphertext.info.blocks[0]
        .set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

    // Remove the plaintext before the mul to avoid degree issues but sill increase the
    // noise
    let scalar_vector = vec![native_mod_plaintext.0; num_ct_blocks];
    let mut d_decomposed_scalar = CudaVec::<u64>::new(num_ct_blocks, streams, 0);
    unsafe {
        d_decomposed_scalar.copy_from_cpu_async(scalar_vector.as_slice(), streams, 0);
    }

    cuda_lwe_ciphertext_plaintext_sub_assign(
        &mut after_pbs_shortint_ct.as_mut().d_blocks,
        &d_decomposed_scalar,
        streams,
    );

    let big_lwe_dim = params.polynomial_size().0 * params.glwe_dimension().0;
    let scalar_u64 = scalar_for_multiplication as u64;

    unsafe {
        unchecked_small_scalar_mul_integer_async(
            streams,
            &mut after_pbs_shortint_ct.ciphertext,
            scalar_u64,
        );
    }
    streams.synchronize();

    // Put the message back in after mul to have our msg in a noisy ct
    let tmp = after_pbs_shortint_ct.duplicate(streams);
    let encoded_msg = sks.encoding().encode(Cleartext(msg));
    unsafe {
        add_lwe_ciphertext_vector_plaintext_scalar_async(
            streams,
            &mut after_pbs_shortint_ct.as_mut().d_blocks.0.d_vec,
            &tmp.as_ref().d_blocks.0.d_vec,
            encoded_msg.0,
            LweDimension(big_lwe_dim),
            num_ct_blocks as u32,
        );
    }
    streams.synchronize();

    let after_ks_lwe_aux = LweCiphertext::new(
        0u64,
        sks.key_switching_key.output_key_lwe_size(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    let mut d_after_ks_lwe = CudaLweCiphertextList::from_lwe_ciphertext(&after_ks_lwe_aux, streams);

    //Indexes needed for the keyswitch
    let h_indexes = [u64::ZERO];
    let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(1, streams, 0) };
    let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(1, streams, 0) };
    unsafe {
        d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), streams, 0);
        d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), streams, 0);
    }
    streams.synchronize();

    cuda_keyswitch_lwe_ciphertext(
        &sks.key_switching_key,
        &after_pbs_shortint_ct.as_mut().d_blocks,
        &mut d_after_ks_lwe,
        &d_input_indexes,
        &d_output_indexes,
        streams,
    );

    let after_ks_lwe_list = d_after_ks_lwe.to_lwe_ciphertext_list(streams);
    let after_ks_lwe = LweCiphertext::from_container(
        after_ks_lwe_list.into_container(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    let mut d_after_ms_lwe = CudaLweCiphertextList::from_cuda_vec(
        d_after_ks_lwe.0.d_vec,
        LweCiphertextCount(1),
        params.ciphertext_modulus(),
    );
    let mut mod_switched_array: Vec<u64> = match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(_d_bsk) => Vec::with_capacity(0),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            let mod_switched_array_size =
                (2_u32.pow(d_multibit_bsk.grouping_factor.0.try_into().unwrap()) as usize - 1)
                    * d_multibit_bsk.input_lwe_dimension.0;
            vec![0; mod_switched_array_size]
        }
    };

    match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(_d_bsk) => {
            cuda_modulus_switch_ciphertext(
                &mut d_after_ms_lwe,
                br_input_modulus_log.0 as u32,
                streams,
            );
        }
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            let mod_switched_array_size =
                (2_u32.pow(d_multibit_bsk.grouping_factor.0.try_into().unwrap()) as usize - 1)
                    * d_multibit_bsk.input_lwe_dimension.0;

            let mut d_mod_switched_array =
                unsafe { CudaVec::<u64>::new_async(mod_switched_array_size, streams, 0) };
            cuda_modulus_switch_multi_bit_ciphertext(
                &mut d_mod_switched_array,
                &mut d_after_ms_lwe,
                br_input_modulus_log.0 as u32,
                params.polynomial_size().0 as u32,
                d_multibit_bsk.grouping_factor.0 as u32,
                streams,
            );
            unsafe {
                d_mod_switched_array.copy_to_cpu_async(&mut mod_switched_array, streams, 0);
            }
            streams.synchronize();
        }
    };

    let after_ms_lwe_list = d_after_ms_lwe.to_lwe_ciphertext_list(streams);
    let mut after_ms_lwe = LweCiphertext::from_container(
        after_ms_lwe_list.into_container(),
        params.ciphertext_modulus(),
    );

    let decryption_noise_after_ks = DecryptionAndNoiseResult::new(
        &after_ks_lwe,
        &small_lwe_secret_key,
        msg,
        delta,
        cleartext_modulus,
    );

    let decryption_noise_after_ms = match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(_d_bsk) => {
            for val in after_ms_lwe.as_mut() {
                *val <<= shift_to_map_to_native;
            }
            DecryptionAndNoiseResult::new(
                &after_ms_lwe,
                &small_lwe_secret_key,
                msg,
                delta,
                cleartext_modulus,
            )
        }
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            for val in mod_switched_array.iter_mut() {
                *val <<= shift_to_map_to_native;
            }
            let output_ks_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
            DecryptionAndNoiseResult::new_multi_bit(
                &after_ms_lwe,
                &small_lwe_secret_key,
                msg,
                delta,
                cleartext_modulus,
                d_multibit_bsk.grouping_factor,
                output_ks_lwe_dimension,
                &mod_switched_array,
            )
        }
    };

    (decryption_noise_after_ks, decryption_noise_after_ms)
}

fn classic_pbs_atomic_pattern_noise_helper_gpu(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
    streams: &CudaStreams,
) -> (NoiseSample, NoiseSample) {
    let (decryption_and_noise_result_after_ks, decryption_and_noise_result_after_ms) =
        classic_pbs_atomic_pattern_inner_helper_gpu(
            params,
            single_cks,
            single_sks,
            msg,
            scalar_for_multiplication,
            streams,
        );

    (
        match decryption_and_noise_result_after_ks {
            DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
            DecryptionAndNoiseResult::DecryptionFailed => {
                panic!("Failed decryption, noise measurement will be wrong.")
            }
        },
        match decryption_and_noise_result_after_ms {
            DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
            DecryptionAndNoiseResult::DecryptionFailed => {
                panic!("Failed decryption, noise measurement will be wrong.")
            }
        },
    )
}

/// Return 1 if the decryption failed, otherwise 0, allowing to sum the results of threads to get
/// the failure rate.
fn classic_pbs_atomic_pattern_pfail_helper_gpu(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
    streams: &CudaStreams,
) -> f64 {
    let (_decryption_and_noise_result_after_ks, decryption_and_noise_result_after_ms) =
        classic_pbs_atomic_pattern_inner_helper_gpu(
            params,
            single_cks,
            single_sks,
            msg,
            scalar_for_multiplication,
            streams,
        );

    match decryption_and_noise_result_after_ms {
        DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
        DecryptionAndNoiseResult::DecryptionFailed => 1.0,
    }
}

fn noise_check_shortint_classic_pbs_atomic_pattern_noise_gpu<P>(parameters_set: P)
where
    P: Into<PBSParameters>,
{
    let params = parameters_set.into();

    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let modulus_as_f64 = if params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    // Generate the client key and the server key:
    let (radix_cks, sks) = gen_keys_radix_gpu(params, num_blocks, &streams);
    let cks = radix_cks.as_ref();

    let small_lwe_secret_key = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ap_ck) => todo!(),
    };

    let (
        input_pbs_lwe_dimension,
        output_glwe_dimension,
        output_polynomial_size,
        pbs_decomp_base_log,
        pbs_decomp_level_count,
    ) = match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(d_bsk) => (
            d_bsk.input_lwe_dimension(),
            d_bsk.glwe_dimension(),
            d_bsk.polynomial_size(),
            d_bsk.decomp_base_log(),
            d_bsk.decomp_level_count(),
        ),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => (
            d_multibit_bsk.input_lwe_dimension(),
            d_multibit_bsk.glwe_dimension(),
            d_multibit_bsk.polynomial_size(),
            d_multibit_bsk.decomp_base_log(),
            d_multibit_bsk.decomp_level_count(),
        ),
    };

    let input_ks_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let output_ks_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

    // Compute expected variance after getting out of a PBS and doing a full AP until the next mod
    // switch
    //
    // For a big key encryption that is:
    // Encrypt under modulus 2N (start at modswitch) -> BR -> SE -> x MaxNoiseLevel -> KS -> MS (->
    // BR)

    let scalar_for_multiplication = params.max_noise_level().get();

    let expected_variance_after_pbs = match params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => match &sks.bootstrapping_key {
            CudaBootstrappingKey::Classic(_d_bsk) => pbs_variance_132_bits_security_gaussian(
                input_pbs_lwe_dimension,
                output_glwe_dimension,
                output_polynomial_size,
                pbs_decomp_base_log,
                pbs_decomp_level_count,
                modulus_as_f64,
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                multi_bit_pbs_variance_132_bits_security_gaussian(
                    input_pbs_lwe_dimension,
                    output_glwe_dimension,
                    output_polynomial_size,
                    pbs_decomp_base_log,
                    pbs_decomp_level_count,
                    modulus_as_f64,
                    d_multibit_bsk.grouping_factor.0 as u32,
                )
            }
        },
        DynamicDistribution::TUniform(_) => match &sks.bootstrapping_key {
            CudaBootstrappingKey::Classic(_d_bsk) => pbs_variance_132_bits_security_tuniform(
                input_pbs_lwe_dimension,
                output_glwe_dimension,
                output_polynomial_size,
                pbs_decomp_base_log,
                pbs_decomp_level_count,
                modulus_as_f64,
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                multi_bit_pbs_variance_132_bits_security_tuniform(
                    input_pbs_lwe_dimension,
                    output_glwe_dimension,
                    output_polynomial_size,
                    pbs_decomp_base_log,
                    pbs_decomp_level_count,
                    modulus_as_f64,
                    d_multibit_bsk.grouping_factor.0 as u32,
                )
            }
        },
    };

    let expected_variance_after_multiplication =
        scalar_multiplication_variance(expected_variance_after_pbs, scalar_for_multiplication);

    // The keyswitching key uses the noise from the lwe_noise_distribution
    let ks_additive_variance = match params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_ks =
        Variance(expected_variance_after_multiplication.0 + ks_additive_variance.0);

    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_input_modulus = 1u64 << br_input_modulus_log.0;

    let ms_additive_var: Variance = match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(_d_bsk) => modulus_switch_additive_variance(
            output_ks_lwe_dimension,
            modulus_as_f64,
            br_input_modulus as f64,
        ),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            modulus_switch_multi_bit_additive_variance(
                output_ks_lwe_dimension,
                modulus_as_f64,
                br_input_modulus as f64,
                d_multibit_bsk.grouping_factor.0 as f64,
            )
        }
    };

    let expected_variance_after_ms = Variance(expected_variance_after_ks.0 + ms_additive_var.0);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_after_ks = vec![];
    let mut noise_samples_after_ms = vec![];
    for msg in 0..cleartext_modulus {
        let (current_noise_samples_after_ks, current_noise_samples_after_ms): (Vec<_>, Vec<_>) = (0
            ..100)
            .into_par_iter()
            .map(|_| {
                let my_stream = CudaStreams::new_single_gpu(GpuIndex::new(0));
                classic_pbs_atomic_pattern_noise_helper_gpu(
                    params.into(),
                    &cks.key,
                    &sks,
                    msg,
                    scalar_for_multiplication.try_into().unwrap(),
                    &my_stream,
                )
            })
            .unzip();

        noise_samples_after_ks.extend(current_noise_samples_after_ks.into_iter().map(|x| x.value));
        noise_samples_after_ms.extend(current_noise_samples_after_ms.into_iter().map(|x| x.value));
    }

    // let measured_mean_after_ms = arithmetic_mean(&noise_samples_after_ms);
    // let measured_variance_after_ms = variance(&noise_samples_after_ms);

    // let mean_ci = mean_confidence_interval(
    //     noise_samples_after_ms.len() as f64,
    //     measured_mean_after_ms,
    //     measured_variance_after_ms.get_standard_dev(),
    //     0.99,
    // );

    // let variance_ci = variance_confidence_interval(
    //     noise_samples_after_ms.len() as f64,
    //     measured_variance_after_ms,
    //     0.99,
    // );

    // let expected_mean_after_ms = 0.0;

    // println!("measured_variance_after_ms={measured_variance_after_ms:?}");
    // println!("expected_variance_after_ms={expected_variance_after_ms:?}");
    // println!("variance_lower_bound={:?}", variance_ci.lower_bound());
    // println!("variance_upper_bound={:?}", variance_ci.upper_bound());
    // println!("measured_mean_after_ms={measured_mean_after_ms:?}");
    // println!("expected_mean_after_ms={expected_mean_after_ms:?}");
    // println!("mean_lower_bound={:?}", mean_ci.lower_bound());
    // println!("mean_upper_bound={:?}", mean_ci.upper_bound());

    // // Expected mean is 0
    // assert!(mean_ci.mean_is_in_interval(expected_mean_after_ms));
    // // We want to be smaller but secure or in the interval
    // if measured_variance_after_ms <= expected_variance_after_ms {
    //     let noise_for_security = match params.lwe_noise_distribution() {
    //         DynamicDistribution::Gaussian(_) => {
    //             minimal_lwe_variance_for_132_bits_security_gaussian(
    //                 sks.bootstrapping_key.input_lwe_dimension(),
    //                 modulus_as_f64,
    //             )
    //         }
    //         DynamicDistribution::TUniform(_) => {
    //             minimal_lwe_variance_for_132_bits_security_tuniform(
    //                 sks.bootstrapping_key.input_lwe_dimension(),
    //                 modulus_as_f64,
    //             )
    //         }
    //     };

    //     if !variance_ci.variance_is_in_interval(expected_variance_after_ms) {
    //         println!(
    //             "\n==========\n\
    //             Warning: noise formula might be over estimating the noise.\n\
    //             ==========\n"
    //         );
    //     }

    //     assert!(measured_variance_after_ms >= noise_for_security);
    // } else {
    //     assert!(variance_ci.variance_is_in_interval(expected_variance_after_ms));
    // }

    let after_ks_ok = mean_and_variance_check(
        &noise_samples_after_ks,
        "after_ks",
        0.0,
        expected_variance_after_ks,
        params.lwe_noise_distribution(),
        small_lwe_secret_key.lwe_dimension(),
        modulus_as_f64,
    );

    let after_ms_ok = mean_and_variance_check(
        &noise_samples_after_ms,
        "after_ms",
        0.0,
        expected_variance_after_ms,
        params.lwe_noise_distribution(),
        small_lwe_secret_key.lwe_dimension(),
        modulus_as_f64,
    );

    let normality_check = normality_test_f64(
        &noise_samples_after_ks[..5000.min(noise_samples_after_ks.len())],
        0.01,
    );

    if normality_check.null_hypothesis_is_valid {
        println!("Normality check after KS is OK\n");
    } else {
        println!("Normality check after KS failed\n");
    }

    assert!(after_ks_ok && after_ms_ok && normality_check.null_hypothesis_is_valid);

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);
}

create_parameterized_test!(noise_check_shortint_classic_pbs_atomic_pattern_noise_gpu {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn noise_check_shortint_classic_pbs_atomic_pattern_pfail_gpu<P>(parameters_set: P)
where
    P: Into<PBSParameters>,
{
    let mut params = parameters_set.into();

    assert_eq!(
        params.carry_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        params.message_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * params.carry_modulus().0 * params.message_modulus().0).ilog2();

    params.set_carry_modulus(CarryModulus(1 << 4));

    let new_precision_with_padding =
        (2 * params.carry_modulus().0 * params.message_modulus().0).ilog2();

    let original_pfail = 2.0f64.powf(params.log2_p_fail());

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", params.log2_p_fail());

    let expected_pfail = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    params.set_log2_p_fail(expected_pfail.log2());

    println!("expected_pfail={expected_pfail}");
    println!("expected_pfail_log2={}", params.log2_p_fail());

    let (runs_for_expected_fails, expected_fails) = if should_run_long_pfail_tests() {
        let total_runs = 1_000_000;
        let expected_fails = (total_runs as f64 * expected_pfail).round() as u32;
        (total_runs, expected_fails)
    } else {
        let expected_fails = 200;
        let runs_for_expected_fails = (expected_fails as f64 / expected_pfail).round() as u32;
        (runs_for_expected_fails, expected_fails)
    };

    println!("runs_for_expected_fails={runs_for_expected_fails}");

    let params: ShortintParameterSet = params.into();
    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let scalar_for_multiplication = params.max_noise_level().get();

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    // Generate the client key and the server key:
    let (radix_cks, sks) = gen_keys_radix_gpu(params, num_blocks, &streams);
    let cks = radix_cks.as_ref();

    let measured_fails: f64 = (0..runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % cleartext_modulus;
            let my_stream = CudaStreams::new_single_gpu(GpuIndex::new(0));
            classic_pbs_atomic_pattern_pfail_helper_gpu(
                params,
                &cks.key,
                &sks,
                msg,
                scalar_for_multiplication.try_into().unwrap(),
                &my_stream,
            )
        })
        .sum();

    let measured_pfail = measured_fails / (runs_for_expected_fails as f64);

    println!("measured_fails={measured_fails}");
    println!("expected_fails={expected_fails}");
    println!("measured_pfail={measured_pfail}");
    println!("expected_pfail={expected_pfail}");

    let equivalent_measured_pfail = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail={equivalent_measured_pfail}");
    println!("original_expected_pfail  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_log2={}",
        equivalent_measured_pfail.log2()
    );
    println!("original_expected_pfail_log2  ={}", original_pfail.log2());

    if measured_fails > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            runs_for_expected_fails as f64,
            measured_fails,
            0.99,
        );

        println!(
            "pfail_lower_bound={}",
            pfail_confidence_interval.lower_bound()
        );
        println!(
            "pfail_upper_bound={}",
            pfail_confidence_interval.upper_bound()
        );

        if measured_pfail <= expected_pfail {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters, \
            or some hypothesis does not hold.\n\
            ==========\n"
        );
    }
}

create_parameterized_test!(noise_check_shortint_classic_pbs_atomic_pattern_pfail_gpu {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn pbs_compress_and_classic_ap_inner_helper_gpu(
    block_params: ShortintParameterSet,
    compression_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CudaCompressionKey,
    single_decompression_key: &CudaDecompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
    pfail_special_case: CompressionSpecialPfailCase,
    streams: &CudaStreams,
) -> (Vec<DecryptionAndNoiseResult>, Vec<DecryptionAndNoiseResult>) {
    match pfail_special_case {
        CompressionSpecialPfailCase::AfterAP {
            decryption_adapted_message_modulus,
            decryption_adapted_carry_modulus,
        } => {
            let adapted_cleartext_modulus =
                decryption_adapted_carry_modulus.0 * decryption_adapted_message_modulus.0;

            let cleartext_modulus =
                block_params.message_modulus().0 * block_params.carry_modulus().0;

            assert!(
                cleartext_modulus <= adapted_cleartext_modulus,
                "This test only works if the adapted cleartext \
                space is bigger than the original one."
            );
        }
        CompressionSpecialPfailCase::DoesNotNeedSpecialCase => (),
    };

    assert!(block_params.pbs_only());
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let thread_cks: &crate::integer::client_key::ClientKey;
    let thread_sks: CudaServerKey;
    let thread_compression_private_key: crate::integer::compression_keys::CompressionPrivateKeys;
    let thread_compression_key: CudaCompressionKey;
    let thread_decompression_key: CudaDecompressionKey;
    let thread_radix_cks: RadixClientKey;
    let num_blocks = 1;
    let (cks, sks, compression_private_key, compression_key, decompression_key) =
        if should_use_one_key_per_sample() {
            (thread_radix_cks, thread_sks) = gen_keys_radix_gpu(block_params, num_blocks, streams);
            thread_cks = thread_radix_cks.as_ref();

            thread_compression_private_key =
                thread_cks.new_compression_private_key(compression_params);
            (thread_compression_key, thread_decompression_key) = thread_radix_cks
                .new_cuda_compression_decompression_keys(&thread_compression_private_key, streams);

            (
                &thread_cks.key,
                &thread_sks,
                &thread_compression_private_key.key,
                &thread_compression_key,
                &thread_decompression_key,
            )
        } else {
            // If we don't want to use per thread keys (to go faster), we use those single keys for
            // all threads
            (
                single_cks,
                single_sks,
                single_compression_private_key,
                single_compression_key,
                single_decompression_key,
            )
        };
    let small_lwe_secret_key = match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ap_ck) => todo!(),
    };
    // We can only store values under message_modulus with the current compression scheme.
    let encryption_cleartext_modulus =
        block_params.message_modulus().0 * block_params.carry_modulus().0;
    let encryption_delta = (1u64 << 63) / encryption_cleartext_modulus;

    // We multiply by the message_modulus during compression, so the top bits corresponding to the
    // modulus won't be usable during compression
    let compression_cleartext_modulus =
        encryption_cleartext_modulus / block_params.message_modulus().0;
    let compression_delta = (1u64 << 63) / compression_cleartext_modulus;
    let msg = msg % compression_cleartext_modulus;

    let polynomial_size = match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(key) => key.polynomial_size(),
        CudaBootstrappingKey::MultiBit(key) => key.polynomial_size(),
    };

    let compute_br_input_modulus_log = polynomial_size.to_blind_rotation_input_modulus_log();

    let shift_to_map_to_native = u64::BITS - compute_br_input_modulus_log.0 as u32;
    let compute_br_input_modulus =
        CiphertextModulus::try_new_power_of_2(compute_br_input_modulus_log.0).unwrap();
    let no_noise_distribution = DynamicDistribution::new_gaussian(Variance(0.0));
    let br_modulus_delta =
        compute_br_input_modulus.get_custom_modulus() as u64 / (2 * encryption_cleartext_modulus);
    // Prepare the max number of LWE to pack, encrypt them under the compute PBS input modulus (2N)
    // without noise
    let num_ct_blocks = 1;

    // Prepare the indexes for the LUT (shared between all ciphertexts)
    let mut lut_vector_indexes: Vec<u64> = vec![u64::ZERO; num_ct_blocks];
    for (i, ind) in lut_vector_indexes.iter_mut().enumerate() {
        *ind = <usize as CastInto<u64>>::cast_into(i);
    }

    let mut d_lut_vector_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    unsafe { d_lut_vector_indexes.copy_from_cpu_async(&lut_vector_indexes, streams, 0) };
    let lwe_indexes_usize: Vec<usize> = (0..num_ct_blocks).collect_vec();
    let lwe_indexes = lwe_indexes_usize
        .iter()
        .map(|&x| <usize as CastInto<u64>>::cast_into(x))
        .collect_vec();
    let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    unsafe {
        d_input_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
        d_output_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
    }
    let num_streams = 16;
    let vec_local_streams = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(0)))
        .collect::<Vec<_>>();

    let ciphertexts = (0..compression_key.lwe_per_glwe.0)
        .into_par_iter()
        .map(|index| {
            let stream_index = index % num_streams;
            let local_streams = &vec_local_streams[stream_index];
            let mut shortint_ct: CudaUnsignedRadixCiphertext =
                sks.create_trivial_zero_radix(num_ct_blocks, local_streams);

            let mut rsc = TestResources::new();
            // Encrypt noiseless under 2N
            let encrypted_lwe_under_br_modulus = {
                let under_br_modulus = allocate_and_encrypt_new_lwe_ciphertext(
                    &small_lwe_secret_key,
                    Plaintext(msg * br_modulus_delta),
                    no_noise_distribution,
                    compute_br_input_modulus,
                    &mut rsc.encryption_random_generator,
                );
                let under_br_modulus_next = LweCiphertext::from_container(
                    under_br_modulus.into_container(),
                    shortint_ct.ciphertext.d_blocks.ciphertext_modulus(),
                );

                CudaLweCiphertextList::from_lwe_ciphertext(&under_br_modulus_next, local_streams)
            };

            let identity_lut = sks.generate_lookup_table(|x| x);
            let d_accumulator =
                CudaGlweCiphertextList::from_glwe_ciphertext(&identity_lut.acc, local_streams);

            match &sks.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_programmable_bootstrap_lwe_ciphertext(
                        &encrypted_lwe_under_br_modulus,
                        &mut shortint_ct.as_mut().d_blocks,
                        &d_accumulator,
                        &d_lut_vector_indexes,
                        &d_output_indexes,
                        &d_input_indexes,
                        LweCiphertextCount(num_ct_blocks),
                        d_bsk,
                        local_streams,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                        &encrypted_lwe_under_br_modulus,
                        &mut shortint_ct.as_mut().d_blocks,
                        &d_accumulator,
                        &d_lut_vector_indexes,
                        &d_output_indexes,
                        &d_input_indexes,
                        d_multibit_bsk,
                        local_streams,
                    );
                }
            }
            shortint_ct.ciphertext.info.blocks[0]
                .set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

            shortint_ct.ciphertext
        })
        .collect::<Vec<_>>();

    vec_local_streams.iter().for_each(|s| s.synchronize());

    // Do the compression process
    let packed_list = compression_key.compress_ciphertexts_into_list(&ciphertexts, streams);
    let cuda_extracted_glwe = packed_list.extract_glwe(0, streams);

    let mut vec_info = vec![];
    for _tmp_ct in ciphertexts.iter() {
        vec_info.push(DataKind::Unsigned(1));
    }
    let cuda_compressed_list = CudaCompressedCiphertextList {
        packed_list,
        info: vec_info,
    };
    assert_eq!(
        cuda_compressed_list.packed_list.glwe_ciphertext_count().0,
        1
    );

    let cuda_polynomial_size = cuda_compressed_list.packed_list.polynomial_size;

    let cuda_glwe_ciphertext_count = cuda_compressed_list.packed_list.glwe_ciphertext_count();

    let cuda_ciphertext_modulus = cuda_compressed_list.packed_list.ciphertext_modulus;

    let cuda_glwe_dimension = cuda_compressed_list.packed_list.glwe_dimension;

    let cuda_glwe_equivalent_lwe_dimension = cuda_compressed_list
        .packed_list
        .glwe_dimension
        .to_equivalent_lwe_dimension(cuda_polynomial_size);

    let nths = (0..(cuda_glwe_ciphertext_count.0 * cuda_polynomial_size.0))
        .map(|x| MonomialDegree(x % cuda_polynomial_size.0))
        .collect_vec();

    let mut d_lwes = CudaLweCiphertextList::new(
        cuda_glwe_equivalent_lwe_dimension,
        LweCiphertextCount(cuda_glwe_ciphertext_count.0 * cuda_polynomial_size.0),
        cuda_ciphertext_modulus,
        streams,
    );

    // Get the individual LWE ciphertexts back under the storage modulus
    let lwe_per_glwe = cuda_polynomial_size.0;
    cuda_extract_lwe_samples_from_glwe_ciphertext_list(
        &cuda_extracted_glwe,
        &mut d_lwes,
        nths.as_slice(),
        lwe_per_glwe.try_into().unwrap(),
        streams,
    );

    // Move results to CPU to calculate the noise
    let lwes_list = d_lwes.to_lwe_ciphertext_list(streams);
    let output_container = lwes_list.into_container();
    let lwes: Vec<_> = output_container
        .chunks_exact(cuda_polynomial_size.0 * cuda_glwe_dimension.0 + 1)
        .map(|s| LweCiphertextOwned::from_container(s.to_vec(), cuda_ciphertext_modulus))
        .collect();

    let after_compression_result: Vec<_> = lwes
        .into_par_iter()
        .map(|lwe| {
            DecryptionAndNoiseResult::new(
                &lwe,
                &compression_private_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                msg,
                compression_delta,
                compression_cleartext_modulus,
            )
        })
        .collect();

    let lwe_per_glwe = cuda_compressed_list.packed_list.lwe_per_glwe.0;

    let (after_ap_lwe, after_mod_arrays): (Vec<_>, Vec<_>) = (0..lwe_per_glwe)
        .into_par_iter()
        .map(|index| {
            let stream_index = index % num_streams;
            let local_streams = &vec_local_streams[stream_index];
            //Get data to do the unpack on GPU
            let preceding_infos = cuda_compressed_list.info.get(..index).unwrap();
            let current_info = cuda_compressed_list.info.get(index).copied().unwrap();
            let comp_message_modulus = cuda_compressed_list.packed_list.message_modulus;

            let start_block_index: usize = preceding_infos
                .iter()
                .copied()
                .map(|kind| kind.num_blocks(comp_message_modulus))
                .sum();
            let end_block_index =
                start_block_index + current_info.num_blocks(comp_message_modulus) - 1;

            let decompressed_radix = decompression_key
                .unpack(
                    &cuda_compressed_list.packed_list,
                    current_info,
                    start_block_index,
                    end_block_index,
                    local_streams,
                )
                .unwrap();

            let scalar_vector = vec![msg * encryption_delta; num_ct_blocks];
            let mut d_decomposed_scalar = CudaVec::<u64>::new(
                decompressed_radix.d_blocks.0.lwe_ciphertext_count.0,
                local_streams,
                0,
            );
            unsafe {
                d_decomposed_scalar.copy_from_cpu_async(scalar_vector.as_slice(), local_streams, 0);
            }
            let big_lwe_dim = decompressed_radix.d_blocks.0.lwe_dimension.0;
            let mut decompressed_ct = CudaUnsignedRadixCiphertext {
                ciphertext: decompressed_radix,
            };

            // Strictly remove the plaintext to avoid wrong results during the mul
            cuda_lwe_ciphertext_plaintext_sub_assign(
                &mut decompressed_ct.as_mut().d_blocks,
                &d_decomposed_scalar,
                local_streams,
            );

            unsafe {
                unchecked_small_scalar_mul_integer_async(
                    local_streams,
                    &mut decompressed_ct.ciphertext,
                    scalar_for_multiplication,
                );
            }

            let tmp = decompressed_ct.duplicate(local_streams);

            let encoded_msg = sks.encoding().encode(Cleartext(msg));
            unsafe {
                add_lwe_ciphertext_vector_plaintext_scalar_async(
                    local_streams,
                    &mut decompressed_ct.as_mut().d_blocks.0.d_vec,
                    &tmp.as_ref().d_blocks.0.d_vec,
                    encoded_msg.0,
                    LweDimension(big_lwe_dim),
                    num_ct_blocks as u32,
                );
            }

            let after_ks_lwe_aux = LweCiphertext::new(
                0u64,
                sks.key_switching_key.output_key_lwe_size(),
                sks.key_switching_key.ciphertext_modulus(),
            );
            let mut d_after_ks_lwe =
                CudaLweCiphertextList::from_lwe_ciphertext(&after_ks_lwe_aux, local_streams);
            // We need to create the indexes for the keyswitch
            let h_indexes = &[u64::ZERO];
            let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(1, local_streams, 0) };
            let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(1, local_streams, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), local_streams, 0);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), local_streams, 0);
            }

            cuda_keyswitch_lwe_ciphertext(
                &sks.key_switching_key,
                &decompressed_ct.as_mut().d_blocks, //&decompressed_radix.as_mut().d_blocks,
                &mut d_after_ks_lwe,
                &d_input_indexes,
                &d_output_indexes,
                local_streams,
            );

            let mut mod_switched_array: Vec<u64> = match &sks.bootstrapping_key {
                CudaBootstrappingKey::Classic(_d_bsk) => Vec::with_capacity(0),
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    let mod_switched_array_size =
                        (2_u32.pow(d_multibit_bsk.grouping_factor.0.try_into().unwrap()) as usize
                            - 1)
                            * d_multibit_bsk.input_lwe_dimension.0;
                    vec![0; mod_switched_array_size]
                }
            };

            match &sks.bootstrapping_key {
                CudaBootstrappingKey::Classic(_d_bsk) => {
                    cuda_modulus_switch_ciphertext(
                        &mut d_after_ks_lwe,
                        compute_br_input_modulus_log.0 as u32,
                        local_streams,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    let mod_switched_array_size =
                        (2_u32.pow(d_multibit_bsk.grouping_factor.0.try_into().unwrap()) as usize
                            - 1)
                            * d_multibit_bsk.input_lwe_dimension.0;
                    let mut d_mod_switched_array = unsafe {
                        CudaVec::<u64>::new_async(mod_switched_array_size, local_streams, 0)
                    };
                    cuda_modulus_switch_multi_bit_ciphertext(
                        &mut d_mod_switched_array,
                        &mut d_after_ks_lwe,
                        compute_br_input_modulus_log.0 as u32,
                        block_params.polynomial_size().0 as u32,
                        d_multibit_bsk.grouping_factor.0 as u32,
                        local_streams,
                    );
                    unsafe {
                        d_mod_switched_array.copy_to_cpu_async(
                            &mut mod_switched_array,
                            local_streams,
                            0,
                        );
                    }
                    local_streams.synchronize();
                }
            };

            let after_ks_lwe_list = d_after_ks_lwe.to_lwe_ciphertext_list(local_streams);
            let mut after_ks_lwe = LweCiphertext::from_container(
                after_ks_lwe_list.into_container(),
                decompressed_ct.as_ref().d_blocks.ciphertext_modulus(),
            );

            match &sks.bootstrapping_key {
                CudaBootstrappingKey::Classic(_d_bsk) => {
                    for val in after_ks_lwe.as_mut() {
                        *val <<= shift_to_map_to_native;
                    }
                }
                CudaBootstrappingKey::MultiBit(_d_multibit_bsk) => {
                    for val in mod_switched_array.iter_mut() {
                        *val <<= shift_to_map_to_native;
                    }
                }
            };

            let after_ms_lwe = after_ks_lwe;
            (after_ms_lwe, mod_switched_array)
        })
        .collect();

    let (expected_msg, decryption_delta, decryption_cleartext_modulus) = match pfail_special_case {
        CompressionSpecialPfailCase::AfterAP {
            decryption_adapted_message_modulus,
            decryption_adapted_carry_modulus,
        } => {
            let adapted_cleartext_modulus =
                decryption_adapted_message_modulus.0 * decryption_adapted_carry_modulus.0;
            let adapted_delta = (1u64 << 63) / adapted_cleartext_modulus;
            let delta_diff = encryption_delta / adapted_delta;
            let expected_msg = msg * delta_diff;

            (expected_msg, adapted_delta, adapted_cleartext_modulus)
        }
        CompressionSpecialPfailCase::DoesNotNeedSpecialCase => {
            (msg, encryption_delta, encryption_cleartext_modulus)
        }
    };

    let after_ap_result: Vec<_> = after_ap_lwe
        .into_iter()
        .zip(after_mod_arrays.into_iter())
        .map(|(lwe, ms_array)| match &sks.bootstrapping_key {
            CudaBootstrappingKey::Classic(_d_bsk) => DecryptionAndNoiseResult::new(
                &lwe,
                &small_lwe_secret_key,
                expected_msg,
                decryption_delta,
                decryption_cleartext_modulus,
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                let output_ks_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
                DecryptionAndNoiseResult::new_multi_bit(
                    &lwe,
                    &small_lwe_secret_key,
                    expected_msg,
                    decryption_delta,
                    decryption_cleartext_modulus,
                    d_multibit_bsk.grouping_factor,
                    output_ks_lwe_dimension,
                    &ms_array,
                )
            }
        })
        .collect();

    (after_compression_result, after_ap_result)
}

fn pbs_compress_and_classic_ap_noise_helper_gpu(
    block_params: ShortintParameterSet,
    compression_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CudaCompressionKey,
    single_decompression_key: &CudaDecompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
    streams: &CudaStreams,
) -> (Vec<NoiseSample>, Vec<NoiseSample>) {
    let (decryption_and_noise_result_after_compression, decryption_and_noise_result_after_ap) =
        pbs_compress_and_classic_ap_inner_helper_gpu(
            block_params,
            compression_params,
            single_cks,
            single_sks,
            single_compression_private_key,
            single_compression_key,
            single_decompression_key,
            msg,
            scalar_for_multiplication,
            CompressionSpecialPfailCase::DoesNotNeedSpecialCase,
            streams,
        );

    (
        decryption_and_noise_result_after_compression
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            })
            .collect(),
        decryption_and_noise_result_after_ap
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            })
            .collect(),
    )
}

fn pbs_compress_and_classic_ap_pfail_helper_gpu(
    block_params: ShortintParameterSet,
    compression_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CudaCompressionKey,
    single_decompression_key: &CudaDecompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
    pfail_special_case: CompressionSpecialPfailCase,
    streams: &CudaStreams,
) -> (Vec<f64>, Vec<f64>) {
    let (decryption_and_noise_result_after_compression, decryption_and_noise_result_after_ap) =
        pbs_compress_and_classic_ap_inner_helper_gpu(
            block_params,
            compression_params,
            single_cks,
            single_sks,
            single_compression_private_key,
            single_compression_key,
            single_decompression_key,
            msg,
            scalar_for_multiplication,
            pfail_special_case,
            streams,
        );

    (
        decryption_and_noise_result_after_compression
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
                DecryptionAndNoiseResult::DecryptionFailed => 1.0,
            })
            .collect(),
        decryption_and_noise_result_after_ap
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
                DecryptionAndNoiseResult::DecryptionFailed => 1.0,
            })
            .collect(),
    )
}

fn noise_check_shortint_pbs_compression_ap_noise_gpu<P>(
    block_params_int: P,
    compression_params: CompressionParameters,
) where
    P: Into<PBSParameters>,
{
    let block_params = block_params_int.into();

    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let modulus_as_f64 = if block_params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        block_params.ciphertext_modulus().get_custom_modulus() as f64
    };
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    // Generate the client key and the server key:
    let (radix_cks, sks) = gen_keys_radix_gpu(block_params, num_blocks, &streams);
    let cks = radix_cks.as_ref();
    let small_lwe_secret_key = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ap_ck) => todo!(),
    };
    let compression_private_key = cks.new_compression_private_key(compression_params);
    let (cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&compression_private_key, &streams);

    let compute_ks_input_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

    let (
        compute_pbs_input_lwe_dimension,
        compute_pbs_output_glwe_dimension,
        compute_pbs_output_polynomial_size,
        compute_pbs_decomp_base_log,
        compute_pbs_decomp_level_count,
    ) = match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(d_bsk) => (
            d_bsk.input_lwe_dimension(),
            d_bsk.glwe_dimension(),
            d_bsk.polynomial_size(),
            d_bsk.decomp_base_log(),
            d_bsk.decomp_level_count(),
        ),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => (
            d_multibit_bsk.input_lwe_dimension(),
            d_multibit_bsk.glwe_dimension(),
            d_multibit_bsk.polynomial_size(),
            d_multibit_bsk.decomp_base_log(),
            d_multibit_bsk.decomp_level_count(),
        ),
    };
    let scalar_for_ap_multiplication = block_params.max_noise_level().get();

    let ap_br_input_modulus_log = block_params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let ap_br_input_modulus = 1u64 << ap_br_input_modulus_log.0;

    let expected_variance_after_compute_pbs = match block_params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => match &sks.bootstrapping_key {
            CudaBootstrappingKey::Classic(_d_bsk) => pbs_variance_132_bits_security_gaussian(
                compute_pbs_input_lwe_dimension,
                compute_pbs_output_glwe_dimension,
                compute_pbs_output_polynomial_size,
                compute_pbs_decomp_base_log,
                compute_pbs_decomp_level_count,
                modulus_as_f64,
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                multi_bit_pbs_variance_132_bits_security_gaussian(
                    compute_pbs_input_lwe_dimension,
                    compute_pbs_output_glwe_dimension,
                    compute_pbs_output_polynomial_size,
                    compute_pbs_decomp_base_log,
                    compute_pbs_decomp_level_count,
                    modulus_as_f64,
                    d_multibit_bsk.grouping_factor.0 as u32,
                )
            }
        },
        DynamicDistribution::TUniform(_) => match &sks.bootstrapping_key {
            CudaBootstrappingKey::Classic(_d_bsk) => pbs_variance_132_bits_security_tuniform(
                compute_pbs_input_lwe_dimension,
                compute_pbs_output_glwe_dimension,
                compute_pbs_output_polynomial_size,
                compute_pbs_decomp_base_log,
                compute_pbs_decomp_level_count,
                modulus_as_f64,
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                multi_bit_pbs_variance_132_bits_security_tuniform(
                    compute_pbs_input_lwe_dimension,
                    compute_pbs_output_glwe_dimension,
                    compute_pbs_output_polynomial_size,
                    compute_pbs_decomp_base_log,
                    compute_pbs_decomp_level_count,
                    modulus_as_f64,
                    d_multibit_bsk.grouping_factor.0 as u32,
                )
            }
        },
    };
    let multiplication_factor_before_packing_ks = block_params.message_modulus().0;

    let expected_variance_after_msg_shif_to_msb = scalar_multiplication_variance(
        expected_variance_after_compute_pbs,
        multiplication_factor_before_packing_ks,
    );

    let pksk_input_lwe_dimension = cuda_compression_key
        .packing_key_switching_key
        .input_key_lwe_dimension();
    let pksk_output_glwe_dimension = cuda_compression_key
        .packing_key_switching_key
        .output_glwe_size()
        .to_glwe_dimension();
    let pksk_output_polynomial_size = cuda_compression_key
        .packing_key_switching_key
        .output_polynomial_size();
    let pksk_decomp_base_log = cuda_compression_key
        .packing_key_switching_key
        .decomposition_base_log();
    let pksk_decomp_level_count = cuda_compression_key
        .packing_key_switching_key
        .decomposition_level_count();
    let pksk_output_lwe_dimension =
        pksk_output_glwe_dimension.to_equivalent_lwe_dimension(pksk_output_polynomial_size);

    let lwe_to_pack = cuda_compression_key.lwe_per_glwe.0;

    let packing_keyswitch_additive_variance =
        match compression_params.packing_ks_key_noise_distribution {
            DynamicDistribution::Gaussian(_) => {
                packing_keyswitch_additive_variance_132_bits_security_gaussian(
                    pksk_input_lwe_dimension,
                    pksk_output_glwe_dimension,
                    pksk_output_polynomial_size,
                    pksk_decomp_base_log,
                    pksk_decomp_level_count,
                    lwe_to_pack as f64,
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                packing_keyswitch_additive_variance_132_bits_security_tuniform(
                    pksk_input_lwe_dimension,
                    pksk_output_glwe_dimension,
                    pksk_output_polynomial_size,
                    pksk_decomp_base_log,
                    pksk_decomp_level_count,
                    lwe_to_pack as f64,
                    modulus_as_f64,
                )
            }
        };

    let expected_variance_after_pks =
        Variance(expected_variance_after_msg_shif_to_msb.0 + packing_keyswitch_additive_variance.0);

    let compression_storage_modulus = 1u64 << cuda_compression_key.storage_log_modulus.0;
    let compression_storage_modulus_as_f64 = compression_storage_modulus as f64;

    let storage_modulus_switch_additive_variance = modulus_switch_additive_variance(
        pksk_output_lwe_dimension,
        modulus_as_f64,
        compression_storage_modulus_as_f64,
    );

    let expected_variance_after_storage_modulus_switch =
        Variance(expected_variance_after_pks.0 + storage_modulus_switch_additive_variance.0);

    let (
        decompression_br_input_lwe_dimension,
        decompression_br_output_glwe_dimension,
        decompression_br_output_polynomial_size,
        decompression_br_base_log,
        decompression_br_level_count,
    ) = match &cuda_decompression_key.blind_rotate_key {
        CudaBootstrappingKey::Classic(d_brk) => (
            d_brk.input_lwe_dimension(),
            d_brk.glwe_dimension(),
            d_brk.polynomial_size(),
            d_brk.decomp_base_log(),
            d_brk.decomp_level_count(),
        ),
        CudaBootstrappingKey::MultiBit(d_multibit_brk) => (
            d_multibit_brk.input_lwe_dimension(),
            d_multibit_brk.glwe_dimension(),
            d_multibit_brk.polynomial_size(),
            d_multibit_brk.decomp_base_log(),
            d_multibit_brk.decomp_level_count(),
        ),
    };

    // Starting decompression, we RESET the noise with a PBS
    // We return under the key of the compute AP so check the associated GLWE noise distribution
    let expected_variance_after_decompression = match block_params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => pbs_variance_132_bits_security_gaussian(
            decompression_br_input_lwe_dimension,
            decompression_br_output_glwe_dimension,
            decompression_br_output_polynomial_size,
            decompression_br_base_log,
            decompression_br_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_variance_132_bits_security_tuniform(
            decompression_br_input_lwe_dimension,
            decompression_br_output_glwe_dimension,
            decompression_br_output_polynomial_size,
            decompression_br_base_log,
            decompression_br_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_ap_max_mul = scalar_multiplication_variance(
        expected_variance_after_decompression,
        scalar_for_ap_multiplication,
    );

    // Now keyswitch
    let ap_ks_additive_variance = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_ap_ks =
        Variance(expected_variance_after_ap_max_mul.0 + ap_ks_additive_variance.0);

    let ap_ms_additive_variance: Variance = match &sks.bootstrapping_key {
        CudaBootstrappingKey::Classic(_d_bsk) => modulus_switch_additive_variance(
            compute_ks_output_lwe_dimension,
            modulus_as_f64,
            ap_br_input_modulus as f64,
        ),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            modulus_switch_multi_bit_additive_variance(
                compute_ks_output_lwe_dimension,
                modulus_as_f64,
                ap_br_input_modulus as f64,
                d_multibit_bsk.grouping_factor.0 as f64,
            )
        }
    };
    let expected_variance_after_ap_ms =
        Variance(expected_variance_after_ap_ks.0 + ap_ms_additive_variance.0);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples_after_compression = vec![];
    let mut noise_samples_after_ap = vec![];
    let number_of_runs = 1000usize.div_ceil(cuda_compression_key.lwe_per_glwe.0);

    for msg in 0..cleartext_modulus {
        let (current_noise_samples_after_compression, current_noise_samples_after_ap): (
            Vec<_>,
            Vec<_>,
        ) = (0..number_of_runs)
            .into_iter()
            .map(|_| {
                let my_stream = CudaStreams::new_single_gpu(GpuIndex::new(0));
                pbs_compress_and_classic_ap_noise_helper_gpu(
                    block_params.into(),
                    compression_params,
                    cks.as_ref(),
                    &sks,
                    &compression_private_key.key,
                    &cuda_compression_key,
                    &cuda_decompression_key,
                    msg,
                    scalar_for_ap_multiplication,
                    &my_stream,
                )
            })
            .unzip();
        noise_samples_after_compression.extend(
            current_noise_samples_after_compression
                .into_iter()
                .flatten()
                .map(|x| x.value),
        );
        noise_samples_after_ap.extend(
            current_noise_samples_after_ap
                .into_iter()
                .flatten()
                .map(|x| x.value),
        );
    }

    let after_compression_is_ok = mean_and_variance_check(
        &noise_samples_after_compression,
        "after_compression",
        0.0,
        expected_variance_after_storage_modulus_switch,
        compression_params.packing_ks_key_noise_distribution,
        compression_private_key
            .key
            .post_packing_ks_key
            .as_lwe_secret_key()
            .lwe_dimension(),
        modulus_as_f64,
    );
    let lwe_dimension = small_lwe_secret_key.lwe_dimension();
    let after_ap_is_ok = mean_and_variance_check(
        &noise_samples_after_ap,
        "after_ap",
        0.0,
        expected_variance_after_ap_ms,
        block_params.lwe_noise_distribution(),
        lwe_dimension, //small_lwe_secret_key().lwe_dimension(),
        modulus_as_f64,
    );

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);

    assert!(after_compression_is_ok && after_ap_is_ok);
}

#[test]
fn test_noise_check_shortint_classic_pbs_compression_ap_noise_tuniform_gpu() {
    noise_check_shortint_pbs_compression_ap_noise_gpu(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_multi_bit_pbs_compression_ap_noise_tuniform_gpu() {
    noise_check_shortint_pbs_compression_ap_noise_gpu(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_shortint_pbs_compression_ap_pfail_gpu<P>(
    parameters_set: P,
    compression_params: CompressionParameters,
) where
    P: Into<PBSParameters>,
{
    let block_params = parameters_set.into();
    assert_eq!(
        block_params.carry_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * block_params.carry_modulus().0 * block_params.message_modulus().0).ilog2();

    // We are going to check if the decryption works well under adapted moduli that will tweak the
    // pfail.
    let decryption_adapted_message_modulus = block_params.message_modulus();
    let decryption_adapted_carry_modulus = CarryModulus(1 << 4);

    let new_precision_with_padding =
        (2 * decryption_adapted_message_modulus.0 * decryption_adapted_carry_modulus.0).ilog2();

    let original_pfail = 2.0f64.powf(block_params.log2_p_fail());

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", block_params.log2_p_fail());

    let expected_pfail_after_ap = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    let expected_pfail_after_ap_log2 = expected_pfail_after_ap.log2();

    println!("expected_pfail_after_ap={expected_pfail_after_ap}");
    println!("expected_pfail_after_ap_log2={expected_pfail_after_ap_log2}");

    let samples_per_run = compression_params.lwe_per_glwe.0;

    let (expected_fails_after_ap, runs_for_expected_fails, total_sample_count) =
        if should_run_long_pfail_tests() {
            let target_sample_count = 1_000_000_usize;
            let runs_count = target_sample_count.div_ceil(samples_per_run);
            let actual_sample_count = runs_count * samples_per_run;
            let expected_fails_after_ap =
                (expected_pfail_after_ap * actual_sample_count as f64).round() as u32;
            (expected_fails_after_ap, runs_count, actual_sample_count)
        } else {
            let expected_fails_after_ap = 200;

            let runs_for_expected_fails = (expected_fails_after_ap as f64
                / (expected_pfail_after_ap * samples_per_run as f64))
                .round() as usize;

            let total_sample_count = runs_for_expected_fails * samples_per_run;
            (
                expected_fails_after_ap,
                runs_for_expected_fails,
                total_sample_count,
            )
        };

    println!("runs_for_expected_fails={runs_for_expected_fails}");
    println!("total_sample_count={total_sample_count}");

    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let scalar_for_multiplication = block_params.max_noise_level().get();

    let encryption_cleartext_modulus =
        block_params.message_modulus().0 * block_params.carry_modulus().0;
    // We multiply by the message_modulus during compression, so the top bits corresponding to the
    // modulus won't be usable during compression
    let compression_cleartext_modulus =
        encryption_cleartext_modulus / block_params.message_modulus().0;

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;

    // Generate the client key and the server key:
    let (radix_cks, sks) = gen_keys_radix_gpu(block_params, num_blocks, &streams);
    let cks = radix_cks.as_ref();
    let compression_private_key = cks.new_compression_private_key(compression_params);
    let (cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&compression_private_key, &streams);

    let (_measured_fails_after_compression, measured_fails_after_ap): (Vec<_>, Vec<_>) = (0
        ..runs_for_expected_fails)
        .into_iter()
        .map(|_index| {
            let msg: u64 = rand::random::<u64>() % compression_cleartext_modulus;
            pbs_compress_and_classic_ap_pfail_helper_gpu(
                block_params,
                compression_params,
                cks.as_ref(),
                &sks,
                &compression_private_key.key,
                &cuda_compression_key,
                &cuda_decompression_key,
                msg,
                scalar_for_multiplication,
                CompressionSpecialPfailCase::AfterAP {
                    decryption_adapted_message_modulus,
                    decryption_adapted_carry_modulus,
                },
                &streams,
            )
        })
        .unzip();

    //let sample_count = measured_fails_after_ap.len();
    let measured_fails_after_ap: f64 = measured_fails_after_ap.into_iter().flatten().sum();
    let measured_pfail_after_ap = measured_fails_after_ap / (total_sample_count as f64);

    println!("measured_fails_after_ap={measured_fails_after_ap}");
    println!("measured_pfail_after_ap={measured_pfail_after_ap}");
    println!("expected_fails_after_ap={expected_fails_after_ap}");
    println!("expected_pfail_after_ap={expected_pfail_after_ap}");

    let equivalent_measured_pfail_after_ap = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail_after_ap,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail_after_ap={equivalent_measured_pfail_after_ap}");
    println!("original_expected_pfail_after_ap  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_after_ap_log2={}",
        equivalent_measured_pfail_after_ap.log2()
    );
    println!(
        "original_expected_pfail_after_ap_log2  ={}",
        original_pfail.log2()
    );

    if measured_fails_after_ap > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            total_sample_count as f64,
            measured_fails_after_ap,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_lower_bound,
            original_precision_with_padding,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_upper_bound,
            original_precision_with_padding,
        );

        println!("equivalent_pfail_lower_bound={equivalent_pfail_lower_bound}");
        println!("equivalent_pfail_upper_bound={equivalent_pfail_upper_bound}");
        println!(
            "equivalent_pfail_lower_bound_log2={}",
            equivalent_pfail_lower_bound.log2()
        );
        println!(
            "equivalent_pfail_upper_bound_log2={}",
            equivalent_pfail_upper_bound.log2()
        );

        if measured_pfail_after_ap <= expected_pfail_after_ap {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail_after_ap) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail_after_ap));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters.\n\
            ==========\n"
        );
    }
}

#[test]
fn test_noise_check_shortint_classic_pbs_compression_ap_after_ap_pfail_tuniform_gpu() {
    noise_check_shortint_pbs_compression_ap_pfail_gpu(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
#[test]
fn test_noise_check_shortint_multi_bit_pbs_compression_ap_after_ap_pfail_tuniform_gpu() {
    noise_check_shortint_pbs_compression_ap_pfail_gpu(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_shortint_pbs_compression_ap_after_ms_storage_pfail_gpu<P>(
    parameters_set: P,
    compression_params: CompressionParameters,
) where
    P: Into<PBSParameters>,
{
    let mut block_params = parameters_set.into();

    assert_eq!(
        block_params.carry_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );

    let block_params_log2_pfail = block_params.log2_p_fail();

    let original_message_modulus = block_params.message_modulus();
    let original_carry_modulus = block_params.carry_modulus();

    let encryption_cleartext_modulus = original_message_modulus.0 * original_carry_modulus.0;
    // We multiply by message modulus before compression
    let original_compression_cleartext_modulus =
        encryption_cleartext_modulus / original_message_modulus.0;

    // We are going to simulate 6 bits to measure the pfail of compression
    // To avoid a multiplication we set the message modulus to 1 and put everything in the carry
    // modulus

    block_params.set_message_modulus(MessageModulus(1));
    block_params.set_carry_modulus(CarryModulus(1 << 6));

    let block_params = block_params;

    let modified_encryption_modulus =
        block_params.message_modulus().0 * block_params.carry_modulus().0;

    let samples_per_run = compression_params.lwe_per_glwe.0;

    let (run_count, total_sample_count) = if should_run_long_pfail_tests() {
        let target_sample_count = 1_000_000_usize;
        let run_count = target_sample_count.div_ceil(samples_per_run);
        let actual_sample_count = run_count * samples_per_run;
        (run_count, actual_sample_count)
    } else {
        let run_count = 500;
        let total_sample_count = run_count * samples_per_run;
        (run_count, total_sample_count)
    };

    println!("run_count={run_count}");
    println!("total_sample_count={total_sample_count}");

    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let scalar_for_multiplication = block_params.max_noise_level().get();

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    // Generate the client key and the server key:
    let (radix_cks, sks) = gen_keys_radix_gpu(block_params, num_blocks, &streams);
    let cks = radix_cks.as_ref();
    let compression_private_key = cks.new_compression_private_key(compression_params);
    let (cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&compression_private_key, &streams);

    let (measured_fails_after_ms_storage, _measured_fails_after_ap): (Vec<_>, Vec<_>) = (0
        ..run_count)
        .into_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % modified_encryption_modulus;
            pbs_compress_and_classic_ap_pfail_helper_gpu(
                block_params,
                compression_params,
                cks.as_ref(),
                &sks,
                &compression_private_key.key,
                &cuda_compression_key,
                &cuda_decompression_key,
                msg,
                scalar_for_multiplication,
                CompressionSpecialPfailCase::DoesNotNeedSpecialCase,
                &streams,
            )
        })
        .unzip();

    let measured_fails_after_ms_storage: f64 =
        measured_fails_after_ms_storage.into_iter().flatten().sum();
    let measured_pfail_after_ms_storage =
        measured_fails_after_ms_storage / (total_sample_count as f64);

    let measured_pfail_after_ms_storage_log2 = measured_pfail_after_ms_storage.log2();

    println!("measured_fails_after_ms_storage={measured_fails_after_ms_storage}");
    println!("measured_pfail_after_ms_storage={measured_pfail_after_ms_storage}");
    println!("measured_pfail_after_ms_storage_log2={measured_pfail_after_ms_storage_log2}");

    let precision_used_during_compression =
        1 + (block_params.message_modulus().0 * block_params.carry_modulus().0).ilog2();

    // We want to estimate the pfail under the original modulus with the one under the modified
    // precision_used_during_compression
    let equivalent_pfail_ms_storage = equivalent_pfail_gaussian_noise(
        precision_used_during_compression,
        measured_pfail_after_ms_storage,
        1 + original_compression_cleartext_modulus.ilog2(),
    );

    let equivalent_pfail_ms_storage_log2 = equivalent_pfail_ms_storage.log2();

    println!("equivalent_pfail_ms_storage={equivalent_pfail_ms_storage}");
    println!("equivalent_pfail_ms_storage_log2={equivalent_pfail_ms_storage_log2}");

    let original_pfail = 2.0f64.powf(block_params_log2_pfail);

    println!("original_expected_pfail_after_ms_storage={original_pfail}");
    println!(
        "original_expected_pfail_after_after_ms_storage={}",
        original_pfail.log2()
    );

    assert!(equivalent_pfail_ms_storage <= 2.0f64.powi(-64));

    // if measured_fails_after_ms_storage > 0.0 {
    //     let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
    //         total_sample_count as f64,
    //         measured_fails_after_ms_storage,
    //         0.99,
    //     );

    //     println!(
    //         "pfail_lower_bound={}",
    //         pfail_confidence_interval.lower_bound()
    //     );
    //     println!(
    //         "pfail_upper_bound={}",
    //         pfail_confidence_interval.upper_bound()
    //     );

    //     if measured_pfail_after_ms_storage <= expected_pfail_after_ms_storage {
    //         if !pfail_confidence_interval.mean_is_in_interval(expected_pfail_after_ms_storage) {
    //             println!(
    //                 "\n==========\n\
    //                 WARNING: measured pfail is smaller than expected pfail \
    //                 and out of the confidence interval\n\
    //                 the optimizer might be pessimistic when generating parameters.\n\
    //                 ==========\n"
    //             );
    //         }
    //     } else {
    //         assert!(pfail_confidence_interval.
    // mean_is_in_interval(expected_pfail_after_ms_storage));     }
    // } else {
    //     println!(
    //         "\n==========\n\
    //         WARNING: measured pfail is 0, it is either a bug or \
    //         it is way smaller than the expected pfail\n\
    //         the optimizer might be pessimistic when generating parameters.\n\
    //         ==========\n"
    //     );
    // }
}

#[test]
fn test_noise_check_shortint_classic_pbs_compression_ap_after_ms_storage_pfail_tuniform_gpu() {
    noise_check_shortint_pbs_compression_ap_after_ms_storage_pfail_gpu(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
#[test]
fn test_noise_check_shortint_multi_bit_pbs_compression_ap_after_ms_storage_pfail_tuniform_gpu() {
    noise_check_shortint_pbs_compression_ap_after_ms_storage_pfail_gpu(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn br_to_squash_pbs_128_inner_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: NoiseSquashingParameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &CudaBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    single_pbs_128_key: &CudaLweBootstrapKey,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
    scalar_for_multiplication: u8,
    streams: &CudaStreams,
) -> (
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    assert!(pbs128_params
        .modulus_switch_noise_reduction_params
        .is_some());
    assert!(block_params.pbs_only());
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );
    let num_ct_blocks = 1;
    let mut engine = ShortintEngine::new();
    let thread_compression_private_key;
    let thread_radix_cks;
    let thread_cks;
    let thread_sks;
    let thread_encryption_key;
    let thread_input_br_key;
    let thread_pbs_128_key;
    let thread_output_pbs_128_glwe_secret_key;
    let thread_cuda_decompression_key;
    let thread_compression_private_key_key;
    let thread_small_lwe_secret_key;
    let num_blocks = 1;

    let (cks, sks, encryption_key, input_br_key, pbs_128_key, output_pbs_128_glwe_secret_key) =
        if should_use_one_key_per_sample() {
            (thread_radix_cks, thread_sks) = gen_keys_radix_gpu(block_params, num_blocks, streams);
            thread_cks = thread_radix_cks.as_ref();
            thread_small_lwe_secret_key = match &thread_cks.key.atomic_pattern {
                AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
                AtomicPatternClientKey::KeySwitch32(_ks_ck) => {
                    todo!()
                }
            };

            thread_pbs_128_key = {
                let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
                    thread_small_lwe_secret_key
                        .as_ref()
                        .iter()
                        .copied()
                        .map(|x| x as u128)
                        .collect::<Vec<_>>(),
                );

                let mut engine = ShortintEngine::new();

                thread_output_pbs_128_glwe_secret_key =
                    allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
                        pbs128_params.glwe_dimension,
                        pbs128_params.polynomial_size,
                        &mut engine.secret_generator,
                    );

                let std_bootstrapping_key =
                    par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _, _>(
                        &input_lwe_secret_key_as_u128,
                        &thread_output_pbs_128_glwe_secret_key,
                        pbs128_params.decomp_base_log,
                        pbs128_params.decomp_level_count,
                        pbs128_params.glwe_noise_distribution,
                        pbs128_params.ciphertext_modulus,
                        &mut engine.encryption_generator,
                    );
                let modulus_switch_noise_reduction_key = pbs128_params
                    .modulus_switch_noise_reduction_params
                    .map(|modulus_switch_noise_reduction_params| {
                        ModulusSwitchNoiseReductionKey::new(
                            modulus_switch_noise_reduction_params,
                            &thread_small_lwe_secret_key,
                            &mut engine,
                            block_params.ciphertext_modulus(),
                            block_params.lwe_noise_distribution(),
                        )
                    });
                let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(
                    &std_bootstrapping_key,
                    modulus_switch_noise_reduction_key.as_ref(),
                    streams,
                );
                d_bsk
            };

            (thread_encryption_key, thread_input_br_key) = match input_br_params {
                PBS128InputBRParams::Decompression { params } => {
                    thread_compression_private_key = thread_cks.new_compression_private_key(params);
                    (_, thread_cuda_decompression_key) = thread_radix_cks
                        .new_cuda_compression_decompression_keys(
                            &thread_compression_private_key,
                            streams,
                        );
                    thread_compression_private_key_key = thread_compression_private_key
                        .key
                        .post_packing_ks_key
                        .as_lwe_secret_key();

                    (
                        &thread_compression_private_key_key,
                        &thread_cuda_decompression_key.blind_rotate_key,
                    )
                }
                PBS128InputBRParams::Compute => {
                    (&thread_small_lwe_secret_key, &thread_sks.bootstrapping_key)
                }
            };
            (
                &thread_cks.key,
                &thread_sks,
                thread_encryption_key,
                thread_input_br_key,
                &thread_pbs_128_key,
                &thread_output_pbs_128_glwe_secret_key.as_view(),
            )
        } else {
            // If we don't want to use per thread keys (to go faster), we use those single keys for
            // all threads
            (
                single_cks,
                single_sks,
                single_encryption_key,
                single_input_br_key,
                single_pbs_128_key,
                single_output_pbs_128_glwe_secret_key,
            )
        };

    let identity_lut = sks.generate_lookup_table(|x| x);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;

    let (polynomial_size, output_lwe_dimension, glwe_dimension, input_lwe_dimension) =
        match &input_br_key {
            CudaBootstrappingKey::Classic(d_bsk) => (
                d_bsk.polynomial_size(),
                d_bsk.output_lwe_dimension(),
                d_bsk.glwe_dimension(),
                d_bsk.input_lwe_dimension(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => (
                d_multibit_bsk.polynomial_size(),
                d_multibit_bsk.output_lwe_dimension(),
                d_multibit_bsk.glwe_dimension(),
                d_multibit_bsk.input_lwe_dimension(),
            ),
        };

    let br_input_modulus_log = polynomial_size.to_blind_rotation_input_modulus_log();
    let br_128_input_modulus_log = pbs_128_key
        .polynomial_size
        .to_blind_rotation_input_modulus_log();

    //let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;
    let shift_to_map_to_native_u64_before_pbs_128 = u64::BITS - br_128_input_modulus_log.0 as u32;

    let delta = (1u64 << 63) / cleartext_modulus;
    let delta_u128 = (1u128 << 127) / cleartext_modulus as u128;

    // We want to encrypt the ciphertext under modulus 2N but then use the native
    // modulus to simulate a noiseless mod switch as input
    let d_input_pbs_lwe_ct = {
        let ms_modulus = CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();
        let no_noise_dist = DynamicDistribution::new_gaussian(Variance(0.0));

        let ms_delta = ms_modulus.get_custom_modulus() as u64 / (2 * cleartext_modulus);

        let ms_plaintext = Plaintext(msg * ms_delta);

        let simulated_mod_switch_ct = allocate_and_encrypt_new_lwe_ciphertext(
            encryption_key,
            ms_plaintext,
            no_noise_dist,
            ms_modulus,
            &mut engine.encryption_generator,
        );

        let raw_data = simulated_mod_switch_ct.into_container();
        // Now get the noiseless mod switched encryption under the proper modulus
        // The power of 2 modulus are always encrypted in the MSBs, so this is fine
        let h_ct = LweCiphertext::from_container(raw_data, block_params.ciphertext_modulus());
        let d_ct = CudaLweCiphertextList::from_lwe_ciphertext(&h_ct, streams);
        d_ct
    };

    let mut after_pbs_shortint_ct: CudaUnsignedRadixCiphertext =
        sks.create_trivial_zero_radix(num_ct_blocks, streams);

    // Need to generate the required indexes for the PBS
    let mut lut_vector_indexes: Vec<u64> = vec![u64::ZERO; num_ct_blocks];
    for (i, ind) in lut_vector_indexes.iter_mut().enumerate() {
        *ind = <usize as CastInto<u64>>::cast_into(i);
    }
    let mut d_lut_vector_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    unsafe { d_lut_vector_indexes.copy_from_cpu_async(&lut_vector_indexes, streams, 0) };
    let lwe_indexes_usize: Vec<usize> = (0..num_ct_blocks).collect_vec();
    let lwe_indexes = lwe_indexes_usize
        .iter()
        .map(|&x| <usize as CastInto<u64>>::cast_into(x))
        .collect_vec();
    let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
    unsafe {
        d_input_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
        d_output_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
    }

    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&identity_lut.acc, streams);

    match &input_br_key {
        CudaBootstrappingKey::Classic(d_bsk) => {
            // Apply the PBS only and no modulus switch noise reduction as we have a noiseless input
            // ciphertext
            cuda_programmable_bootstrap_lwe_ciphertext_no_ms_noise_reduction(
                &d_input_pbs_lwe_ct,
                &mut after_pbs_shortint_ct.as_mut().d_blocks,
                &d_accumulator,
                &d_lut_vector_indexes,
                &d_output_indexes,
                &d_input_indexes,
                LweCiphertextCount(num_ct_blocks),
                d_bsk,
                streams,
            );
        }
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                &d_input_pbs_lwe_ct,
                &mut after_pbs_shortint_ct.as_mut().d_blocks,
                &d_accumulator,
                &d_lut_vector_indexes,
                &d_output_indexes,
                &d_input_indexes,
                d_multibit_bsk,
                streams,
            );
        }
    }
    after_pbs_shortint_ct.ciphertext.info.blocks[0]
        .set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

    // Remove the plaintext before the mul to avoid degree issues but sill increase the
    // noise
    let native_mod_plaintext = Plaintext(msg * delta);
    let scalar_vector = vec![native_mod_plaintext.0; num_ct_blocks];
    let mut d_decomposed_scalar = CudaVec::<u64>::new(num_ct_blocks, streams, 0);
    unsafe {
        d_decomposed_scalar.copy_from_cpu_async(scalar_vector.as_slice(), streams, 0);
    }

    cuda_lwe_ciphertext_plaintext_sub_assign(
        &mut after_pbs_shortint_ct.as_mut().d_blocks,
        &d_decomposed_scalar,
        streams,
    );

    let scalar_u64 = scalar_for_multiplication as u64;

    unsafe {
        unchecked_small_scalar_mul_integer_async(
            streams,
            &mut after_pbs_shortint_ct.ciphertext,
            scalar_u64,
        );
    }
    streams.synchronize();

    // Put the message back in after mul to have our msg in a noisy ct
    let big_lwe_dim = polynomial_size.0 * glwe_dimension.0;
    let tmp = after_pbs_shortint_ct.duplicate(streams);
    let encoded_msg = sks.encoding().encode(Cleartext(msg));
    unsafe {
        add_lwe_ciphertext_vector_plaintext_scalar_async(
            streams,
            &mut after_pbs_shortint_ct.as_mut().d_blocks.0.d_vec,
            &tmp.as_ref().d_blocks.0.d_vec,
            encoded_msg.0,
            LweDimension(big_lwe_dim),
            num_ct_blocks as u32,
        );
    }
    streams.synchronize();

    let after_ks_lwe_aux = LweCiphertext::new(
        0u64,
        sks.key_switching_key.output_key_lwe_size(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    let mut d_after_ks_lwe = CudaLweCiphertextList::from_lwe_ciphertext(&after_ks_lwe_aux, streams);

    //Indexes needed for the keyswitch
    let h_indexes = [u64::ZERO];
    let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(1, streams, 0) };
    let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(1, streams, 0) };
    unsafe {
        d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), streams, 0);
        d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), streams, 0);
    }
    streams.synchronize();

    cuda_keyswitch_lwe_ciphertext(
        &sks.key_switching_key,
        &after_pbs_shortint_ct.as_mut().d_blocks,
        &mut d_after_ks_lwe,
        &d_input_indexes,
        &d_output_indexes,
        streams,
    );

    let after_ks_lwe_list = d_after_ks_lwe.to_lwe_ciphertext_list(streams);
    let after_ks_lwe = LweCiphertext::from_container(
        after_ks_lwe_list.into_container(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    let mut d_before_ms = CudaLweCiphertextList::from_lwe_ciphertext(&after_ks_lwe, streams);
    let ct_modulus = d_after_ks_lwe.ciphertext_modulus().raw_modulus_float();

    cuda_improve_noise_modulus_switch_ciphertext(
        &mut d_before_ms.0.d_vec,
        &d_after_ks_lwe.0.d_vec,
        &d_input_indexes,
        input_lwe_dimension,
        num_ct_blocks as u32,
        br_128_input_modulus_log.0 as u32,
        ct_modulus,
        pbs_128_key.d_ms_noise_reduction_key.as_ref().unwrap(),
        streams,
    );

    let before_ms_lwe_list = d_before_ms.to_lwe_ciphertext_list(streams);
    let before_ms_lwe = LweCiphertext::from_container(
        before_ms_lwe_list.into_container(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    cuda_modulus_switch_ciphertext(&mut d_before_ms, br_128_input_modulus_log.0 as u32, streams);

    let after_ms_lwe_list = d_before_ms.to_lwe_ciphertext_list(streams);
    let mut after_ms_lwe = LweCiphertext::from_container(
        after_ms_lwe_list.into_container(),
        sks.key_switching_key.ciphertext_modulus(),
    );
    for val in after_ms_lwe.as_mut() {
        *val <<= shift_to_map_to_native_u64_before_pbs_128;
    }

    let d_input_pbs_128 = CudaLweCiphertextList::from_lwe_ciphertext(&after_ks_lwe, streams);

    let output_pbs_128 = LweCiphertext::new(
        0u128,
        pbs_128_key.output_lwe_dimension().to_lwe_size(),
        pbs128_params.ciphertext_modulus,
    );
    let mut d_output_pbs_128 = CudaLweCiphertextList::from_lwe_ciphertext(&output_pbs_128, streams);

    let acc = generate_programmable_bootstrap_glwe_lut(
        pbs_128_key.polynomial_size(),
        pbs_128_key.glwe_dimension().to_glwe_size(),
        cleartext_modulus as usize,
        pbs128_params.ciphertext_modulus,
        delta_u128,
        |x| x,
    );

    let d_acc = CudaGlweCiphertextList::from_glwe_ciphertext(&acc, streams);

    cuda_programmable_bootstrap_128_lwe_ciphertext(
        &d_input_pbs_128,
        &mut d_output_pbs_128,
        &d_acc,
        LweCiphertextCount(num_ct_blocks),
        &pbs_128_key,
        streams,
    );

    let after_pbs_128_list = d_output_pbs_128.to_lwe_ciphertext_list(streams);
    let after_pbs_128 = LweCiphertext::from_container(
        after_pbs_128_list.into_container(),
        pbs128_params.ciphertext_modulus,
    );

    let small_lwe_secret_key = match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ks_ck) => {
            todo!()
        }
    };
    let decryption_noise_after_ks = DecryptionAndNoiseResult::new(
        &after_ks_lwe,
        &small_lwe_secret_key,
        msg,
        delta,
        cleartext_modulus,
    );
    let decryption_noise_before_ms = DecryptionAndNoiseResult::new(
        &before_ms_lwe,
        &small_lwe_secret_key,
        msg,
        delta,
        cleartext_modulus,
    );

    let decryption_noise_after_ms = DecryptionAndNoiseResult::new(
        &after_ms_lwe,
        &small_lwe_secret_key,
        msg,
        delta,
        cleartext_modulus,
    );

    let decryption_noise_after_pbs128 = DecryptionAndNoiseResult::new(
        &after_pbs_128,
        &output_pbs_128_glwe_secret_key.as_lwe_secret_key(),
        msg as u128,
        delta_u128,
        cleartext_modulus as u128,
    );

    (
        decryption_noise_after_ks,
        decryption_noise_before_ms,
        decryption_noise_after_ms,
        decryption_noise_after_pbs128,
    )
}

fn br_to_squash_pbs_128_noise_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: NoiseSquashingParameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &CudaBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    single_pbs_128_key: &CudaLweBootstrapKey,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
    scalar_for_multiplication: u8,
    streams: &CudaStreams,
) -> ((NoiseSample, NoiseSample), (NoiseSample, NoiseSample)) {
    //let (decryption_and_noise_result_before_pbs_128, decryption_and_noise_result_after_pbs_128) =
    let (
        decryption_and_noise_result_before_drift_mitigation,
        decryption_and_noise_result_before_ms_of_pbs_128,
        decryption_and_noise_result_before_pbs_128,
        decryption_and_noise_result_after_pbs_128,
    ) = br_to_squash_pbs_128_inner_helper(
        input_br_params,
        block_params,
        pbs128_params,
        single_encryption_key,
        single_input_br_key,
        single_cks,
        single_sks,
        single_pbs_128_key,
        single_output_pbs_128_glwe_secret_key,
        msg,
        scalar_for_multiplication,
        streams,
    );

    (
        (
            match decryption_and_noise_result_before_drift_mitigation {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
            match decryption_and_noise_result_before_ms_of_pbs_128 {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
        ),
        (
            match decryption_and_noise_result_before_pbs_128 {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
            match decryption_and_noise_result_after_pbs_128 {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
        ),
    )
}

fn br_to_squash_pbs_128_pfail_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: NoiseSquashingParameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &CudaBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &CudaServerKey,
    single_pbs_128_key: &CudaLweBootstrapKey,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
    scalar_for_multiplication: u8,
    streams: &CudaStreams,
) -> (f64, f64) {
    let (
        _decryption_and_noise_result_before_drift_mitigation,
        _decryption_and_noise_result_before_ms_of_pbs_128,
        decryption_and_noise_result_before_pbs_128,
        decryption_and_noise_result_after_pbs_128,
    ) = br_to_squash_pbs_128_inner_helper(
        input_br_params,
        block_params,
        pbs128_params,
        single_encryption_key,
        single_input_br_key,
        single_cks,
        single_sks,
        single_pbs_128_key,
        single_output_pbs_128_glwe_secret_key,
        msg,
        scalar_for_multiplication,
        streams,
    );

    (
        match decryption_and_noise_result_before_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
            DecryptionAndNoiseResult::DecryptionFailed => 1.0,
        },
        match decryption_and_noise_result_after_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
            DecryptionAndNoiseResult::DecryptionFailed => 1.0,
        },
    )
}

fn noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise<P>(
    input_br_params: PBS128InputBRParams,
    parameter_set: P,
    pbs128_params: NoiseSquashingParameters,
) where
    P: Into<PBSParameters>,
{
    let block_params = parameter_set.into();
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let compute_modulus_as_f64 = if block_params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        block_params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let pbs128_output_modulus_as_f64 = if pbs128_params.ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(128)
    } else {
        pbs128_params.ciphertext_modulus.get_custom_modulus() as f64
    };

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    // Generate the client key and the server key:
    let (radix_cks, sks) = gen_keys_radix_gpu(block_params, num_blocks, &streams);
    let cks = radix_cks.as_ref();

    let output_pbs_128_glwe_secret_key;
    let small_lwe_secret_key = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ks_ck) => {
            todo!()
        }
    };
    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            small_lwe_secret_key
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        let mut engine = ShortintEngine::new();

        output_pbs_128_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
            pbs128_params.glwe_dimension,
            pbs128_params.polynomial_size,
            &mut engine.secret_generator,
        );

        let std_bootstrapping_key =
            par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _, _>(
                &input_lwe_secret_key_as_u128,
                &output_pbs_128_glwe_secret_key,
                pbs128_params.decomp_base_log,
                pbs128_params.decomp_level_count,
                pbs128_params.glwe_noise_distribution,
                pbs128_params.ciphertext_modulus,
                &mut engine.encryption_generator,
            );
        let modulus_switch_noise_reduction_key = pbs128_params
            .modulus_switch_noise_reduction_params
            .map(|modulus_switch_noise_reduction_params| {
                ModulusSwitchNoiseReductionKey::new(
                    modulus_switch_noise_reduction_params,
                    &small_lwe_secret_key,
                    &mut engine,
                    block_params.ciphertext_modulus(),
                    block_params.lwe_noise_distribution(),
                )
            });
        let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(
            &std_bootstrapping_key,
            modulus_switch_noise_reduction_key.as_ref(),
            &streams,
        );

        d_bsk
    };

    let compression_private_key;
    let cuda_decompression_key;
    let small_lwe_secret_key = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ks_ck) => {
            todo!()
        }
    };
    let (encryption_key, input_br_key) = match input_br_params {
        PBS128InputBRParams::Decompression { params } => {
            compression_private_key = cks.new_compression_private_key(params);

            (_, cuda_decompression_key) = radix_cks
                .new_cuda_compression_decompression_keys(&compression_private_key, &streams);
            (
                &compression_private_key
                    .key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &cuda_decompression_key.blind_rotate_key,
            )
        }
        PBS128InputBRParams::Compute => (&small_lwe_secret_key, &sks.bootstrapping_key),
    };

    match &input_br_key {
        CudaBootstrappingKey::Classic(d_bsk) => assert!(d_bsk.d_ms_noise_reduction_key.is_some()),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
            assert!(true)
        }
    };
    let (input_lwe_dim, glwe_dim, pol_size, decomp_base_log, decomp_level_count) =
        match &input_br_key {
            CudaBootstrappingKey::Classic(d_bsk) => (
                d_bsk.input_lwe_dimension(),
                d_bsk.glwe_dimension(),
                d_bsk.polynomial_size(),
                d_bsk.decomp_base_log(),
                d_bsk.decomp_level_count(),
            ),
            CudaBootstrappingKey::MultiBit(d_bsk) => (
                d_bsk.input_lwe_dimension(),
                d_bsk.glwe_dimension(),
                d_bsk.polynomial_size(),
                d_bsk.decomp_base_log(),
                d_bsk.decomp_level_count(),
            ),
        };

    // We get out under the big key of the compute params, so we can check this noise distribution
    let expected_variance_after_input_br = match block_params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => match &input_br_key {
            CudaBootstrappingKey::Classic(_d_bsk) => pbs_variance_132_bits_security_gaussian(
                input_lwe_dim,
                glwe_dim,
                pol_size,
                decomp_base_log,
                decomp_level_count,
                compute_modulus_as_f64,
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                multi_bit_pbs_variance_132_bits_security_gaussian(
                    input_lwe_dim,
                    glwe_dim,
                    pol_size,
                    decomp_base_log,
                    decomp_level_count,
                    compute_modulus_as_f64,
                    d_multibit_bsk.grouping_factor.0 as u32,
                )
            }
        },
        DynamicDistribution::TUniform(_) => match &input_br_key {
            CudaBootstrappingKey::Classic(_d_bsk) => pbs_variance_132_bits_security_tuniform(
                input_lwe_dim,
                glwe_dim,
                pol_size,
                decomp_base_log,
                decomp_level_count,
                compute_modulus_as_f64,
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                multi_bit_pbs_variance_132_bits_security_tuniform(
                    input_lwe_dim,
                    glwe_dim,
                    pol_size,
                    decomp_base_log,
                    decomp_level_count,
                    compute_modulus_as_f64,
                    d_multibit_bsk.grouping_factor.0 as u32,
                )
            }
        },
    };

    let scalar_for_multiplication = block_params.max_noise_level().get();
    let expected_variance_after_multiplication =
        scalar_multiplication_variance(expected_variance_after_input_br, scalar_for_multiplication);

    let compute_ks_input_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

    let keyswitch_additive_variance = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            compute_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            compute_modulus_as_f64,
        ),
    };

    let expected_variance_after_ks =
        Variance(expected_variance_after_multiplication.0 + keyswitch_additive_variance.0);

    let br_128_input_modulus_log = pbs_128_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_128_input_modulus = 1u64 << br_128_input_modulus_log.0;

    let drift_mitigation_additive_var = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(compute_modulus_as_f64),
    };

    let expected_variance_after_drift_mitigation =
        Variance(expected_variance_after_ks.0 + drift_mitigation_additive_var.0);

    let ms_additive_variance = generalized_modulus_switch_additive_variance(
        compute_ks_output_lwe_dimension,
        compute_modulus_as_f64,
        br_128_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_after_drift_mitigation.0 + ms_additive_variance.0);

    let expected_variance_after_pbs_128 = match pbs128_params.glwe_noise_distribution {
        DynamicDistribution::Gaussian(_) => pbs_128_variance_132_bits_security_gaussian(
            pbs_128_key.input_lwe_dimension(),
            pbs_128_key.glwe_dimension(),
            pbs_128_key.polynomial_size(),
            pbs_128_key.decomp_base_log(),
            pbs_128_key.decomp_level_count(),
            104f64,
            pbs128_output_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_128_variance_132_bits_security_tuniform(
            pbs_128_key.input_lwe_dimension(),
            pbs_128_key.glwe_dimension(),
            pbs_128_key.polynomial_size(),
            pbs_128_key.decomp_base_log(),
            pbs_128_key.decomp_level_count(),
            104f64,
            pbs128_output_modulus_as_f64,
        ),
    };

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples_before_drift_mitigation = vec![];
    let mut noise_samples_before_ms_of_pbs_128 = vec![];
    let mut noise_samples_before_pbs_128 = vec![];
    let mut noise_samples_after_pbs_128 = vec![];

    let sample_count_per_msg = 1000;

    let num_streams = 16;
    let vec_local_streams = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(gpu_index)))
        .collect::<Vec<_>>();

    for msg in 0..cleartext_modulus {
        let (
            (
                current_noise_samples_before_drift_mitigation,
                current_noise_samples_before_ms_of_pbs_128,
            ),
            (current_noise_samples_before_pbs_128, current_noise_samples_after_pbs_128),
        ): ((Vec<_>, Vec<_>), (Vec<_>, Vec<_>)) = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|index| {
                let local_stream = &vec_local_streams[index % num_streams];
                let msg: u64 = rand::random::<u64>() % cleartext_modulus;
                //println!("Running iteration {index} with msg={msg} ... ");
                br_to_squash_pbs_128_noise_helper(
                    input_br_params,
                    block_params,
                    pbs128_params,
                    &encryption_key,
                    &input_br_key,
                    &cks.key,
                    &sks,
                    &pbs_128_key,
                    &output_pbs_128_glwe_secret_key.as_view(),
                    msg,
                    scalar_for_multiplication.try_into().unwrap(),
                    local_stream,
                )
            })
            .unzip();

        noise_samples_before_drift_mitigation.extend(
            current_noise_samples_before_drift_mitigation
                .into_iter()
                .map(|x| x.value),
        );

        noise_samples_before_ms_of_pbs_128.extend(
            current_noise_samples_before_ms_of_pbs_128
                .into_iter()
                .map(|x| x.value),
        );

        noise_samples_before_pbs_128.extend(
            current_noise_samples_before_pbs_128
                .into_iter()
                .map(|x| x.value),
        );

        noise_samples_after_pbs_128.extend(
            current_noise_samples_after_pbs_128
                .into_iter()
                .map(|x| x.value),
        );
    }

    println!();

    let normality_check_before_drift_mitigation = normality_test_f64(
        &noise_samples_before_drift_mitigation
            [..5000.min(noise_samples_before_drift_mitigation.len())],
        0.01,
    );

    if normality_check_before_drift_mitigation.null_hypothesis_is_valid {
        println!("Normality check before drift mitigation is OK\n");
    } else {
        println!("Normality check before drift mitigation failed\n");
    }

    let normality_check_before_ms = normality_test_f64(
        &noise_samples_before_ms_of_pbs_128[..5000.min(noise_samples_before_ms_of_pbs_128.len())],
        0.01,
    );

    if normality_check_before_ms.null_hypothesis_is_valid {
        println!("Normality check before MS is OK\n");
    } else {
        println!("Normality check before MS failed\n");
    }

    let small_lwe_secret_key = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ks_ck) => {
            todo!()
        }
    };
    let before_drift_mitigation_is_ok = mean_and_variance_check(
        &noise_samples_before_drift_mitigation,
        "before_drift_mitigation",
        0.0,
        expected_variance_after_ks,
        block_params.lwe_noise_distribution(),
        small_lwe_secret_key.lwe_dimension(),
        compute_modulus_as_f64,
    );

    let before_ms_of_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_before_ms_of_pbs_128,
        "before_ms_of_pbs_128",
        0.0,
        expected_variance_after_drift_mitigation,
        block_params.lwe_noise_distribution(),
        small_lwe_secret_key.lwe_dimension(),
        compute_modulus_as_f64,
    );

    let before_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_before_pbs_128,
        "before_pbs_128",
        0.0,
        expected_variance_after_ms,
        block_params.lwe_noise_distribution(),
        small_lwe_secret_key.lwe_dimension(),
        compute_modulus_as_f64,
    );

    let after_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_after_pbs_128,
        "after_pbs_128",
        0.0,
        expected_variance_after_pbs_128,
        pbs128_params.glwe_noise_distribution,
        output_pbs_128_glwe_secret_key
            .as_lwe_secret_key()
            .lwe_dimension(),
        pbs128_output_modulus_as_f64,
    );
    assert!(
        before_drift_mitigation_is_ok
            && before_ms_of_pbs_128_is_ok
            && before_pbs_128_is_ok
            && after_pbs_128_is_ok
            && normality_check_before_drift_mitigation.null_hypothesis_is_valid
            && normality_check_before_ms.null_hypothesis_is_valid
    );

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);
}

#[test]
fn test_noise_check_classical_shortint_compute_br_to_squash_pbs_128_atomic_pattern_noise_tuniform_gpu(
) {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Compute,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_multi_bit_shortint_compute_br_to_squash_pbs_128_atomic_pattern_noise_tuniform_gpu(
) {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Compute,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_noise_tuniform_gpu()
{
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Decompression {
            params: COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        },
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail<P>(
    input_br_params: PBS128InputBRParams,
    mut parameters_set: P,
    pbs128_params: NoiseSquashingParameters,
) where
    P: Into<PBSParameters>,
{
    let mut block_params = parameters_set.into();
    assert_eq!(
        block_params.carry_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * block_params.carry_modulus().0 * block_params.message_modulus().0).ilog2();
    block_params.set_carry_modulus(CarryModulus(1 << 4));

    let new_precision_with_padding =
        (2 * block_params.message_modulus().0 * block_params.carry_modulus().0).ilog2();

    let original_pfail = 2.0f64.powf(block_params.log2_p_fail());

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", block_params.log2_p_fail());

    let expected_pfail_before_pbs_128 = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    let expected_pfail_before_pbs_128_log2 = expected_pfail_before_pbs_128.log2();

    println!("expected_pfail_before_pbs_128={expected_pfail_before_pbs_128}");
    println!("expected_pfail_before_pbs_128_log2={expected_pfail_before_pbs_128_log2}");

    let (runs_for_expected_fails, expected_fails_before_pbs_128, total_sample_count) =
        if should_run_long_pfail_tests() {
            let total_runs = 1_000_000;
            let expected_fails = (total_runs as f64 * expected_pfail_before_pbs_128).round() as u32;
            (total_runs, expected_fails, total_runs)
        } else {
            let expected_fails_before_pbs_128 = 200;
            let samples_per_run = 1;

            let runs_for_expected_fails = (expected_fails_before_pbs_128 as f64
                / (expected_pfail_before_pbs_128 * samples_per_run as f64))
                .round() as usize;

            let total_sample_count = runs_for_expected_fails * samples_per_run;
            (
                runs_for_expected_fails,
                expected_fails_before_pbs_128,
                total_sample_count,
            )
        };

    println!("runs_for_expected_fails={runs_for_expected_fails}");
    println!("total_sample_count={total_sample_count}");

    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    // Generate the client key and the server key:
    let (radix_cks, sks) = gen_keys_radix_gpu(block_params, num_blocks, &streams);
    let cks = radix_cks.as_ref();

    let small_lwe_secret_key = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(ap_ck) => ap_ck.small_lwe_secret_key(),
        AtomicPatternClientKey::KeySwitch32(_ap_ck) => todo!(),
    };
    let output_pbs_128_glwe_secret_key;

    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            small_lwe_secret_key
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        let mut engine = ShortintEngine::new();

        output_pbs_128_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
            pbs128_params.glwe_dimension,
            pbs128_params.polynomial_size,
            &mut engine.secret_generator,
        );

        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            //::<_, _, _, _, _, _>(
            &input_lwe_secret_key_as_u128,
            &output_pbs_128_glwe_secret_key,
            pbs128_params.decomp_base_log,
            pbs128_params.decomp_level_count,
            pbs128_params.glwe_noise_distribution,
            pbs128_params.ciphertext_modulus,
            &mut engine.encryption_generator,
        );
        let modulus_switch_noise_reduction_key = pbs128_params
            .modulus_switch_noise_reduction_params
            .map(|modulus_switch_noise_reduction_params| {
                ModulusSwitchNoiseReductionKey::new(
                    modulus_switch_noise_reduction_params,
                    &small_lwe_secret_key,
                    &mut engine,
                    block_params.ciphertext_modulus(),
                    block_params.lwe_noise_distribution(),
                )
            });
        let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(
            &std_bootstrapping_key,
            modulus_switch_noise_reduction_key.as_ref(),
            &streams,
        );
        d_bsk
    };

    let compression_private_key;
    let cuda_decompression_key;
    let (encryption_key, input_br_key) = match input_br_params {
        PBS128InputBRParams::Decompression { params } => {
            compression_private_key = cks.new_compression_private_key(params);
            (_, cuda_decompression_key) = radix_cks
                .new_cuda_compression_decompression_keys(&compression_private_key, &streams);
            (
                &compression_private_key
                    .key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &cuda_decompression_key.blind_rotate_key,
            )
        }
        PBS128InputBRParams::Compute => (&small_lwe_secret_key, &sks.bootstrapping_key),
    };

    let scalar_for_multiplication = block_params.max_noise_level().get();
    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;

    let num_streams = 16;
    let vec_local_streams = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(gpu_index)))
        .collect::<Vec<_>>();

    let (measured_fails_before_pbs_128, _measured_fails_after_pbs_128): (Vec<_>, Vec<_>) = (0
        ..runs_for_expected_fails)
        .into_par_iter()
        .map(|index| {
            let local_stream = &vec_local_streams[index % num_streams];
            let msg: u64 = rand::random::<u64>() % cleartext_modulus;
            //println!("Running iteration {index} with msg={msg} ... ");
            br_to_squash_pbs_128_pfail_helper(
                input_br_params,
                block_params,
                pbs128_params,
                &encryption_key,
                &input_br_key,
                &cks.key,
                &sks,
                &pbs_128_key,
                &output_pbs_128_glwe_secret_key.as_view(),
                msg,
                scalar_for_multiplication.try_into().unwrap(),
                local_stream,
            )
        })
        .unzip();

    let sample_count = measured_fails_before_pbs_128.len();
    let measured_fails_before_pbs_128: f64 = measured_fails_before_pbs_128.into_iter().sum();
    let measured_pfail_before_pbs_128 = measured_fails_before_pbs_128 / (sample_count as f64);

    println!("measured_fails_before_pbs_128={measured_fails_before_pbs_128}");
    println!("measured_pfail_before_pbs_128={measured_pfail_before_pbs_128}");
    println!("expected_fails_before_pbs_128={expected_fails_before_pbs_128}");
    println!("expected_pfail_before_pbs_128={expected_pfail_before_pbs_128}");

    let equivalent_measured_pfail_before_pbs_128 = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail_before_pbs_128,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail_before_pbs_128={equivalent_measured_pfail_before_pbs_128}");
    println!("original_expected_pfail_before_pbs_128  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_before_pbs_128_log2={}",
        equivalent_measured_pfail_before_pbs_128.log2()
    );
    println!(
        "original_expected_pfail_before_pbs_128_log2  ={}",
        original_pfail.log2()
    );

    if measured_fails_before_pbs_128 > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            total_sample_count as f64,
            measured_fails_before_pbs_128,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_lower_bound,
            original_precision_with_padding,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_upper_bound,
            original_precision_with_padding,
        );

        println!("equivalent_pfail_lower_bound={equivalent_pfail_lower_bound}");
        println!("equivalent_pfail_upper_bound={equivalent_pfail_upper_bound}");
        println!(
            "equivalent_pfail_lower_bound_log2={}",
            equivalent_pfail_lower_bound.log2()
        );
        println!(
            "equivalent_pfail_upper_bound_log2={}",
            equivalent_pfail_upper_bound.log2()
        );

        if measured_pfail_before_pbs_128 <= expected_pfail_before_pbs_128 {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail_before_pbs_128) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail_before_pbs_128));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters.\n\
            ==========\n"
        );
    }
}

#[test]
fn test_noise_check_classical_shortint_compute_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform_gpu(
) {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Compute,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_multi_bit_shortint_compute_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform_gpu(
) {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Compute,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform_gpu()
{
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Decompression {
            params: COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        },
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

//Missing to merge the PBS128 GPU
/*
#[derive(Clone, Copy, Debug)]
enum PBS128InputBRParams {
    Decompression { params: CompressionParameters },
    Compute,
}

#[derive(Clone, Copy, Debug)]
struct PBS128Parameters {
    input_lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_noise_distribution: DynamicDistribution<u128>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    // There was a doubt on the mantissa size, several experiments were conducted
    mantissa_size: f64,
    ciphertext_modulus: CoreCiphertextModulus<u128>,
}
// Mantissa 106
// hat_N, hat_k, hat_l_bs, hat_b_bs  , big_pbs_glwe_bound
// 2048,      2,        3, 4294967296, 30
// hat_b_bs_log2 = 32

// Mantissa 100
// hat_N, hat_k, hat_l_bs, hat_b_bs, big_pbs_glwe_bound
// 2048,      2,        3, 67108864, 30
// hat_b_bs_log2 = 26

// Mantissa 104
// hat_N, hat_k, hat_l_bs, hat_b_bs , big_pbs_glwe_bound
// 2048,      2,        3, 536870912, 30
// hat_b_bs_log2 = 29
const PBS128_PARAMS: PBS128Parameters = PBS128Parameters {
    input_lwe_dimension: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.lwe_dimension,
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
    decomp_base_log: DecompositionBaseLog(32),
    decomp_level_count: DecompositionLevelCount(3),
    mantissa_size: 106f64,
    // 2^128
    ciphertext_modulus: CoreCiphertextModulus::new_native(),
};

// #[test]
// fn test_noise_check_pbs_128_secure_noise() {
//     let params = PBS128_PARAMS;

//     let modulus_as_f64 = if params.ciphertext_modulus.is_native_modulus() {
//         2.0f64.powi(128)
//     } else {
//         params.ciphertext_modulus.get_custom_modulus() as f64
//     };

//     let tuniform_bound = minimal_glwe_bound_for_132_bits_security_tuniform(
//         params.glwe_dimension,
//         params.polynomial_size,
//         modulus_as_f64,
//     );

//     match params.glwe_noise_distribution {
//         DynamicDistribution::Gaussian(_) => panic!("Only TUniform is checked here"),
//         DynamicDistribution::TUniform(tuniform) => {
//             assert_eq!(tuniform.bound_log2(), tuniform_bound.0.log2() as i32)
//         }
//     }
// }

fn br_to_squash_pbs_128_inner_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
) -> (DecryptionAndNoiseResult, DecryptionAndNoiseResult) {
    assert!(block_params.pbs_only());
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let mut engine = ShortintEngine::new();
    let thread_compression_private_key;
    let thread_decompression_key;
    let thread_cks;
    let thread_sks;
    let thread_encryption_key;
    let thread_input_br_key;
    let thread_pbs_128_key;
    let thread_output_pbs_128_glwe_secret_key;
    let (cks, sks, encryption_key, input_br_key, pbs_128_key, output_pbs_128_glwe_secret_key) =
        if should_use_one_key_per_sample() {
            thread_cks = engine.new_client_key(block_params);
            thread_sks = engine.new_server_key(&thread_cks);

            (thread_encryption_key, thread_input_br_key) = match input_br_params {
                PBS128InputBRParams::Decompression { params } => {
                    thread_compression_private_key = thread_cks.new_compression_private_key(params);
                    thread_decompression_key = thread_cks
                        .new_compression_decompression_keys(&thread_compression_private_key)
                        .1;

                    (
                        thread_compression_private_key
                            .post_packing_ks_key
                            .as_lwe_secret_key(),
                        &thread_decompression_key.blind_rotate_key,
                    )
                }
                PBS128InputBRParams::Compute => (
                    thread_cks.small_lwe_secret_key(),
                    &thread_sks.bootstrapping_key,
                ),
            };
            thread_pbs_128_key = {
                let thread_input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
                    thread_cks
                        .small_lwe_secret_key()
                        .as_ref()
                        .iter()
                        .copied()
                        .map(|x| x as u128)
                        .collect::<Vec<_>>(),
                );

                thread_output_pbs_128_glwe_secret_key =
                    allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
                        pbs128_params.glwe_dimension,
                        pbs128_params.polynomial_size,
                        &mut engine.secret_generator,
                    );

                let std_bootstrapping_key =
                    par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _>(
                        &thread_input_lwe_secret_key_as_u128,
                        &thread_output_pbs_128_glwe_secret_key,
                        pbs128_params.decomp_base_log,
                        pbs128_params.decomp_level_count,
                        pbs128_params.glwe_noise_distribution,
                        pbs128_params.ciphertext_modulus,
                        &mut engine.encryption_generator,
                    );

                let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
                    std_bootstrapping_key.input_lwe_dimension(),
                    std_bootstrapping_key.glwe_size(),
                    std_bootstrapping_key.polynomial_size(),
                    std_bootstrapping_key.decomposition_base_log(),
                    std_bootstrapping_key.decomposition_level_count(),
                );

                convert_standard_lwe_bootstrap_key_to_fourier_128(
                    &std_bootstrapping_key,
                    &mut fbsk,
                );

                fbsk
            };

            (
                &thread_cks,
                &thread_sks,
                &thread_encryption_key,
                thread_input_br_key,
                &thread_pbs_128_key,
                &thread_output_pbs_128_glwe_secret_key.as_view(),
            )
        } else {
            // If we don't want to use per thread keys (to go faster), we use those single keys for
            // all threads
            (
                single_cks,
                single_sks,
                single_encryption_key,
                single_input_br_key,
                single_pbs_128_key,
                single_output_pbs_128_glwe_secret_key,
            )
        };

    let identity_lut = sks.generate_lookup_table(|x| x);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let br_input_modulus_log = input_br_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;

    let delta = (1u64 << 63) / cleartext_modulus;
    let delta_u128 = (1u128 << 127) / cleartext_modulus as u128;

    // We want to encrypt the ciphertext under modulus 2N but then use the native
    // modulus to simulate a noiseless mod switch as input
    let input_pbs_lwe_ct = {
        let ms_modulus = CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();
        let no_noise_dist = DynamicDistribution::new_gaussian(Variance(0.0));

        let ms_delta = ms_modulus.get_custom_modulus() as u64 / (2 * cleartext_modulus);

        let ms_plaintext = Plaintext(msg * ms_delta);

        let simulated_mod_switch_ct = allocate_and_encrypt_new_lwe_ciphertext(
            encryption_key,
            ms_plaintext,
            no_noise_dist,
            ms_modulus,
            &mut engine.encryption_generator,
        );

        let raw_data = simulated_mod_switch_ct.into_container();
        // Now get the noiseless mod switched encryption under the proper modulus
        // The power of 2 modulus are always encrypted in the MSBs, so this is fine
        LweCiphertext::from_container(raw_data, block_params.ciphertext_modulus())
    };

    let mut after_pbs_shortint_ct = sks.unchecked_create_trivial_with_lwe_size(
        Cleartext(0),
        input_br_key.output_lwe_dimension().to_lwe_size(),
    );

    let (_, buffers) = engine.get_buffers(sks);

    // Apply the PBS only
    apply_programmable_bootstrap(
        &input_br_key,
        &input_pbs_lwe_ct,
        &mut after_pbs_shortint_ct.ct,
        &identity_lut.acc,
        buffers,
    );

    after_pbs_shortint_ct.set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

    let mut after_ks_lwe = LweCiphertext::new(
        0u64,
        sks.key_switching_key.output_lwe_size(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    keyswitch_lwe_ciphertext(
        &sks.key_switching_key,
        &after_pbs_shortint_ct.ct,
        &mut after_ks_lwe,
    );

    let mut after_ms = LweCiphertext::new(
        0u64,
        after_ks_lwe.lwe_size(),
        // This will be easier to manage when decrypting, we'll put the value in the
        // MSB
        block_params.ciphertext_modulus(),
    );

    for (dst, src) in after_ms
        .as_mut()
        .iter_mut()
        .zip(after_ks_lwe.as_ref().iter())
    {
        *dst = modulus_switch(*src, br_input_modulus_log) << shift_to_map_to_native;
    }

    let mut input_pbs_128 = LweCiphertext::new(
        0u128,
        pbs_128_key.input_lwe_dimension().to_lwe_size(),
        pbs128_params.ciphertext_modulus,
    );

    assert_eq!(input_pbs_128.lwe_size(), after_ks_lwe.lwe_size());

    // Map the u64 to u128 because the pbs 128 currently does not support different input and scalar
    // types
    for (dst, src) in input_pbs_128
        .as_mut()
        .iter_mut()
        .zip(after_ks_lwe.as_ref().iter())
    {
        *dst = (*src as u128) << 64;
    }

    let mut output_pbs_128 = LweCiphertext::new(
        0u128,
        pbs_128_key.output_lwe_dimension().to_lwe_size(),
        pbs128_params.ciphertext_modulus,
    );

    let acc = generate_programmable_bootstrap_glwe_lut(
        pbs_128_key.polynomial_size(),
        pbs_128_key.glwe_size(),
        cleartext_modulus as usize,
        pbs128_params.ciphertext_modulus,
        delta_u128,
        |x| x,
    );

    programmable_bootstrap_f128_lwe_ciphertext(
        &input_pbs_128,
        &mut output_pbs_128,
        &acc,
        &pbs_128_key,
    );

    (
        DecryptionAndNoiseResult::new(
            &after_ms,
            &cks.small_lwe_secret_key(),
            msg,
            delta,
            cleartext_modulus,
        ),
        DecryptionAndNoiseResult::new(
            &output_pbs_128,
            &output_pbs_128_glwe_secret_key.as_lwe_secret_key(),
            msg as u128,
            delta_u128,
            cleartext_modulus as u128,
        ),
    )
}

fn br_to_squash_pbs_128_noise_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
) -> (NoiseSample, NoiseSample) {
    let (decryption_and_noise_result_before_pbs_128, decryption_and_noise_result_after_pbs_128) =
        br_to_squash_pbs_128_inner_helper(
            input_br_params,
            block_params,
            pbs128_params,
            single_encryption_key,
            single_input_br_key,
            single_cks,
            single_sks,
            single_pbs_128_key,
            single_output_pbs_128_glwe_secret_key,
            msg,
        );

    (
        match decryption_and_noise_result_before_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
            DecryptionAndNoiseResult::DecryptionFailed => {
                panic!("Failed decryption, noise measurement will be wrong.")
            }
        },
        match decryption_and_noise_result_after_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
            DecryptionAndNoiseResult::DecryptionFailed => {
                panic!("Failed decryption, noise measurement will be wrong.")
            }
        },
    )
}

fn br_to_squash_pbs_128_pfail_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
) -> (f64, f64) {
    let (decryption_and_noise_result_before_pbs_128, decryption_and_noise_result_after_pbs_128) =
        br_to_squash_pbs_128_inner_helper(
            input_br_params,
            block_params,
            pbs128_params,
            single_encryption_key,
            single_input_br_key,
            single_cks,
            single_sks,
            single_pbs_128_key,
            single_output_pbs_128_glwe_secret_key,
            msg,
        );

    (
        match decryption_and_noise_result_before_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
            DecryptionAndNoiseResult::DecryptionFailed => 1.0,
        },
        match decryption_and_noise_result_after_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
            DecryptionAndNoiseResult::DecryptionFailed => 1.0,
        },
    )
}

fn noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
    input_br_params: PBS128InputBRParams,
    block_params: ClassicPBSParameters,
    pbs128_params: PBS128Parameters,
) {
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let compute_modulus_as_f64 = if block_params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        block_params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let pbs128_output_modulus_as_f64 = if pbs128_params.ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(128)
    } else {
        pbs128_params.ciphertext_modulus.get_custom_modulus() as f64
    };

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);
    let output_pbs_128_glwe_secret_key;

    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            cks.small_lwe_secret_key()
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        let mut engine = ShortintEngine::new();

        output_pbs_128_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
            pbs128_params.glwe_dimension,
            pbs128_params.polynomial_size,
            &mut engine.secret_generator,
        );

        assert_eq!(
            input_lwe_secret_key_as_u128.lwe_dimension(),
            pbs128_params.input_lwe_dimension
        );

        let std_bootstrapping_key =
            par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _>(
                &input_lwe_secret_key_as_u128,
                &output_pbs_128_glwe_secret_key,
                pbs128_params.decomp_base_log,
                pbs128_params.decomp_level_count,
                pbs128_params.glwe_noise_distribution,
                pbs128_params.ciphertext_modulus,
                &mut engine.encryption_generator,
            );

        let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bootstrapping_key, &mut fbsk);

        fbsk
    };

    let compression_private_key;
    let decompression_key;

    let (encryption_key, input_br_key) = match input_br_params {
        PBS128InputBRParams::Decompression { params } => {
            compression_private_key = cks.new_compression_private_key(params);
            decompression_key = cks
                .new_compression_decompression_keys(&compression_private_key)
                .1;

            (
                &compression_private_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &decompression_key.blind_rotate_key,
            )
        }
        PBS128InputBRParams::Compute => (&cks.small_lwe_secret_key(), &sks.bootstrapping_key),
    };

    // We get out under the big key of the compute params, so we can check this noise distribution
    let expected_variance_after_input_br = match block_params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => pbs_variance_132_bits_security_gaussian(
            input_br_key.input_lwe_dimension(),
            input_br_key.glwe_size().to_glwe_dimension(),
            input_br_key.polynomial_size(),
            input_br_key.decomposition_base_log(),
            input_br_key.decomposition_level_count(),
            compute_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_variance_132_bits_security_tuniform(
            input_br_key.input_lwe_dimension(),
            input_br_key.glwe_size().to_glwe_dimension(),
            input_br_key.polynomial_size(),
            input_br_key.decomposition_base_log(),
            input_br_key.decomposition_level_count(),
            compute_modulus_as_f64,
        ),
    };

    let compute_ks_input_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

    let keyswitch_additive_variance = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            compute_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            compute_modulus_as_f64,
        ),
    };

    let expected_variance_after_ks =
        Variance(expected_variance_after_input_br.0 + keyswitch_additive_variance.0);

    let br_128_input_modulus_log = pbs_128_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_128_input_modulus = 1u64 << br_128_input_modulus_log.0;

    let ms_additive_variance = modulus_switch_additive_variance(
        compute_ks_output_lwe_dimension,
        compute_modulus_as_f64,
        br_128_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_after_ks.0 + ms_additive_variance.0);

    let expected_variance_after_pbs_128 = match pbs128_params.glwe_noise_distribution {
        DynamicDistribution::Gaussian(_) => pbs_128_variance_132_bits_security_gaussian(
            pbs_128_key.input_lwe_dimension(),
            pbs_128_key.glwe_size().to_glwe_dimension(),
            pbs_128_key.polynomial_size(),
            pbs_128_key.decomposition_base_log(),
            pbs_128_key.decomposition_level_count(),
            pbs128_params.mantissa_size,
            pbs128_output_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_128_variance_132_bits_security_tuniform(
            pbs_128_key.input_lwe_dimension(),
            pbs_128_key.glwe_size().to_glwe_dimension(),
            pbs_128_key.polynomial_size(),
            pbs_128_key.decomposition_base_log(),
            pbs_128_key.decomposition_level_count(),
            pbs128_params.mantissa_size,
            pbs128_output_modulus_as_f64,
        ),
    };

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples_before_pbs_128 = vec![];
    let mut noise_samples_after_pbs_128 = vec![];
    for msg in 0..cleartext_modulus {
        let (current_noise_samples_before_pbs_128, current_noise_samples_after_pbs_128): (
            Vec<_>,
            Vec<_>,
        ) = (0..1000)
            .into_par_iter()
            .map(|_| {
                br_to_squash_pbs_128_noise_helper(
                    input_br_params,
                    block_params,
                    pbs128_params,
                    &encryption_key,
                    &input_br_key,
                    &cks,
                    &sks,
                    &pbs_128_key,
                    &output_pbs_128_glwe_secret_key.as_view(),
                    msg,
                )
            })
            .unzip();

        noise_samples_before_pbs_128.extend(
            current_noise_samples_before_pbs_128
                .into_iter()
                .map(|x| x.value),
        );

        noise_samples_after_pbs_128.extend(
            current_noise_samples_after_pbs_128
                .into_iter()
                .map(|x| x.value),
        );
    }

    println!();

    let before_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_before_pbs_128,
        "before_pbs_128",
        0.0,
        expected_variance_after_ms,
        block_params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        compute_modulus_as_f64,
    );

    let after_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_after_pbs_128,
        "after_pbs_128",
        0.0,
        expected_variance_after_pbs_128,
        pbs128_params.glwe_noise_distribution,
        output_pbs_128_glwe_secret_key
            .as_lwe_secret_key()
            .lwe_dimension(),
        pbs128_output_modulus_as_f64,
    );

    assert!(before_pbs_128_is_ok && after_pbs_128_is_ok);

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);
}

#[test]
fn test_noise_check_shortint_compute_br_to_squash_pbs_128_atomic_pattern_noise_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Compute,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PBS128_PARAMS,
    )
}

#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_noise_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Decompression {
            params: COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        },
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PBS128_PARAMS,
    )
}

fn noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
    input_br_params: PBS128InputBRParams,
    mut block_params: ClassicPBSParameters,
    pbs128_params: PBS128Parameters,
) {
    assert_eq!(
        block_params.carry_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * block_params.carry_modulus.0 * block_params.message_modulus.0).ilog2();
    block_params.carry_modulus.0 = 1 << 4;

    let new_precision_with_padding =
        (2 * block_params.message_modulus.0 * block_params.carry_modulus.0).ilog2();

    let original_pfail = 2.0f64.powf(block_params.log2_p_fail);

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", block_params.log2_p_fail);

    let expected_pfail_before_pbs_128 = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    let expected_pfail_before_pbs_128_log2 = expected_pfail_before_pbs_128.log2();

    println!("expected_pfail_before_pbs_128={expected_pfail_before_pbs_128}");
    println!("expected_pfail_before_pbs_128_log2={expected_pfail_before_pbs_128_log2}");

    let (runs_for_expected_fails, expected_fails_before_pbs_128, total_sample_count) =
        if should_run_long_pfail_tests() {
            let total_runs = 1_000_000;
            let expected_fails = (total_runs as f64 * expected_pfail_before_pbs_128).round() as u32;
            (total_runs, expected_fails, total_runs)
        } else {
            let expected_fails_before_pbs_128 = 200;
            let samples_per_run = 1;

            let runs_for_expected_fails = (expected_fails_before_pbs_128 as f64
                / (expected_pfail_before_pbs_128 * samples_per_run as f64))
                .round() as usize;

            let total_sample_count = runs_for_expected_fails * samples_per_run;
            (
                runs_for_expected_fails,
                expected_fails_before_pbs_128,
                total_sample_count,
            )
        };

    println!("runs_for_expected_fails={runs_for_expected_fails}");
    println!("total_sample_count={total_sample_count}");

    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);
    let output_pbs_128_glwe_secret_key;

    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            cks.small_lwe_secret_key()
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        let mut engine = ShortintEngine::new();

        output_pbs_128_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
            pbs128_params.glwe_dimension,
            pbs128_params.polynomial_size,
            &mut engine.secret_generator,
        );

        assert_eq!(
            input_lwe_secret_key_as_u128.lwe_dimension(),
            pbs128_params.input_lwe_dimension
        );

        let std_bootstrapping_key =
            par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _>(
                &input_lwe_secret_key_as_u128,
                &output_pbs_128_glwe_secret_key,
                pbs128_params.decomp_base_log,
                pbs128_params.decomp_level_count,
                pbs128_params.glwe_noise_distribution,
                pbs128_params.ciphertext_modulus,
                &mut engine.encryption_generator,
            );

        let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bootstrapping_key, &mut fbsk);

        fbsk
    };

    let compression_private_key;
    let decompression_key;

    let (encryption_key, input_br_key) = match input_br_params {
        PBS128InputBRParams::Decompression { params } => {
            compression_private_key = cks.new_compression_private_key(params);
            decompression_key = cks
                .new_compression_decompression_keys(&compression_private_key)
                .1;

            (
                &compression_private_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &decompression_key.blind_rotate_key,
            )
        }
        PBS128InputBRParams::Compute => (&cks.small_lwe_secret_key(), &sks.bootstrapping_key),
    };

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let (measured_fails_before_pbs_128, _measured_fails_after_pbs_128): (Vec<_>, Vec<_>) = (0
        ..runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % cleartext_modulus;

            br_to_squash_pbs_128_pfail_helper(
                input_br_params,
                block_params,
                pbs128_params,
                &encryption_key,
                &input_br_key,
                &cks,
                &sks,
                &pbs_128_key,
                &output_pbs_128_glwe_secret_key.as_view(),
                msg,
            )
        })
        .unzip();

    let sample_count = measured_fails_before_pbs_128.len();
    let measured_fails_before_pbs_128: f64 = measured_fails_before_pbs_128.into_iter().sum();
    let measured_pfail_before_pbs_128 = measured_fails_before_pbs_128 / (sample_count as f64);

    println!("measured_fails_before_pbs_128={measured_fails_before_pbs_128}");
    println!("measured_pfail_before_pbs_128={measured_pfail_before_pbs_128}");
    println!("expected_fails_before_pbs_128={expected_fails_before_pbs_128}");
    println!("expected_pfail_before_pbs_128={expected_pfail_before_pbs_128}");

    if measured_fails_before_pbs_128 > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            total_sample_count as f64,
            measured_fails_before_pbs_128,
            0.99,
        );

        println!(
            "pfail_lower_bound={}",
            pfail_confidence_interval.lower_bound()
        );
        println!(
            "pfail_upper_bound={}",
            pfail_confidence_interval.upper_bound()
        );

        if measured_pfail_before_pbs_128 <= expected_pfail_before_pbs_128 {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail_before_pbs_128) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail_before_pbs_128));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters.\n\
            ==========\n"
        );
    }
}

#[test]
fn test_noise_check_shortint_compute_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Compute,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PBS128_PARAMS,
    )
}

#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Decompression {
            params: COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        },
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PBS128_PARAMS,
    )
}
*/
