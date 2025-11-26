use super::utils::noise_simulation::CudaDynLwe;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLwePackingKeyswitchResult, LwePackingKeyswitch,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::{
    NoiseSimulationLweFourier128Bsk, NoiseSimulationLwePackingKeyswitchKey,
};
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::{CudaSideResources, CudaStreams};
use crate::core_crypto::prelude::{GlweCiphertext, GlweCiphertextCount, LweCiphertextCount};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
use crate::integer::CompressedServerKey;

use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::core_crypto::prelude::{generate_programmable_bootstrap_glwe_lut, LweCiphertext};
use crate::integer::ciphertext::NoiseSquashingCompressionPrivateKey;
use crate::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;
use crate::integer::gpu::server_key::radix::{CudaNoiseSquashingKey, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::unchecked_small_scalar_mul_integer_async;
use crate::integer::IntegerCiphertext;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    //TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, MetaParameters, NoiseSquashingCompressionParameters, Variance,
};
use crate::shortint::server_key::tests::noise_distribution::dp_ks_pbs128_packingks::{
    dp_ks_any_ms_standard_pbs128, dp_ks_any_ms_standard_pbs128_packing_ks,
};
use crate::shortint::server_key::tests::noise_distribution::should_use_single_key_debug;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, NoiseSimulationGlwe, NoiseSimulationLwe, NoiseSimulationLweKeyswitchKey,
    NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, DecryptionAndNoiseResult, NoiseSample,
};
use crate::shortint::{PaddingBit, ShortintEncoding, ShortintParameterSet};
use crate::GpuIndex;
use rayon::prelude::*;

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint for GPU
fn sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks_gpu(meta_params: MetaParameters) {
    let (atomic_params, noise_squashing_params, noise_squashing_compression_params) = {
        let meta_noise_squashing_params = meta_params.noise_squashing_parameters.unwrap();
        (
            meta_params.compute_parameters,
            meta_noise_squashing_params.parameters,
            meta_noise_squashing_params.compression_parameters.unwrap(),
        )
    };
    //let atomic_params: AtomicPatternParameters = params.into();
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = atomic_params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let compressed_noise_squashing_compression_key =
        cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);
    let noise_squashing_key = compressed_noise_squashing_compression_key.decompress();
    let cuda_noise_squashing_key =
        compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);
    let noise_squashing_compression_private_key =
        NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);
    let noise_squashing_compression_key = noise_squashing_private_key
        .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);
    let cuda_noise_squashing_compression_key =
        CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
            &noise_squashing_compression_key,
            &streams,
        );

    let lwe_per_glwe = cuda_noise_squashing_compression_key.lwe_per_glwe;

    let modulus_switch_config = cuda_noise_squashing_key.noise_simulation_modulus_switch_config();

    let br_input_modulus_log = noise_squashing_key.key.br_input_modulus_log();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };
    let max_scalar_mul = sks.key.max_noise_level.get();

    let id_lut_cpu = generate_programmable_bootstrap_glwe_lut(
        noise_squashing_key.key.polynomial_size(),
        noise_squashing_key.key.glwe_size(),
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );

    let id_lut_gpu = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut_cpu, &streams);

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0).map(|_| cks.key.encrypt(0)).collect();

    // Create proper CudaSideResources
    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(1),
        message_modulus: atomic_params.message_modulus(),
        carry_modulus: atomic_params.carry_modulus(),
        atomic_pattern: crate::shortint::AtomicPatternKind::Standard(
            crate::shortint::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources: Vec<CudaSideResources> = (0..input_zeros.len())
        .map(|_| CudaSideResources::new(&streams, cuda_block_info))
        .collect();

    let input_zero_as_lwe: Vec<_> = input_zeros
        .iter()
        .map(|ct| {
            let d_ct_input = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &crate::integer::RadixCiphertext::from_blocks(vec![ct.clone()]),
                &streams,
            );
            CudaDynLwe::U64(d_ct_input.ciphertext.d_blocks)
        })
        .collect();

    // Create a wrapper for the packing keyswitch key with proper traits
    let cuda_packing_key = CudaPackingKeyswitchKey128::new(
        &cuda_noise_squashing_compression_key,
        &mut cuda_side_resources[0],
    );

    let (_before_packing, d_after_packing) = dp_ks_any_ms_standard_pbs128_packing_ks(
        input_zero_as_lwe,
        max_scalar_mul,
        &cuda_sks,
        modulus_switch_config,
        &cuda_noise_squashing_key,
        br_input_modulus_log,
        &id_lut_gpu,
        &cuda_packing_key,
        &mut cuda_side_resources,
    );

    let cuda_noise_squashed_cts: Vec<_> = input_zeros
        .into_par_iter()
        .map(|ct| {
            let cloned_ct = ct.clone();
            let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![cloned_ct]);
            let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_ct, &streams);
            unsafe {
                unchecked_small_scalar_mul_integer_async(
                    &streams,
                    &mut d_ct.ciphertext,
                    max_scalar_mul,
                    atomic_params.message_modulus(),
                    atomic_params.carry_modulus(),
                );
            }
            streams.synchronize();
            cuda_noise_squashing_key.unchecked_squash_ciphertext_noise(
                &d_ct.ciphertext,
                &cuda_sks,
                &streams,
            )
        })
        .collect();

    let gpu_compressed = cuda_noise_squashing_compression_key
        .compress_noise_squashed_ciphertexts_into_list(&cuda_noise_squashed_cts, &streams);

    let gpu_extracted = gpu_compressed.extract_glwe(0, &streams);
    let extracted_list = gpu_extracted.to_glwe_ciphertext_list(&streams);
    let extracted_glwe = GlweCiphertext::from_container(
        extracted_list.clone().into_container(),
        extracted_list.polynomial_size(),
        extracted_list.ciphertext_modulus(),
    );

    let after_packing_list = d_after_packing.to_glwe_ciphertext_list(&streams);
    let mut after_packing = GlweCiphertext::from_container(
        after_packing_list.clone().into_container(),
        after_packing_list.polynomial_size(),
        after_packing_list.ciphertext_modulus(),
    );
    // Bodies that were not filled are discarded
    after_packing.get_mut_body().as_mut()[lwe_per_glwe.0..].fill(0);

    assert_eq!(after_packing.as_view(), extracted_glwe.as_view());
}

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint for GPU
fn sanity_check_encrypt_dp_ks_standard_pbs128_gpu<P>(
    params: P,
    noise_squashing_params: NoiseSquashingParameters,
) where
    P: Into<AtomicPatternParameters> + Copy,
{
    let atomic_params: AtomicPatternParameters = params.into();
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = atomic_params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let compressed_noise_squashing_compression_key =
        cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);
    let noise_squashing_key = compressed_noise_squashing_compression_key.decompress();
    let cuda_noise_squashing_key =
        compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);

    let modulus_switch_config = cuda_noise_squashing_key.noise_simulation_modulus_switch_config();

    let br_input_modulus_log = noise_squashing_key.key.br_input_modulus_log();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };
    let max_scalar_mul = sks.key.max_noise_level.get();

    let id_lut_cpu = generate_programmable_bootstrap_glwe_lut(
        noise_squashing_key.key.polynomial_size(),
        noise_squashing_key.key.glwe_size(),
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );

    let id_lut_gpu = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut_cpu, &streams);

    let lwe_per_glwe = LweCiphertextCount(128);
    let input_zeros: Vec<_> = (0..lwe_per_glwe.0).map(|_| cks.key.encrypt(0)).collect();

    // Create proper CudaSideResources
    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(1),
        message_modulus: atomic_params.message_modulus(),
        carry_modulus: atomic_params.carry_modulus(),
        atomic_pattern: crate::shortint::AtomicPatternKind::Standard(
            crate::shortint::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources: Vec<CudaSideResources> = (0..input_zeros.len())
        .map(|_| CudaSideResources::new(&streams, cuda_block_info))
        .collect();

    let input_zero_as_lwe: Vec<_> = input_zeros
        .iter()
        .map(|ct| {
            let d_ct_input = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &crate::integer::RadixCiphertext::from_blocks(vec![ct.clone()]),
                &streams,
            );
            CudaDynLwe::U64(d_ct_input.ciphertext.d_blocks)
        })
        .collect();

    let res: Vec<_> = input_zero_as_lwe
        .into_par_iter()
        .zip(cuda_side_resources.par_iter_mut())
        .map(|(input, side_resources)| {
            let (input, after_dp, ks_result, drift_technique_result, ms_result, pbs_result) =
                dp_ks_any_ms_standard_pbs128(
                    input,
                    max_scalar_mul,
                    &cuda_sks,
                    modulus_switch_config,
                    &cuda_noise_squashing_key,
                    br_input_modulus_log,
                    &id_lut_gpu,
                    side_resources,
                );

            (
                input,
                after_dp,
                ks_result,
                drift_technique_result,
                ms_result,
                pbs_result,
            )
        })
        .collect();

    let input_zeros_non_pattern: Vec<_> = input_zeros
        .iter()
        .map(|ct| {
            let d_ct_input = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &crate::integer::RadixCiphertext::from_blocks(vec![ct.clone()]),
                &streams,
            );
            d_ct_input
        })
        .collect();

    let vector_non_pattern: Vec<_> = input_zeros_non_pattern
        .into_par_iter()
        .map(|mut d_ct_input2| {
            unsafe {
                unchecked_small_scalar_mul_integer_async(
                    &streams,
                    &mut d_ct_input2.ciphertext,
                    max_scalar_mul,
                    atomic_params.message_modulus(),
                    atomic_params.carry_modulus(),
                );
            }

            streams.synchronize();

            let noise_squashed = cuda_noise_squashing_key
                .squash_radix_ciphertext_noise(&cuda_sks, &d_ct_input2.ciphertext, &streams)
                .unwrap();
            noise_squashed
        })
        .collect();

    let vector_pattern_cpu: Vec<_> = res
        .into_iter()
        .map(
            |(_input, _after_dp, _ks_result, _drift_technique_result, _ms_result, pbs_result)| {
                let after_pbs_list = pbs_result.as_lwe_128().to_lwe_ciphertext_list(&streams);
                LweCiphertext::from_container(
                    after_pbs_list.clone().into_container(),
                    after_pbs_list.ciphertext_modulus(),
                )
            },
        )
        .collect();

    let vector_non_pattern_cpu: Vec<_> = vector_non_pattern
        .into_par_iter()
        .map(|cuda_squashed_radix_ct| {
            let squashed_noise_ct_cpu =
                cuda_squashed_radix_ct.to_squashed_noise_radix_ciphertext(&streams);
            squashed_noise_ct_cpu.packed_blocks()[0]
                .lwe_ciphertext()
                .clone()
        })
        .collect();

    // Compare that all the results are equivalent
    vector_pattern_cpu
        .iter()
        .enumerate()
        .zip(vector_non_pattern_cpu.iter().enumerate())
        .for_each(|((_i, a), (_j, b))| {
            assert_eq!(a.as_view(), b.as_view());
        });
    // assert_eq!(pbs_result_array[0].as_view(),salida_outside[0].as_view());
}

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint for GPU
fn sanity_check_encrypt_dp_ks_standard_pbs128_gpu_vs_cpu<P>(
    params: P,
    noise_squashing_params: NoiseSquashingParameters,
) where
    P: Into<AtomicPatternParameters> + Copy,
{
    let atomic_params: AtomicPatternParameters = params.into();
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = atomic_params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let compressed_noise_squashing_compression_key =
        cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);
    let noise_squashing_key = compressed_noise_squashing_compression_key.decompress();
    let cuda_noise_squashing_key =
        compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);

    let modulus_switch_config = cuda_noise_squashing_key.noise_simulation_modulus_switch_config();

    let br_input_modulus_log = noise_squashing_key.key.br_input_modulus_log();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };
    let max_scalar_mul = sks.key.max_noise_level.get();

    let id_lut_cpu = generate_programmable_bootstrap_glwe_lut(
        noise_squashing_key.key.polynomial_size(),
        noise_squashing_key.key.glwe_size(),
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );

    let id_lut_gpu = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut_cpu, &streams);

    let ct = cks.key.encrypt(0u64);

    // Create proper CudaSideResources
    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(1),
        message_modulus: atomic_params.message_modulus(),
        carry_modulus: atomic_params.carry_modulus(),
        atomic_pattern: crate::shortint::AtomicPatternKind::Standard(
            crate::shortint::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources = CudaSideResources::new(&streams, cuda_block_info);

    let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![ct]);
    let d_ct_input1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_ct, &streams);
    let mut d_ct_input2 = d_ct_input1.duplicate(&streams);
    let d_dynlwe_input1 = CudaDynLwe::U64(d_ct_input1.ciphertext.d_blocks);

    let (_input, _after_dp, _ks_result, _drift_technique_result, _ms_result, pbs_result) =
        dp_ks_any_ms_standard_pbs128(
            d_dynlwe_input1,
            max_scalar_mul,
            &cuda_sks,
            modulus_switch_config,
            &cuda_noise_squashing_key,
            br_input_modulus_log,
            &id_lut_gpu,
            &mut cuda_side_resources,
        );
    unsafe {
        unchecked_small_scalar_mul_integer_async(
            &streams,
            &mut d_ct_input2.ciphertext,
            max_scalar_mul,
            atomic_params.message_modulus(),
            atomic_params.carry_modulus(),
        );
    }

    streams.synchronize();

    let cpu_after_mul = d_ct_input2.to_radix_ciphertext(&streams);
    let cpu_squashed_radix_ct = noise_squashing_key
        .squash_radix_ciphertext_noise(&sks, &cpu_after_mul)
        .unwrap();
    let cpu_squashed_noise_ct = cpu_squashed_radix_ct.packed_blocks()[0].lwe_ciphertext();

    let cuda_squashed_radix_ct = cuda_noise_squashing_key
        .squash_radix_ciphertext_noise(&cuda_sks, &d_ct_input2.ciphertext, &streams)
        .unwrap();

    // Validate After PBS result
    let after_pbs_list = pbs_result.as_lwe_128().to_lwe_ciphertext_list(&streams);
    let after_pbs_ct = LweCiphertext::from_container(
        after_pbs_list.clone().into_container(),
        after_pbs_list.ciphertext_modulus(),
    );

    let squashed_noise_ct_cpu = cuda_squashed_radix_ct.to_squashed_noise_radix_ciphertext(&streams);
    let squashed_noise_ct = squashed_noise_ct_cpu.packed_blocks()[0].lwe_ciphertext();
    println!("After PBS CT: {:?}", after_pbs_ct.as_view());
    println!("Squashed Noise CT: {:?}", squashed_noise_ct.as_view());
    println!(
        "CPU Squashed Noise CT: {:?}",
        cpu_squashed_noise_ct.as_view()
    );

    //  assert_eq!(after_pbs_ct.as_view(),squashed_noise_ct.as_view());
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_dp_ks_standard_pbs128_packing_ks_inner_helper_gpu(
    params: AtomicPatternParameters,
    noise_squashing_params: NoiseSquashingParameters,
    noise_squashing_compression_params: NoiseSquashingCompressionParameters,
    single_cks: &crate::integer::ClientKey,
    single_cuda_sks: &CudaServerKey,
    single_noise_squashing_private_key: &NoiseSquashingPrivateKey,
    single_noise_squashing_key: &crate::integer::noise_squashing::NoiseSquashingKey,
    single_cuda_noise_squashing_key: &CudaNoiseSquashingKey,
    single_noise_squashing_compression_private_key: &NoiseSquashingCompressionPrivateKey,
    single_cuda_noise_squashing_compression_key: &CudaNoiseSquashingCompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    Vec<(
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
    )>,
    Vec<DecryptionAndNoiseResult>,
) {
    let thread_cks: crate::integer::ClientKey;
    let thread_cuda_sks: CudaServerKey;
    let thread_noise_squashing_private_key: NoiseSquashingPrivateKey;
    let thread_noise_squashing_key: crate::integer::noise_squashing::NoiseSquashingKey;
    let thread_cuda_noise_squashing_key: CudaNoiseSquashingKey;
    let thread_noise_squashing_compression_private_key: NoiseSquashingCompressionPrivateKey;
    let thread_cuda_noise_squashing_compression_key: CudaNoiseSquashingCompressionKey;
    let (
        cks,
        cuda_sks,
        noise_squashing_private_key,
        noise_squashing_key,
        cuda_noise_squashing_key,
        noise_squashing_compression_private_key,
        cuda_noise_squashing_compression_key,
    ) = if should_use_single_key_debug() {
        (
            single_cks,
            single_cuda_sks,
            single_noise_squashing_private_key,
            single_noise_squashing_key,
            single_cuda_noise_squashing_key,
            single_noise_squashing_compression_private_key,
            single_cuda_noise_squashing_compression_key,
        )
    } else {
        let block_params: ShortintParameterSet = params.into();
        thread_cks = crate::integer::ClientKey::new(block_params);
        let thread_compressed_server_key =
            CompressedServerKey::new_radix_compressed_server_key(&thread_cks);
        thread_cuda_sks =
            CudaServerKey::decompress_from_cpu(&thread_compressed_server_key, &streams);

        thread_noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
        let thread_compressed_noise_squashing_compression_key =
            thread_cks.new_compressed_noise_squashing_key(&thread_noise_squashing_private_key);
        thread_noise_squashing_key = thread_compressed_noise_squashing_compression_key.decompress();
        thread_cuda_noise_squashing_key =
            thread_compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);
        thread_noise_squashing_compression_private_key =
            NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);
        let thread_noise_squashing_compression_key = thread_noise_squashing_private_key
            .new_noise_squashing_compression_key(&thread_noise_squashing_compression_private_key);
        thread_cuda_noise_squashing_compression_key =
            CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                &thread_noise_squashing_compression_key,
                &streams,
            );
        (
            &thread_cks,
            &thread_cuda_sks,
            &thread_noise_squashing_private_key,
            &thread_noise_squashing_key,
            &thread_cuda_noise_squashing_key,
            &thread_noise_squashing_compression_private_key,
            &thread_cuda_noise_squashing_compression_key,
        )
    };

    let modulus_switch_config = cuda_noise_squashing_key.noise_simulation_modulus_switch_config();

    let bsk_polynomial_size = noise_squashing_key.key.polynomial_size();
    let bsk_glwe_size = noise_squashing_key.key.glwe_size();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };

    let id_lut_cpu = generate_programmable_bootstrap_glwe_lut(
        bsk_polynomial_size,
        bsk_glwe_size,
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );
    let id_lut_gpu = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut_cpu, &streams);

    let lwe_per_glwe = cuda_noise_squashing_compression_key.lwe_per_glwe;

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0).map(|_| cks.key.encrypt(msg)).collect();

    // Create proper CudaSideResources
    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: crate::shortint::AtomicPatternKind::Standard(
            crate::shortint::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources: Vec<CudaSideResources> = (0..input_zeros.len())
        .map(|_| CudaSideResources::new(&streams, cuda_block_info))
        .collect();

    let input_zero_as_lwe: Vec<_> = input_zeros
        .iter()
        .map(|ct| {
            let d_ct_input = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &crate::integer::RadixCiphertext::from_blocks(vec![ct.clone()]),
                &streams,
            );
            CudaDynLwe::U64(d_ct_input.ciphertext.d_blocks)
        })
        .collect();

    // Create a wrapper for the packing keyswitch key with proper traits
    let cuda_packing_key = CudaPackingKeyswitchKey128::new(
        &cuda_noise_squashing_compression_key,
        &mut cuda_side_resources[0],
    );

    let (before_packing_gpu, after_packing_gpu) = dp_ks_any_ms_standard_pbs128_packing_ks(
        input_zero_as_lwe,
        scalar_for_multiplication,
        cuda_sks,
        modulus_switch_config,
        cuda_noise_squashing_key,
        br_input_modulus_log,
        &id_lut_gpu,
        &cuda_packing_key,
        &mut cuda_side_resources,
    );

    let before_packing: Vec<_> = before_packing_gpu
        .into_iter()
        .map(
            |(
                input_gpu,
                after_dp_gpu,
                after_ks_gpu,
                after_drift_gpu,
                after_ms_gpu,
                after_pbs128_gpu,
            )| {
                match &cks.key.atomic_pattern {
                    AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
                        let params = standard_atomic_pattern_client_key.parameters;
                        let u64_encoding = ShortintEncoding {
                            ciphertext_modulus: params.ciphertext_modulus(),
                            message_modulus: params.message_modulus(),
                            carry_modulus: params.carry_modulus(),
                            padding_bit: PaddingBit::Yes,
                        };
                        let large_lwe_secret_key =
                            standard_atomic_pattern_client_key.large_lwe_secret_key();
                        let small_lwe_secret_key =
                            standard_atomic_pattern_client_key.small_lwe_secret_key();

                        let input_list = input_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
                        let input_ct = LweCiphertext::from_container(
                            input_list.clone().into_container(),
                            input_list.ciphertext_modulus(),
                        );
                        let input = DynLwe::U64(input_ct);

                        let after_dp_list =
                            after_dp_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
                        let after_dp_ct = LweCiphertext::from_container(
                            after_dp_list.clone().into_container(),
                            after_dp_list.ciphertext_modulus(),
                        );
                        let after_dp = DynLwe::U64(after_dp_ct);

                        let after_ks_list =
                            after_ks_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
                        let after_ks_ct = LweCiphertext::from_container(
                            after_ks_list.clone().into_container(),
                            after_ks_list.ciphertext_modulus(),
                        );
                        let after_ks = DynLwe::U64(after_ks_ct);

                        let before_ms_gpu: &CudaDynLwe =
                            after_drift_gpu.as_ref().unwrap_or(&after_ks_gpu);
                        let before_ms_list =
                            before_ms_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
                        let before_ms_ct = LweCiphertext::from_container(
                            before_ms_list.clone().into_container(),
                            before_ms_list.ciphertext_modulus(),
                        );
                        let before_ms = DynLwe::U64(before_ms_ct);

                        let after_ms_list =
                            after_ms_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
                        let after_ms_ct = LweCiphertext::from_container(
                            after_ms_list.clone().into_container(),
                            after_ms_list.ciphertext_modulus(),
                        );
                        let after_ms = DynLwe::U64(after_ms_ct);

                        let after_pbs128_list = after_pbs128_gpu
                            .as_lwe_128()
                            .to_lwe_ciphertext_list(streams);
                        let after_pbs128_ct = LweCiphertext::from_container(
                            after_pbs128_list.clone().into_container(),
                            after_pbs128_list.ciphertext_modulus(),
                        );
                        let after_pbs128 = DynLwe::U128(after_pbs128_ct);

                        (
                            DecryptionAndNoiseResult::new_from_lwe(
                                &input.as_lwe_64(),
                                &large_lwe_secret_key,
                                msg,
                                &u64_encoding,
                            ),
                            DecryptionAndNoiseResult::new_from_lwe(
                                &after_dp.as_lwe_64(),
                                &large_lwe_secret_key,
                                msg,
                                &u64_encoding,
                            ),
                            DecryptionAndNoiseResult::new_from_lwe(
                                &after_ks.as_lwe_64(),
                                &small_lwe_secret_key,
                                msg,
                                &u64_encoding,
                            ),
                            DecryptionAndNoiseResult::new_from_lwe(
                                &before_ms.as_lwe_64(),
                                &small_lwe_secret_key,
                                msg,
                                &u64_encoding,
                            ),
                            DecryptionAndNoiseResult::new_from_lwe(
                                &after_ms.as_lwe_64(),
                                &small_lwe_secret_key,
                                msg,
                                &u64_encoding,
                            ),
                            DecryptionAndNoiseResult::new_from_lwe(
                                &after_pbs128.as_lwe_128(),
                                &noise_squashing_private_key
                                    .key
                                    .post_noise_squashing_lwe_secret_key(),
                                msg.into(),
                                &u128_encoding,
                            ),
                        )
                    }
                    AtomicPatternClientKey::KeySwitch32(_ks32_atomic_pattern_client_key) => {
                        panic!("KS32 atomic pattern not supported for GPU yet");
                    }
                }
            },
        )
        .collect();
    let after_packing_list = after_packing_gpu.to_glwe_ciphertext_list(&streams);
    let after_packing = GlweCiphertext::from_container(
        after_packing_list.clone().into_container(),
        after_packing_list.polynomial_size(),
        after_packing_list.ciphertext_modulus(),
    );
    let after_packing = DecryptionAndNoiseResult::new_from_glwe(
        &after_packing,
        noise_squashing_compression_private_key
            .key
            .post_packing_ks_key(),
        lwe_per_glwe,
        msg.into(),
        &u128_encoding,
    );

    assert_eq!(after_packing.len(), lwe_per_glwe.0);

    (before_packing, after_packing)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_dp_ks_standard_pbs128_packing_ks_noise_helper_gpu(
    params: AtomicPatternParameters,
    noise_squashing_params: NoiseSquashingParameters,
    noise_squashing_compression_params: NoiseSquashingCompressionParameters,
    single_cks: &crate::integer::ClientKey,
    single_cuda_sks: &CudaServerKey,
    single_noise_squashing_private_key: &NoiseSquashingPrivateKey,
    single_noise_squashing_key: &crate::integer::noise_squashing::NoiseSquashingKey,
    single_cuda_noise_squashing_key: &CudaNoiseSquashingKey,
    single_noise_squashing_compression_private_key: &NoiseSquashingCompressionPrivateKey,
    single_cuda_noise_squashing_compression_key: &CudaNoiseSquashingCompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    Vec<(
        NoiseSample,
        NoiseSample,
        NoiseSample,
        NoiseSample,
        NoiseSample,
        NoiseSample,
    )>,
    Vec<NoiseSample>,
) {
    let (before_compression, after_compression) =
        encrypt_dp_ks_standard_pbs128_packing_ks_inner_helper_gpu(
            params,
            noise_squashing_params,
            noise_squashing_compression_params,
            single_cks,
            single_cuda_sks,
            single_noise_squashing_private_key,
            single_noise_squashing_key,
            single_cuda_noise_squashing_key,
            single_noise_squashing_compression_private_key,
            single_cuda_noise_squashing_compression_key,
            msg,
            scalar_for_multiplication,
            br_input_modulus_log,
            streams,
        );

    (
        before_compression
            .into_iter()
            .map(
                |(input, after_dp, after_ks, after_drift, after_ms, after_pbs)| {
                    (
                        input
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_dp
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_ks
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_drift
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_ms
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_pbs
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                    )
                },
            )
            .collect(),
        after_compression
            .into_iter()
            .map(|after_compression| {
                after_compression
                    .get_noise_if_decryption_was_correct()
                    .expect("Decryption Failed")
            })
            .collect(),
    )
}

fn noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_noise_gpu(meta_params: MetaParameters) {
    let (atomic_params, noise_squashing_params, noise_squashing_compression_params) = {
        let meta_noise_squashing_params = meta_params.noise_squashing_parameters.unwrap();
        (
            meta_params.compute_parameters,
            meta_noise_squashing_params.parameters,
            meta_noise_squashing_params.compression_parameters.unwrap(),
        )
    };
    //let atomic_params: AtomicPatternParameters = params.into();
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = atomic_params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let compressed_noise_squashing_compression_key =
        cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);
    let noise_squashing_key = compressed_noise_squashing_compression_key.decompress();
    let cuda_noise_squashing_key =
        compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);
    let noise_squashing_compression_private_key =
        NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);
    let noise_squashing_compression_key = noise_squashing_private_key
        .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);
    let cuda_noise_squashing_compression_key =
        CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
            &noise_squashing_compression_key,
            &streams,
        );

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(atomic_params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(atomic_params);
    let noise_simulation_bsk128 =
        NoiseSimulationLweFourier128Bsk::new_from_parameters(atomic_params, noise_squashing_params);
    let noise_simulation_packing_key =
        NoiseSimulationLwePackingKeyswitchKey::new_from_noise_squashing_parameters(
            noise_squashing_params,
            noise_squashing_compression_params,
        );

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks.key));

    assert!(noise_simulation_bsk128
        .matches_actual_shortint_noise_squashing_key(&noise_squashing_key.key));
    assert!(noise_simulation_packing_key.matches_actual_pksk(
        noise_squashing_compression_key
            .key
            .packing_key_switching_key()
    ));

    let br_input_modulus_log = noise_squashing_key.key.br_input_modulus_log();

    let max_scalar_mul = sks.key.max_noise_level.get();

    let noise_simulation_accumulator = NoiseSimulationGlwe::new(
        noise_simulation_bsk128
            .output_glwe_size()
            .to_glwe_dimension(),
        noise_simulation_bsk128.output_polynomial_size(),
        Variance(0.0),
        noise_simulation_bsk128.modulus(),
    );

    let (_before_packing_sim, after_packing_sim) = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks.key, 0);
        dp_ks_any_ms_standard_pbs128_packing_ks(
            vec![noise_simulation; cuda_noise_squashing_compression_key.lwe_per_glwe.0],
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
            &noise_simulation_bsk128,
            br_input_modulus_log,
            &noise_simulation_accumulator,
            &noise_simulation_packing_key,
            &mut vec![(); cuda_noise_squashing_compression_key.lwe_per_glwe.0],
        )
    };

    let after_packing_sim = after_packing_sim.into_lwe();

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let pksk = noise_squashing_compression_key
            .key
            .packing_key_switching_key();

        let out_glwe_dim = pksk.output_key_glwe_dimension();
        let out_poly_size = pksk.output_key_polynomial_size();

        (
            out_glwe_dim.to_equivalent_lwe_dimension(out_poly_size),
            pksk.ciphertext_modulus().raw_modulus_float(),
        )
    };

    assert_eq!(
        after_packing_sim.lwe_dimension(),
        expected_lwe_dimension_out
    );
    assert_eq!(
        after_packing_sim.modulus().as_f64(),
        expected_modulus_f64_out
    );

    let cleartext_modulus = atomic_params.message_modulus().0 * atomic_params.carry_modulus().0;
    let mut noise_samples_after_packing = vec![];

    let sample_count_per_msg =
        1000usize.div_ceil(cuda_noise_squashing_compression_key.lwe_per_glwe.0);

    for _i in 0..cleartext_modulus {
        let current_noise_samples_after_packing: Vec<_> = (0..sample_count_per_msg)
            .into_iter()
            .map(|_j| {
                let (_before_packing, after_packing) =
                    encrypt_dp_ks_standard_pbs128_packing_ks_noise_helper_gpu(
                        atomic_params,
                        noise_squashing_params,
                        noise_squashing_compression_params,
                        &cks,
                        &cuda_sks,
                        &noise_squashing_private_key,
                        &noise_squashing_key,
                        &cuda_noise_squashing_key,
                        &noise_squashing_compression_private_key,
                        &cuda_noise_squashing_compression_key,
                        0,
                        max_scalar_mul,
                        br_input_modulus_log,
                        &streams,
                    );
                after_packing
            })
            .flatten()
            .collect();

        noise_samples_after_packing.extend(
            current_noise_samples_after_packing
                .into_iter()
                .map(|x| x.value),
        );
    }

    let after_packing_is_ok = mean_and_variance_check(
        &noise_samples_after_packing,
        "after_packing",
        0.0,
        after_packing_sim.variance(),
        noise_squashing_compression_params.packing_ks_key_noise_distribution,
        after_packing_sim.lwe_dimension(),
        after_packing_sim.modulus().as_f64(),
    );

    assert!(after_packing_is_ok);
}

/// GPU packing keyswitch key wrapper for noise distribution tests
pub struct CudaPackingKeyswitchKey128<'a> {
    cuda_pksk: &'a CudaLwePackingKeyswitchKey<u128>,
    lwe_per_glwe: LweCiphertextCount,
}

impl<'a> CudaPackingKeyswitchKey128<'a> {
    pub fn new(
        compression_key: &'a CudaNoiseSquashingCompressionKey,
        _side_resources: &CudaSideResources,
    ) -> Self {
        let lwe_per_glwe = compression_key.lwe_per_glwe;

        Self {
            cuda_pksk: &compression_key.packing_key_switching_key,
            lwe_per_glwe,
        }
    }
}

impl<'a> AllocateLwePackingKeyswitchResult for CudaPackingKeyswitchKey128<'a> {
    type Output = CudaGlweCiphertextList<u128>;
    type SideResources = CudaSideResources;

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let glwe_dimension = self.cuda_pksk.output_glwe_size().to_glwe_dimension();
        let polynomial_size = self.cuda_pksk.output_polynomial_size();
        let ciphertext_modulus = self.cuda_pksk.ciphertext_modulus();

        CudaGlweCiphertextList::new(
            glwe_dimension,
            polynomial_size,
            GlweCiphertextCount(1),
            ciphertext_modulus,
            &side_resources.streams,
        )
    }
}

impl<'pksk> LwePackingKeyswitch<[&CudaDynLwe], CudaGlweCiphertextList<u128>>
    for CudaPackingKeyswitchKey128<'pksk>
{
    type SideResources = CudaSideResources;

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &[&CudaDynLwe],
        output: &mut CudaGlweCiphertextList<u128>,
        side_resources: &mut CudaSideResources,
    ) {
        use crate::core_crypto::gpu::algorithms::lwe_packing_keyswitch::cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128;
        let input_lwe_ciphertext_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            input
                .iter()
                .map(|ciphertext| ciphertext.as_lwe_128()),//&ciphertext.as_ref().d_blocks),
            &side_resources.streams,
        );

        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128(
            self.cuda_pksk,
            &input_lwe_ciphertext_list,
            output,
            &side_resources.streams,
        );
    }
}

#[test]
fn test_noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_test_param_message_2_carry_2_ks_pbs_tuniform_2m128_gpu(
) {
    noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_noise_gpu(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        //TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    )
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks_gpu_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks_gpu(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        //TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    )
}
#[test]
#[cfg(feature = "gpu")]
fn test_gpu_sanity_check_encrypt_dp_ks_standard_pbs128_gpu_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    sanity_check_encrypt_dp_ks_standard_pbs128_gpu(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
#[test]
#[cfg(feature = "gpu")]
fn test_gpu_sanity_check_encrypt_dp_ks_standard_pbs128_gpu_vs_cpu_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    sanity_check_encrypt_dp_ks_standard_pbs128_gpu_vs_cpu(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
