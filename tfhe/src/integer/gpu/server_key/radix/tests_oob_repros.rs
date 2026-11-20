use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::{gen_keys_radix_gpu, CudaServerKey};
use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
use crate::integer::{ClientKey, CompressedServerKey};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::AtomicPatternParameters;

fn compress_and_decompress_small(num_blocks: usize) {
    let streams = CudaStreams::new_multi_gpu();
    let params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_params = COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let (radix_cks, sks) =
        gen_keys_radix_gpu::<AtomicPatternParameters>(params.into(), num_blocks, &streams);
    let cks = radix_cks.as_ref();
    let private_compression_key = cks.new_compression_private_key(comp_params);
    let (cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);

    let ct = radix_cks.encrypt(0u64);
    let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    let d_ct = sks.bitand(&d_ct, &d_ct, &streams);

    let mut builder = CudaCompressedCiphertextListBuilder::new();
    builder.push(d_ct, &streams);
    let cuda_compressed = builder.build(&cuda_compression_key, &streams);

    let _: CudaUnsignedRadixCiphertext = cuda_compressed
        .get(0, &cuda_decompression_key, &streams)
        .unwrap()
        .unwrap();
}

#[test]
fn bug_a_sample_extract_nth_modulo() {
    compress_and_decompress_small(4);
}

#[test]
fn bug_b_host_extract_memset_offset() {
    compress_and_decompress_small(4);
}

#[test]
fn bug_c_tmp_glwe_array_out_alloc() {
    let streams = CudaStreams::new_multi_gpu();
    let params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_params = COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let (radix_cks, sks) =
        gen_keys_radix_gpu::<AtomicPatternParameters>(params.into(), 32, &streams);
    let cks = radix_cks.as_ref();
    let private_compression_key = cks.new_compression_private_key(comp_params);
    let (cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);

    let lwe_per_glwe = comp_params.lwe_per_glwe().0;
    let messages_count = 2 * lwe_per_glwe / 32 + 2;

    let mut builder = CudaCompressedCiphertextListBuilder::new();
    for i in 0..messages_count {
        let ct = radix_cks.encrypt(i as u128);
        let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
        let d_ct = sks.bitand(&d_ct, &d_ct, &streams);
        builder.push(d_ct, &streams);
    }
    let cuda_compressed = builder.build(&cuda_compression_key, &streams);

    for i in 0..messages_count {
        let _: CudaUnsignedRadixCiphertext = cuda_compressed
            .get(i, &cuda_decompression_key, &streams)
            .unwrap()
            .unwrap();
    }
}

#[cfg(feature = "zk-pok")]
#[test]
fn bug_d_zk_expand_odd_blocks() {
    use crate::core_crypto::prelude::LweCiphertextCount;
    use crate::integer::ciphertext::CompactCiphertextList;
    use crate::integer::gpu::key_switching_key::{
        CudaKeySwitchingKey, CudaKeySwitchingKeyMaterial,
    };
    use crate::integer::gpu::zk::CudaProvenCompactCiphertextList;
    use crate::integer::key_switching_key::KeySwitchingKey;
    use crate::integer::{CompactPrivateKey, CompactPublicKey};
    use crate::shortint::parameters::{
        PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};

    let streams = CudaStreams::new_multi_gpu();
    let fhe_params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let ksk_params = PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let metadata = b"integer";

    let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(32)).unwrap();
    let cks = ClientKey::new(fhe_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sk = compressed_server_key.decompress();
    let gpu_sk = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let compact_private_key = CompactPrivateKey::new(pke_params);
    let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
    let d_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
    let d_ksk = CudaKeySwitchingKey::from_cuda_key_switching_key_material(&d_ksk_material, &gpu_sk);

    let pk = CompactPublicKey::new(&compact_private_key);

    let proven_ct = CompactCiphertextList::builder(&pk)
        .push(true)
        .build_with_proof_packed(&crs, metadata, ZkComputeLoad::Proof)
        .unwrap();

    let gpu_proven_ct =
        CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(&proven_ct, &streams);

    let _ = gpu_proven_ct
        .expand_without_verification(&d_ksk, &streams)
        .unwrap();
}

#[test]
fn bug_e_cuda_vec_slice_bounds() {
    let streams = CudaStreams::new_multi_gpu();
    let v: CudaVec<u64> = unsafe { CudaVec::new_async(0, &streams, 0) };
    streams.synchronize();
    let _ = v.as_slice(.., 0);
}

#[test]
fn bug_f_noise_squashing_degree_oob() {
    let param = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_parameters =
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    const NUM_BLOCKS: usize = 16;
    let streams = CudaStreams::new_multi_gpu();

    let cks = ClientKey::new(param);
    let compressed_sks = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_sks, &streams);

    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
    let compressed_noise_squashing_key =
        cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);
    let cuda_noise_squashing_key = compressed_noise_squashing_key.decompress_to_cuda(&streams);

    let ct = cks.encrypt_radix(0u32, NUM_BLOCKS);
    let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);

    let _ = cuda_noise_squashing_key
        .squash_radix_ciphertext_noise(&cuda_sks, &d_ct.ciphertext, &streams)
        .unwrap();
}

#[test]
fn bug_g_mul_lut_index_oob() {
    let streams = CudaStreams::new_multi_gpu();
    let params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let (radix_cks, sks) =
        gen_keys_radix_gpu::<AtomicPatternParameters>(params.into(), 4, &streams);

    let d_a = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &radix_cks.encrypt(3u64),
        &streams,
    );
    let d_b = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &radix_cks.encrypt(5u64),
        &streams,
    );

    let _ = sks.mul(&d_a, &d_b, &streams);
}
