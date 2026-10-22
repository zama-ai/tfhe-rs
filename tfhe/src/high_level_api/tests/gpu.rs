use rand::Rng;

use crate::array::{GpuFheBoolArray, GpuFheUint32Array};
use crate::core_crypto::gpu::get_number_of_gpus;
use crate::high_level_api::global_state::CustomMultiGpuIndexes;
use crate::prelude::*;
use crate::shortint::parameters::{
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkeCrs, ZkComputeLoad};
use crate::{
    clear_gpu_thread_locals, set_server_key, unset_server_key, ClientKey, CompactCiphertextList,
    CompactPublicKey, CompressedCiphertextListBuilder, CompressedServerKey,
    CompressedSquashedNoiseCiphertextList, ConfigBuilder, Device, FheBool, FheInt32, FheUint32,
    FheUint8, GpuIndex, KVStore, SquashedNoiseFheBool, SquashedNoiseFheInt, SquashedNoiseFheUint,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;

/// Regression test: dropping a rayon pool whose threads holds some thread-local GPU
/// data (keys, streams, etc) can cause issue if not properly cleaned up.
///
/// This is because rayon does not seem to wait for the thread destruction
/// which then creates ordering problems with the CUDA driver
///
/// The scenario is:
/// 1. Create a custom rayon thread pool.
/// 2. On each thread, set a GPU server key (which stores CUDA resources in thread-locals).
/// 3. decrypt as decrypt init and uses a different set of cuda stream thread locals
/// 4. Drop the pool
#[test]
fn test_drop_rayon_pool_with_gpu_server_key_thread_locals() {
    let config = ConfigBuilder::default().build();
    let cks = ClientKey::generate(config);

    let num_gpus = get_number_of_gpus() as usize;

    let compressed_sks = CompressedServerKey::new(&cks);
    let sks_vec: Vec<_> = (0..num_gpus)
        .map(|i| compressed_sks.decompress_to_specific_gpu(GpuIndex::new(i as u32)))
        .collect();

    let pool = ThreadPoolBuilder::new()
        .num_threads(4 * num_gpus)
        .exit_handler(|_| clear_gpu_thread_locals())
        .build()
        .unwrap();

    let results: Vec<u8> = pool.install(|| {
        (0..4 * num_gpus)
            .into_par_iter()
            .map_init(
                || {
                    let gpu_index = rayon::current_thread_index().unwrap_or(0) % num_gpus;
                    set_server_key(sks_vec[gpu_index].clone());
                },
                |(), _| {
                    let ct = FheUint8::encrypt_trivial(42u8);
                    let result: u8 = ct.decrypt(&cks);
                    result
                },
            )
            .collect()
    });

    for val in &results {
        assert_eq!(*val, 42u8);
    }

    // Explicitly drop the pool — this is where the bug manifests:
    // rayon threads are joined, their thread-locals (holding GPU server keys
    // referencing CUDA resources) are dropped.
    drop(pool);
}

#[test]
fn test_gpu_selection() {
    let config = ConfigBuilder::default().build();
    let keys = ClientKey::generate(config);
    let compressed_server_keys = CompressedServerKey::new(&keys);

    let mut rng = rand::thread_rng();

    let last_gpu = GpuIndex::new(get_number_of_gpus() - 1);

    let clear_a: u32 = rng.gen();
    let clear_b: u32 = rng.gen();

    let mut a = FheUint32::try_encrypt(clear_a, &keys).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &keys).unwrap();

    assert_eq!(a.current_device(), Device::Cpu);
    assert_eq!(b.current_device(), Device::Cpu);
    assert_eq!(a.gpu_indexes(), &[]);
    assert_eq!(b.gpu_indexes(), &[]);

    let cuda_key = compressed_server_keys.decompress_to_specific_gpu(last_gpu);

    set_server_key(cuda_key);
    let c = &a + &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(c.current_device(), Device::CudaGpu);
    assert_eq!(c.gpu_indexes(), &[last_gpu]);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

    // Check explicit move, but first make sure input are on Cpu still
    assert_eq!(a.current_device(), Device::Cpu);
    assert_eq!(b.current_device(), Device::Cpu);
    assert_eq!(a.gpu_indexes(), &[]);
    assert_eq!(b.gpu_indexes(), &[]);

    a.move_to_current_device();
    b.move_to_current_device();

    assert_eq!(a.current_device(), Device::CudaGpu);
    assert_eq!(b.current_device(), Device::CudaGpu);
    assert_eq!(a.gpu_indexes(), &[last_gpu]);
    assert_eq!(b.gpu_indexes(), &[last_gpu]);

    let c = &a + &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(c.current_device(), Device::CudaGpu);
    assert_eq!(c.gpu_indexes(), &[last_gpu]);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}

#[test]
fn test_gpu_selection_2() {
    // The purpose of if this is to test that we can set_server_key using a cuda key that is on GpuY
    // do some computations, then set_server_key using a cuda key that is on GpuX, and try to copy
    // from GpuY to CPU data resulting from the first set of computations (meaning we have
    // access to a stream on GpuY)
    if get_number_of_gpus() < 2 {
        // This test is only really useful if there are 2 GPUs
        return;
    }
    let config = ConfigBuilder::default().build();
    let keys = ClientKey::generate(config);
    let compressed_server_keys = CompressedServerKey::new(&keys);

    let mut rng = rand::thread_rng();

    let first_gpu = GpuIndex::new(0);
    let last_gpu = GpuIndex::new(get_number_of_gpus() - 1);

    let clear_a: u32 = rng.gen();
    let clear_b: u32 = rng.gen();

    let mut a = FheUint32::try_encrypt(clear_a, &keys).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &keys).unwrap();

    assert_eq!(a.current_device(), Device::Cpu);
    assert_eq!(b.current_device(), Device::Cpu);
    assert_eq!(a.gpu_indexes(), &[]);
    assert_eq!(b.gpu_indexes(), &[]);

    let cuda_key = compressed_server_keys.decompress_to_specific_gpu(last_gpu);
    set_server_key(cuda_key);

    a.move_to_current_device();
    b.move_to_current_device();

    assert_eq!(a.current_device(), Device::CudaGpu);
    assert_eq!(b.current_device(), Device::CudaGpu);
    assert_eq!(a.gpu_indexes(), &[last_gpu]);
    assert_eq!(b.gpu_indexes(), &[last_gpu]);

    let c = &a + &b;

    let cuda_key = compressed_server_keys.decompress_to_specific_gpu(first_gpu);
    set_server_key(cuda_key);

    // Check that, even though the current key is on Gpu 0, and c on Gpu 1, we can copy it to cpu
    // to decrypt
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(c.current_device(), Device::CudaGpu);
    assert_eq!(c.gpu_indexes(), &[last_gpu]);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

    // This will effectively require internally to copy from last gpu to first gpu
    let c = &a + &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(c.current_device(), Device::CudaGpu);
    assert_eq!(c.gpu_indexes(), &[first_gpu]);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}

#[test]
fn test_specific_gpu_selection() {
    let config = ConfigBuilder::default().build();
    let keys = ClientKey::generate(config);
    let compressed_server_keys = CompressedServerKey::new(&keys);

    let mut rng = rand::thread_rng();

    let total_gpus = get_number_of_gpus() as usize;
    // There are 2^total_gpus possible subsets, excluding the empty one
    for num_gpus_to_use in 1..(1 << total_gpus) {
        let mut selected_indices = Vec::new();
        for j in 0..total_gpus {
            if (num_gpus_to_use & (1 << j)) != 0 {
                selected_indices.push(j);
            }
        }

        // Convert the selected indices to GpuIndex objects
        let gpus_to_be_used = CustomMultiGpuIndexes::new(
            selected_indices
                .iter()
                .map(|idx| GpuIndex::new(*idx as u32))
                .collect(),
        );

        let cuda_key = compressed_server_keys.decompress_to_specific_gpu(gpus_to_be_used);

        let first_gpu = GpuIndex::new(selected_indices[0] as u32);

        let clear_a: u32 = rng.gen();
        let clear_b: u32 = rng.gen();

        let mut a = FheUint32::try_encrypt(clear_a, &keys).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &keys).unwrap();

        assert_eq!(a.current_device(), Device::Cpu);
        assert_eq!(b.current_device(), Device::Cpu);
        assert_eq!(a.gpu_indexes(), &[]);
        assert_eq!(b.gpu_indexes(), &[]);

        set_server_key(cuda_key);
        let c = &a + &b;
        let decrypted: u32 = c.decrypt(&keys);
        assert_eq!(c.current_device(), Device::CudaGpu);
        assert_eq!(c.gpu_indexes(), &[first_gpu]);
        assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

        // Check explicit move, but first make sure input are on Cpu still
        assert_eq!(a.current_device(), Device::Cpu);
        assert_eq!(b.current_device(), Device::Cpu);
        assert_eq!(a.gpu_indexes(), &[]);
        assert_eq!(b.gpu_indexes(), &[]);

        a.move_to_current_device();
        b.move_to_current_device();

        assert_eq!(a.current_device(), Device::CudaGpu);
        assert_eq!(b.current_device(), Device::CudaGpu);
        assert_eq!(a.gpu_indexes(), &[first_gpu]);
        assert_eq!(b.gpu_indexes(), &[first_gpu]);

        let c = &a + &b;
        let decrypted: u32 = c.decrypt(&keys);
        assert_eq!(c.current_device(), Device::CudaGpu);
        assert_eq!(c.gpu_indexes(), &[first_gpu]);
        assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
        // unset_server_key is sufficient but we use clear_gpu_thread_locals
        // in order to test  that after calling it, the thread is still usable
        // (the needed thread locals will lazily recreate themselves, nothing prevents them)
        clear_gpu_thread_locals();
    }
}

/// GPU the server key is moved to in the tests checking that data follows the server key
///
/// With the fake multi-GPU debug target there is a single GPU on the machine, so the second
/// key is created on GPU 0 as well: this checks the key swap, but not the cross-GPU copies.
/// Returns `None` if there are not enough GPUs to run the tests.
fn gpu_to_move_server_key_to() -> Option<GpuIndex> {
    if cfg!(feature = "gpu-debug-fake-multi-gpu") {
        Some(GpuIndex::new(0))
    } else if get_number_of_gpus() >= 2 {
        Some(GpuIndex::new(1))
    } else {
        None
    }
}

/// Data computed with a key on one GPU must keep working when the key is replaced by a key
/// on another GPU: it gets copied on the fly, and a KVStore has to be moved explicitly
/// before being used so that all its values stay on the same GPU
#[test]
fn test_server_key_moved_to_another_gpu() {
    let Some(gpu_1) = gpu_to_move_server_key_to() else {
        println!("Skipping test_server_key_moved_to_another_gpu: it requires at least 2 GPUs");
        return;
    };

    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_compact_public_key_parameters((
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .build();
    let keys = ClientKey::generate(config);
    let pk = CompactPublicKey::new(&keys);
    let compressed_server_keys = CompressedServerKey::new(&keys);
    let gpu_0 = GpuIndex::new(0);
    let key_on_gpu_0 = compressed_server_keys.decompress_to_specific_gpu(gpu_0);
    let key_on_gpu_1 = compressed_server_keys.decompress_to_specific_gpu(gpu_1);

    let mut rng = rand::thread_rng();
    let clear_a: u32 = rng.gen();
    let clear_b: u32 = rng.gen();
    let clear_values: Vec<u32> = (0..4).map(|_| rng.gen()).collect();

    set_server_key(key_on_gpu_0);

    let a = FheUint32::encrypt(clear_a, &keys);
    let b = FheUint32::encrypt(clear_b, &keys);
    let c = &a + &b;
    assert_eq!(c.gpu_indexes(), &[gpu_0]);

    let mut kv_store = KVStore::<u8, FheUint32>::new();
    for (i, value) in clear_values.iter().enumerate() {
        kv_store.insert_with_clear_key(i as u8, FheUint32::encrypt(*value, &keys));
    }

    let clear_array: Vec<u32> = (0..4).map(|_| rng.gen()).collect();
    let array = GpuFheUint32Array::try_encrypt(clear_array.as_slice(), &keys).unwrap();
    let bool_array = GpuFheBoolArray::try_encrypt(&[true, false][..], &keys).unwrap();

    let mut compact_list = CompactCiphertextList::builder(&pk)
        .push(clear_a)
        .build_packed();
    compact_list.move_to_current_device().unwrap();
    assert_eq!(compact_list.current_device(), Device::CudaGpu);

    unset_server_key();
    set_server_key(key_on_gpu_1);

    // Ciphertexts on GPU 0 are copied on the fly, they are left on GPU 0
    let d = &c + &a;
    assert_eq!(a.gpu_indexes(), &[gpu_0]);
    assert_eq!(c.gpu_indexes(), &[gpu_0]);
    assert_eq!(d.gpu_indexes(), &[gpu_1]);
    let decrypted: u32 = d.decrypt(&keys);
    assert_eq!(
        decrypted,
        clear_a.wrapping_add(clear_b).wrapping_add(clear_a)
    );

    let mut c = c;
    c.move_to_current_device();
    assert_eq!(c.gpu_indexes(), &[gpu_1]);

    // KVStore operations require the store to be on the GPU of the key, so that all its
    // values stay on the same GPU and the store is not copied at each call
    kv_store.move_to_current_device();
    let encrypted_key = FheUint8::encrypt(1u8, &keys);
    let (value, is_some) = kv_store.get(&encrypted_key);
    assert!(is_some.decrypt(&keys));
    let decrypted: u32 = value.decrypt(&keys);
    assert_eq!(decrypted, clear_values[1]);

    let new_value: u32 = rng.gen();
    kv_store.insert_with_clear_key(4, FheUint32::encrypt(new_value, &keys));
    let encrypted_key = FheUint8::encrypt(2u8, &keys);
    let (value, is_some) = kv_store.get(&encrypted_key);
    assert!(is_some.decrypt(&keys));
    let decrypted: u32 = value.decrypt(&keys);
    assert_eq!(decrypted, clear_values[2]);
    let encrypted_key = FheUint8::encrypt(4u8, &keys);
    let (value, is_some) = kv_store.get(&encrypted_key);
    assert!(is_some.decrypt(&keys));
    let decrypted: u32 = value.decrypt(&keys);
    assert_eq!(decrypted, new_value);

    // Arrays on GPU 0 are copied on the fly
    let doubled = &array + &array;
    let decrypted: Vec<u32> = doubled.decrypt(&keys);
    let expected: Vec<u32> = clear_array.iter().map(|v| v.wrapping_add(*v)).collect();
    assert_eq!(decrypted, expected);
    let negated = !&bool_array;
    let decrypted: Vec<bool> = negated.decrypt(&keys);
    assert_eq!(decrypted, vec![false, true]);

    // Expanding a compact list stored on GPU 0
    let expander = compact_list.expand().unwrap();
    let expanded: FheUint32 = expander.get(0).unwrap().unwrap();
    let decrypted: u32 = expanded.decrypt(&keys);
    assert_eq!(decrypted, clear_a);
}

/// Same as [test_server_key_moved_to_another_gpu], for signed and unsigned integers, booleans,
/// compression, noise squashing and zk verification and expansion
#[test]
fn test_server_key_moved_to_another_gpu_ops() {
    let Some(gpu_1) = gpu_to_move_server_key_to() else {
        println!("Skipping test_server_key_moved_to_another_gpu_ops: it requires at least 2 GPUs");
        return;
    };

    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_compact_public_key_parameters((
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing(NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing_compression(
                NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .build();
    let keys = ClientKey::generate(config);
    let compressed_server_keys = CompressedServerKey::new(&keys);
    let gpu_0 = GpuIndex::new(0);
    let key_on_gpu_0 = compressed_server_keys.decompress_to_specific_gpu(gpu_0);
    let key_on_gpu_1 = compressed_server_keys.decompress_to_specific_gpu(gpu_1);

    let mut rng = rand::thread_rng();
    let clear_u: u32 = rng.gen();
    let clear_i: i32 = rng.gen();

    set_server_key(key_on_gpu_0);

    // Ciphertexts computed on GPU 0
    let u = FheUint32::encrypt(clear_u, &keys);
    let u = &u + &u;
    let clear_u = clear_u.wrapping_add(clear_u);
    let i = FheInt32::encrypt(clear_i, &keys);
    let i = &i + &i;
    let clear_i = clear_i.wrapping_add(clear_i);
    let b = u.ge(clear_u);
    assert_eq!(u.gpu_indexes(), &[gpu_0]);

    // Lists compressed on GPU 0
    let compressed = CompressedCiphertextListBuilder::new()
        .push(u.clone())
        .push(i.clone())
        .push(b.clone())
        .build()
        .unwrap();
    let squashed_compressed = CompressedSquashedNoiseCiphertextList::builder()
        .push(u.squash_noise().unwrap())
        .push(i.squash_noise().unwrap())
        .push(b.squash_noise().unwrap())
        .build()
        .unwrap();

    #[cfg(feature = "zk-pok")]
    let crs = CompactPkeCrs::from_config(config, 64).unwrap();
    #[cfg(feature = "zk-pok")]
    let metadata = b"hlapi";
    #[cfg(feature = "zk-pok")]
    let proven_list = {
        let pk = CompactPublicKey::new(&keys);
        let mut proven_list = CompactCiphertextList::builder(&pk)
            .push(clear_u)
            .push(clear_i)
            .build_with_proof_packed(&crs, metadata, ZkComputeLoad::Proof)
            .unwrap();
        proven_list.move_to_current_device().unwrap();
        assert_eq!(proven_list.current_device(), Device::CudaGpu);
        (pk, proven_list)
    };

    unset_server_key();
    set_server_key(key_on_gpu_1);

    // Unsigned, signed and boolean operations
    let u2 = &u * &u;
    assert_eq!(u2.gpu_indexes(), &[gpu_1]);
    let decrypted: u32 = u2.decrypt(&keys);
    assert_eq!(decrypted, clear_u.wrapping_mul(clear_u));

    let i2 = &i - &i;
    let decrypted: i32 = i2.decrypt(&keys);
    assert_eq!(decrypted, 0);
    let i3 = i.clone() >> 1u32;
    let decrypted: i32 = i3.decrypt(&keys);
    assert_eq!(decrypted, clear_i >> 1);

    let b2 = &b & &u.ne(clear_u);
    assert!(!b2.decrypt(&keys));
    let selected = b.select(&u, &u2);
    let decrypted: u32 = selected.decrypt(&keys);
    assert_eq!(decrypted, clear_u);

    // In-place operations relocate the ciphertext
    let mut u3 = u.clone();
    u3 += &u;
    assert_eq!(u3.gpu_indexes(), &[gpu_1]);
    let mut i4 = i.clone();
    i4 += &i;
    let decrypted: i32 = i4.decrypt(&keys);
    assert_eq!(decrypted, clear_i.wrapping_add(clear_i));

    // Decompression of a list compressed on GPU 0
    let u_out: FheUint32 = compressed.get(0).unwrap().unwrap();
    let i_out: FheInt32 = compressed.get(1).unwrap().unwrap();
    let b_out: FheBool = compressed.get(2).unwrap().unwrap();
    assert_eq!(u_out.gpu_indexes(), &[gpu_1]);
    let decrypted: u32 = (&u_out + &u).decrypt(&keys);
    assert_eq!(decrypted, clear_u.wrapping_add(clear_u));
    let decrypted: i32 = i_out.decrypt(&keys);
    assert_eq!(decrypted, clear_i);
    assert!(b_out.decrypt(&keys));

    // Compression with the key on GPU 1 of ciphertexts on GPU 0
    let compressed = CompressedCiphertextListBuilder::new()
        .push(u.clone())
        .push(i.clone())
        .push(b.clone())
        .build()
        .unwrap();
    let u_out: FheUint32 = compressed.get(0).unwrap().unwrap();
    let decrypted: u32 = u_out.decrypt(&keys);
    assert_eq!(decrypted, clear_u);
    let i_out: FheInt32 = compressed.get(1).unwrap().unwrap();
    let decrypted: i32 = i_out.decrypt(&keys);
    assert_eq!(decrypted, clear_i);
    let b_out: FheBool = compressed.get(2).unwrap().unwrap();
    assert!(b_out.decrypt(&keys));

    // Noise squashing of ciphertexts on GPU 0
    let decrypted: u32 = u.squash_noise().unwrap().decrypt(&keys);
    assert_eq!(decrypted, clear_u);
    let decrypted: i32 = i.squash_noise().unwrap().decrypt(&keys);
    assert_eq!(decrypted, clear_i);
    assert!(b.squash_noise().unwrap().decrypt(&keys));

    // Extraction of a squashed noise list compressed on GPU 0
    let ns_u: SquashedNoiseFheUint = squashed_compressed.get(0).unwrap().unwrap();
    let decrypted: u32 = ns_u.decrypt(&keys);
    assert_eq!(decrypted, clear_u);
    let ns_i: SquashedNoiseFheInt = squashed_compressed.get(1).unwrap().unwrap();
    let decrypted: i32 = ns_i.decrypt(&keys);
    assert_eq!(decrypted, clear_i);
    let ns_b: SquashedNoiseFheBool = squashed_compressed.get(2).unwrap().unwrap();
    assert!(ns_b.decrypt(&keys));

    // Compression with the key on GPU 1 of noise squashed ciphertexts of GPU 0 ciphertexts
    let squashed_compressed = CompressedSquashedNoiseCiphertextList::builder()
        .push(u.squash_noise().unwrap())
        .push(i.squash_noise().unwrap())
        .push(b.squash_noise().unwrap())
        .build()
        .unwrap();
    let ns_u: SquashedNoiseFheUint = squashed_compressed.get(0).unwrap().unwrap();
    let decrypted: u32 = ns_u.decrypt(&keys);
    assert_eq!(decrypted, clear_u);
    let ns_i: SquashedNoiseFheInt = squashed_compressed.get(1).unwrap().unwrap();
    let decrypted: i32 = ns_i.decrypt(&keys);
    assert_eq!(decrypted, clear_i);
    let ns_b: SquashedNoiseFheBool = squashed_compressed.get(2).unwrap().unwrap();
    assert!(ns_b.decrypt(&keys));

    // Zk verification and expansion of a proven list on GPU 0
    #[cfg(feature = "zk-pok")]
    {
        let (pk, proven_list) = proven_list;
        let expander = proven_list.verify_and_expand(&crs, &pk, metadata).unwrap();
        let u_out: FheUint32 = expander.get(0).unwrap().unwrap();
        let decrypted: u32 = u_out.decrypt(&keys);
        assert_eq!(decrypted, clear_u);
        let i_out: FheInt32 = expander.get(1).unwrap().unwrap();
        let decrypted: i32 = i_out.decrypt(&keys);
        assert_eq!(decrypted, clear_i);
    }
}
