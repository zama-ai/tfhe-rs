use rand::Rng;

use crate::core_crypto::gpu::get_number_of_gpus;
use crate::high_level_api::global_state::CustomMultiGpuIndexes;
use crate::prelude::*;
use crate::{
    set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, Device, FheUint32, GpuIndex,
};

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
    let num_gpus_to_use = rng.gen_range(1..=get_number_of_gpus()) as usize;

    // Randomly sample num_gpus_to_use indices
    let selected_indices = rand::seq::index::sample(&mut rng, total_gpus, num_gpus_to_use);

    // Convert the selected indices to GpuIndex objects
    let gpus_to_be_used = CustomMultiGpuIndexes::new(
        selected_indices
            .iter()
            .map(|idx| GpuIndex::new(idx as u32))
            .collect(),
    );

    let clear_a: u32 = rng.gen();
    let clear_b: u32 = rng.gen();

    let mut a = FheUint32::try_encrypt(clear_a, &keys).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &keys).unwrap();

    assert_eq!(a.current_device(), Device::Cpu);
    assert_eq!(b.current_device(), Device::Cpu);
    assert_eq!(a.gpu_indexes(), &[]);
    assert_eq!(b.gpu_indexes(), &[]);

    let gpus = gpus_to_be_used.clone();
    let used_gpus = gpus.gpu_indexes();
    let cuda_key = compressed_server_keys.decompress_to_specific_gpu(gpus_to_be_used);

    set_server_key(cuda_key);
    let c = &a + &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(c.current_device(), Device::CudaGpu);
    assert_eq!(c.gpu_indexes().first().unwrap(), used_gpus.first().unwrap());
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
    assert_eq!(a.gpu_indexes().first().unwrap(), used_gpus.first().unwrap());
    assert_eq!(b.gpu_indexes().first().unwrap(), used_gpus.first().unwrap());

    let c = &a + &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(c.current_device(), Device::CudaGpu);
    assert_eq!(c.gpu_indexes().first().unwrap(), used_gpus.first().unwrap());
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}
