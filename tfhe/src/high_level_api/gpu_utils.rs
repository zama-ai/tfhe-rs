use crate::GpuIndex;

/// Check there is enough memory on the GPU to allocate a certain size
/// # Example
///
/// ```rust
/// use rand::Rng;
/// use tfhe::prelude::*;
/// use tfhe::{
///     generate_keys, set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheInt16,
///     FheInt32, GpuIndex,
/// };
///
/// let config = ConfigBuilder::default();
/// let client_key = ClientKey::generate(config);
/// let csks = CompressedServerKey::new(&client_key);
/// let server_key = csks.decompress_to_gpu();
/// set_server_key(server_key);
/// let mut rng = rand::rng();
/// let clear_a = rng.random_range(1..=i32::MAX);
/// let clear_b = rng.random_range(1..=i32::MAX);
/// let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
/// let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
/// let ciphertexts_size = a.get_size_on_gpu() + b.get_size_on_gpu();
/// assert!(check_valid_cuda_malloc(ciphertexts_size, GpuIndex::new(0)));
///
/// a.move_to_current_device();
/// b.move_to_current_device();
///
/// let tmp_buffer_size = a.get_add_assign_size_on_gpu(&b);
/// assert!(check_valid_cuda_malloc(tmp_buffer_size, GpuIndex::new(0)));
/// a += &b;
/// ```
pub fn check_valid_cuda_malloc(size: u64, gpu_index: GpuIndex) -> bool {
    crate::core_crypto::gpu::check_valid_cuda_malloc(size, gpu_index)
}
