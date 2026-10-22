use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::global_state::CudaDuplicate;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::compact_list::CudaFlattenedVecCompactCiphertextList;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList;
use crate::integer::gpu::ciphertext::squashed_noise::{
    CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext,
    CudaSquashedNoiseSignedRadixCiphertext,
};
use crate::integer::gpu::ciphertext::{
    CudaCompressedSquashedNoiseCiphertextList, CudaIntegerRadixCiphertext,
};
use crate::integer::gpu::server_key::radix::kv_store::CudaKVStore;
#[cfg(feature = "zk-pok")]
use crate::integer::gpu::zk::CudaProvenCompactCiphertextList;
use crate::GpuIndex;
use std::sync::LazyLock;

/// Check there is enough memory on the GPU to allocate a certain size
/// # Example
///
/// ```rust
/// use rand::Rng;
/// use tfhe::prelude::*;
/// use tfhe::{set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheInt32, GpuIndex};
///
/// let config = ConfigBuilder::default();
/// let client_key = ClientKey::generate(config);
/// let csks = CompressedServerKey::new(&client_key);
/// let server_key = csks.decompress_to_gpu();
/// set_server_key(server_key);
/// let mut rng = rand::thread_rng();
/// let clear_a = rng.gen_range(1..=i32::MAX);
/// let clear_b = rng.gen_range(1..=i32::MAX);
/// let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
/// let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
/// let ciphertexts_size = a.get_size_on_gpu() + b.get_size_on_gpu();
/// check_valid_cuda_malloc_assert_oom(ciphertexts_size, GpuIndex::new(0));
///
/// a.move_to_current_device();
/// b.move_to_current_device();
///
/// let tmp_buffer_size = a.get_add_size_on_gpu(&b);
/// check_valid_cuda_malloc_assert_oom(tmp_buffer_size, GpuIndex::new(0));
/// a += &b;
/// ```
pub fn check_valid_cuda_malloc(size: u64, gpu_index: GpuIndex) -> bool {
    crate::core_crypto::gpu::check_valid_cuda_malloc(size, gpu_index)
}

pub fn check_valid_cuda_malloc_assert_oom(size: u64, gpu_index: GpuIndex) {
    crate::core_crypto::gpu::check_valid_cuda_malloc_assert_oom(size, gpu_index);
}

impl<T: CudaIntegerRadixCiphertext> CudaDuplicate for T {
    fn gpu_indexes(&self) -> &[GpuIndex] {
        CudaIntegerRadixCiphertext::gpu_indexes(self)
    }

    fn duplicate(&self, streams: &CudaStreams) -> Self {
        CudaIntegerRadixCiphertext::duplicate(self, streams)
    }
}

impl<Key, Ct> CudaDuplicate for CudaKVStore<Key, Ct>
where
    Key: Clone + Ord,
    Ct: CudaIntegerRadixCiphertext,
{
    fn gpu_indexes(&self) -> &[GpuIndex] {
        // An empty store has no GPU, any streams can be used to duplicate it
        static ANY_GPU: LazyLock<[GpuIndex; 1]> = LazyLock::new(|| [GpuIndex::new(0)]);
        self.iter()
            .next()
            .map_or(&ANY_GPU[..], |(_, value)| value.gpu_indexes())
    }

    fn duplicate(&self, streams: &CudaStreams) -> Self {
        self.duplicate(streams)
    }
}

macro_rules! impl_cuda_duplicate {
    ($($ty:ty),* $(,)?) => {
        $(
            impl CudaDuplicate for $ty {
                fn gpu_indexes(&self) -> &[GpuIndex] {
                    self.gpu_indexes()
                }

                fn duplicate(&self, streams: &CudaStreams) -> Self {
                    self.duplicate(streams)
                }
            }
        )*
    };
}

impl_cuda_duplicate!(
    CudaBooleanBlock,
    CudaSquashedNoiseRadixCiphertext,
    CudaSquashedNoiseSignedRadixCiphertext,
    CudaSquashedNoiseBooleanBlock,
    CudaCompressedCiphertextList,
    CudaCompressedSquashedNoiseCiphertextList,
    CudaFlattenedVecCompactCiphertextList,
);

#[cfg(feature = "zk-pok")]
impl_cuda_duplicate!(CudaProvenCompactCiphertextList);
