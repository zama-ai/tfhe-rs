use super::{FheIntId, FheUint, FheUintId};
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::{FheInt, Seed};

impl<Id: FheUintId> FheUint<Id> {
    /// Generates an encrypted unsigned integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0));
    ///
    /// let dec_result: u16 = ct_res.decrypt(&client_key);
    /// ```
    pub fn generate_oblivious_pseudo_random(seed: Seed) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_unsigned_integer(
                        seed,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );

                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_unsigned_integer(
                        seed,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );

                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheUint8::get_generate_oblivious_pseudo_random_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(streams)
            } else {
                0
            }
        })
    }
    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let ct_res = FheUint8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    ///
    /// let dec_result: u16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn generate_oblivious_pseudo_random_bounded(seed: Seed, random_bits_count: u64) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );

                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );
                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random_bounded
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheUint8::get_generate_oblivious_pseudo_random_bounded_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_bounded_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_unsigned_integer_bounded_size_on_gpu(
                        streams,
                    )
            } else {
                0
            }
        })
    }
}

impl<Id: FheIntId> FheInt<Id> {
    /// Generates an encrypted signed integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let ct_res = FheInt8::generate_oblivious_pseudo_random(Seed(0));
    ///
    /// let dec_result: i16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result < 1 << 7);
    /// assert!(dec_result >= -(1 << 7));
    /// ```
    pub fn generate_oblivious_pseudo_random(seed: Seed) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_signed_integer(
                        seed,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );
                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaSignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_signed_integer(
                        seed,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );

                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheInt8::get_generate_oblivious_pseudo_random_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_signed_integer_size_on_gpu(streams)
            } else {
                0
            }
        })
    }
    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let ct_res = FheInt8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    ///
    /// let dec_result: i16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result >= 0);
    /// assert!(dec_result < 1 << random_bits_count);
    /// ```
    pub fn generate_oblivious_pseudo_random_bounded(seed: Seed, random_bits_count: u64) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_signed_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );

                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaSignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_signed_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );
                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random_bounded
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheInt8::get_generate_oblivious_pseudo_random_bounded_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_bounded_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_unsigned_integer_bounded_size_on_gpu(
                        streams,
                    )
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
#[allow(unused_imports)]
mod test {
    use crate::prelude::*;
    use crate::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint64, GpuIndex};

    #[test]
    fn test_oprf_size_on_gpu() {
        let config = ConfigBuilder::default().build();
        let (_client_key, server_key) = generate_keys(config);

        set_server_key(server_key);
        let size = FheUint32::get_generate_oblivious_pseudo_random_bounded_size_on_gpu();
        check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
        let size_1 = FheUint64::get_generate_oblivious_pseudo_random_size_on_gpu();
        check_valid_cuda_malloc_assert_oom(size_1, GpuIndex::new(0));
    }
}
