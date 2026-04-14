use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaDynamicKeyswitchingKey};
use crate::integer::gpu::{
    cuda_backend_oprf_bitonic_shuffle, cuda_backend_unchecked_bitonic_shuffle, CudaServerKey,
    PBSType,
};
use crate::shortint::oprf::{create_random_from_seed_modulus_switched, raw_seeded_msed_to_lwe};
use tfhe_csprng::seeders::Seeder;

impl CudaServerKey {
    /// Shuffles `data` into a uniformly random permutation.
    ///
    /// Random sort keys are generated obliviously via OPRF (using `seeder` to
    /// derive fresh per-block seed material), then a bitonic network sorts on
    /// those keys, dragging `data` along. Both the OPRF and the shuffle run
    /// inside a single CUDA backend call. Neither the keys nor the
    /// permutation are visible to the server in clear.
    ///
    /// `key_num_blocks` controls the bit-width of the random sort keys. Larger
    /// values reduce collision probability — and thus improve shuffle
    /// uniformity — at the cost of more work per comparison/swap.
    ///
    /// # Errors
    ///
    /// Returns an error if `key_num_blocks` is 0.
    pub fn bitonic_shuffle<T, S>(
        &self,
        mut data: Vec<T>,
        key_num_blocks: u64,
        seeder: &mut S,
        streams: &CudaStreams,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: CudaIntegerRadixCiphertext,
        S: Seeder,
    {
        if key_num_blocks == 0 {
            return Err(crate::Error::new(
                "key_num_blocks must be at least 1".to_string(),
            ));
        }
        if data.len() <= 1 {
            return Ok(data);
        }

        let data_num_blocks = data[0].as_ref().d_blocks.lwe_ciphertext_count().0;
        if data[1..]
            .iter()
            .any(|d| d.as_ref().d_blocks.lwe_ciphertext_count().0 != data_num_blocks)
        {
            return Err(crate::Error::new(
                "all data elements must have the same number of blocks".to_string(),
            ));
        }

        for v in data.iter_mut() {
            if !v.block_carries_are_empty() {
                self.full_propagate_assign(v, streams);
            }
        }

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let (input_lwe_dimension, polynomial_size) = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                (d_bsk.input_lwe_dimension, d_bsk.polynomial_size)
            }
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                (d_bsk.input_lwe_dimension, d_bsk.polynomial_size)
            }
        };
        let in_lwe_size = input_lwe_dimension.to_lwe_size();
        let num_values = data.len();
        let message_bits_count = self.message_modulus.0.ilog2() as u64;

        let h_seeded_lwe_list: Vec<u64> = (0..num_values)
            .flat_map(|_| {
                let key_seed = seeder.seed();
                let (seeded, _last_block_bits) = create_random_from_seed_modulus_switched(
                    key_seed,
                    in_lwe_size,
                    polynomial_size,
                    key_num_blocks * message_bits_count,
                    message_bits_count,
                );
                seeded
                    .into_iter()
                    .flat_map(|s| {
                        raw_seeded_msed_to_lwe(&s, self.ciphertext_modulus).into_container()
                    })
                    .collect::<Vec<u64>>()
            })
            .collect();

        let mut d_seeded_lwe_input =
            unsafe { CudaVec::<u64>::new_async(h_seeded_lwe_list.len(), streams, 0) };
        unsafe {
            d_seeded_lwe_input.copy_from_cpu_async(&h_seeded_lwe_list, streams, 0);
        }

        let mut value_refs: Vec<_> = data.iter_mut().map(|v| v.as_mut()).collect();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_oprf_bitonic_shuffle(
                        streams,
                        &mut value_refs,
                        &d_seeded_lwe_input,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        key_num_blocks as u32,
                        data_num_blocks as u32,
                        T::IS_SIGNED,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_oprf_bitonic_shuffle(
                        streams,
                        &mut value_refs,
                        &d_seeded_lwe_input,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        key_num_blocks as u32,
                        data_num_blocks as u32,
                        T::IS_SIGNED,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        Ok(data)
    }

    /// Shuffles `data` using a bitonic sorting network keyed by `keys`.
    ///
    /// Cleans carries on both `data` and `keys`, then runs the unchecked
    /// shuffle.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` and `keys` have different lengths, or if
    /// elements within `data` (or within `keys`) have inconsistent block counts.
    pub fn bitonic_shuffle_with_keys<T>(
        &self,
        mut data: Vec<T>,
        mut keys: Vec<CudaUnsignedRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: CudaIntegerRadixCiphertext,
    {
        if data.len() != keys.len() {
            return Err(crate::Error::new(format!(
                "data and keys must have the same length, got {} and {}",
                data.len(),
                keys.len()
            )));
        }
        if data.len() <= 1 {
            return Ok(data);
        }

        let data_num_blocks = data[0].as_ref().d_blocks.lwe_ciphertext_count().0;
        if data[1..]
            .iter()
            .any(|d| d.as_ref().d_blocks.lwe_ciphertext_count().0 != data_num_blocks)
        {
            return Err(crate::Error::new(
                "all data elements must have the same number of blocks".to_string(),
            ));
        }
        let key_num_blocks = keys[0].as_ref().d_blocks.lwe_ciphertext_count().0;
        if keys[1..]
            .iter()
            .any(|k| k.as_ref().d_blocks.lwe_ciphertext_count().0 != key_num_blocks)
        {
            return Err(crate::Error::new(
                "all keys must have the same number of blocks".to_string(),
            ));
        }

        for v in data.iter_mut() {
            if !v.block_carries_are_empty() {
                self.full_propagate_assign(v, streams);
            }
        }
        for k in keys.iter_mut() {
            if !k.block_carries_are_empty() {
                self.full_propagate_assign(k, streams);
            }
        }

        Ok(self.unchecked_bitonic_shuffle_with_keys(data, keys, streams))
    }

    /// Performs a bitonic shuffle without cleaning inputs.
    ///
    /// # Preconditions
    ///
    /// * `data` and `keys` must have the same length and consistent block counts.
    /// * Data and key blocks must have no carries.
    pub fn unchecked_bitonic_shuffle_with_keys<T>(
        &self,
        mut data: Vec<T>,
        mut keys: Vec<CudaUnsignedRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Vec<T>
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert_eq!(
            data.len(),
            keys.len(),
            "data.len()={} != keys.len()={}",
            data.len(),
            keys.len()
        );
        let n = data.len();
        if n <= 1 {
            return data;
        }

        let key_num_blocks = keys[0].as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let data_num_blocks = data[0].as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let mut key_refs: Vec<_> = keys.iter_mut().map(|k| k.as_mut()).collect();
        let mut value_refs: Vec<_> = data.iter_mut().map(|v| v.as_mut()).collect();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_bitonic_shuffle(
                        streams,
                        &mut key_refs,
                        &mut value_refs,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        key_num_blocks,
                        data_num_blocks,
                        T::IS_SIGNED,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_bitonic_shuffle(
                        streams,
                        &mut key_refs,
                        &mut value_refs,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        key_num_blocks,
                        data_num_blocks,
                        T::IS_SIGNED,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
        data
    }
}
