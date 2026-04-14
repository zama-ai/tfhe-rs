use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::oprf::GenericCudaOprfServerKey;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaDynamicKeyswitchingKey};
use crate::integer::gpu::{
    cuda_backend_oprf_bitonic_shuffle, cuda_backend_unchecked_bitonic_shuffle, CudaServerKey,
};
pub use crate::integer::server_key::radix_parallel::bitonic_shuffle::{
    BitonicShuffleKeySize, CollisionProbability,
};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::oprf::{create_random_from_seed_modulus_switched, raw_seeded_msed_to_lwe};
use crate::shortint::OprfSeed;
use std::borrow::Borrow;

impl CudaServerKey {
    /// Shuffles `data` into a uniformly random permutation using a bitonic sorting network
    /// with OPRF-generated random sort keys.
    ///
    /// The sort keys are derived from `seed` with `oprf_key` (the dedicated OPRF key),
    /// then `data` is sorted by them. For an OPRF key shared with the
    /// CPU backend, both backends therefore produce the same permutation for a given seed.
    pub fn bitonic_shuffle<T, S, K>(
        &self,
        oprf_key: &GenericCudaOprfServerKey<K>,
        mut data: Vec<T>,
        key_size: BitonicShuffleKeySize,
        seed: S,
        streams: &CudaStreams,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: CudaIntegerRadixCiphertext,
        S: OprfSeed,
        K: Borrow<CudaBootstrappingKey<u64>>,
    {
        if self.message_modulus.0 != 4 || self.carry_modulus.0 != 4 {
            return Err(crate::Error::new(
                "bitonic_shuffle on GPU currently only supports MESSAGE_2_CARRY_2 parameters"
                    .to_string(),
            ));
        }

        let key_num_blocks = key_size.num_blocks_of_keys(data.len(), self.message_modulus) as u64;

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
            let needs_propagate = v
                .as_ref()
                .info
                .blocks
                .iter()
                .any(|b| !b.carry_is_empty() || b.noise_level != NoiseLevel::NOMINAL);
            if needs_propagate {
                self.full_propagate_assign(v, streams);
            }
        }

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        // The OPRF that derives the sort keys must use the dedicated OPRF bootstrapping key
        // to match the CPU backend logic
        let oprf_bsk = oprf_key.bootstrapping_key();
        oprf_key.assert_compatible_with_target_bsk(&self.bootstrapping_key);

        let input_lwe_dimension = self.bootstrapping_key.input_lwe_dimension();
        let polynomial_size = self.bootstrapping_key.polynomial_size();
        let in_lwe_size = input_lwe_dimension.to_lwe_size();
        let message_bits_count = self.message_modulus.0.ilog2() as u64;
        let bits_per_block = message_bits_count + self.carry_modulus.0.ilog2() as u64 + 1;
        let key_num_bits = key_num_blocks * message_bits_count;

        let chunks = vec![key_num_bits; data.len()];
        let seeded = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            polynomial_size,
            &chunks,
            message_bits_count,
            bits_per_block,
        );
        let h_seeded_lwe_list: Vec<u64> = seeded
            .0
            .into_iter()
            .flat_map(|(seeded, _bits)| {
                raw_seeded_msed_to_lwe(&seeded, self.ciphertext_modulus).into_container()
            })
            .collect();

        let mut d_seeded_lwe_input =
            unsafe { CudaVec::<u64>::new_async(h_seeded_lwe_list.len(), streams, 0) };
        unsafe {
            d_seeded_lwe_input.copy_from_cpu_async(&h_seeded_lwe_list, streams, 0);
        }
        streams.synchronize();

        let mut value_refs: Vec<_> = data.iter_mut().map(|v| v.as_mut()).collect();

        unsafe {
            match (&self.bootstrapping_key, oprf_bsk) {
                (
                    CudaBootstrappingKey::Classic(d_bsk),
                    CudaBootstrappingKey::Classic(oprf_d_bsk),
                ) => {
                    cuda_backend_oprf_bitonic_shuffle(
                        streams,
                        &mut value_refs,
                        &d_seeded_lwe_input,
                        &oprf_d_bsk.d_vec,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        key_num_blocks as u32,
                        data_num_blocks as u32,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                (
                    CudaBootstrappingKey::MultiBit(d_multibit_bsk),
                    CudaBootstrappingKey::MultiBit(oprf_d_multibit_bsk),
                ) => {
                    cuda_backend_oprf_bitonic_shuffle(
                        streams,
                        &mut value_refs,
                        &d_seeded_lwe_input,
                        &oprf_d_multibit_bsk.d_vec,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        key_num_blocks as u32,
                        data_num_blocks as u32,
                        None,
                    );
                }
                _ => panic!("OPRF key and compute key must use the same kind of bootstrapping key"),
            }
        }

        Ok(data)
    }

    /// Shuffles `data` using a bitonic sorting network keyed by `keys`.
    pub fn bitonic_shuffle_with_keys<T>(
        &self,
        mut data: Vec<T>,
        mut keys: Vec<CudaUnsignedRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: CudaIntegerRadixCiphertext,
    {
        if self.message_modulus.0 != 4 || self.carry_modulus.0 != 4 {
            return Err(crate::Error::new(
                "bitonic_shuffle on GPU currently only supports MESSAGE_2_CARRY_2 parameters"
                    .to_string(),
            ));
        }

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
            let needs_propagate = v
                .as_ref()
                .info
                .blocks
                .iter()
                .any(|b| !b.carry_is_empty() || b.noise_level != NoiseLevel::NOMINAL);
            if needs_propagate {
                self.full_propagate_assign(v, streams);
            }
        }
        for k in keys.iter_mut() {
            let needs_propagate = k
                .as_ref()
                .info
                .blocks
                .iter()
                .any(|b| !b.carry_is_empty() || b.noise_level != NoiseLevel::NOMINAL);
            if needs_propagate {
                self.full_propagate_assign(k, streams);
            }
        }

        Ok(self.unchecked_bitonic_shuffle_with_keys(data, keys, streams))
    }

    /// Performs a bitonic shuffle without cleaning inputs or outputs.
    ///
    /// # Preconditions
    ///
    /// * `data` and `keys` must have the same length and consistent block counts.
    /// * Data and key blocks must have no carries and noise budget for the bitonic compare-and-swap
    ///   operations.
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
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        key_num_blocks,
                        data_num_blocks,
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
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        key_num_blocks,
                        data_num_blocks,
                        None,
                    );
                }
            }
        }
        data
    }
}
