use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::oprf::GenericCudaOprfServerKey;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaDynamicKeyswitchingKey};
use crate::integer::gpu::{
    cuda_backend_oprf_bitonic_shuffle, cuda_backend_unchecked_bitonic_shuffle, CudaServerKey,
    PBSType,
};
pub use crate::integer::server_key::radix_parallel::bitonic_shuffle::{
    BitonicShuffleKeySize, CollisionProbability,
};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::oprf::{create_random_from_seed_modulus_switched, raw_seeded_msed_to_lwe};
use crate::shortint::OprfSeed;
use std::borrow::Borrow;

impl CudaServerKey {
    fn check_params_for_shuffle(&self) -> Result<(), crate::Error> {
        if self.message_modulus.0 != 4 || self.carry_modulus.0 != 4 {
            return Err(crate::Error::new(
                "bitonic_shuffle on GPU currently only supports MESSAGE_2_CARRY_2 parameters"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn shuffle_clean_inplace<T>(&self, ct: &mut T, streams: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let needs_propagate = ct
            .as_ref()
            .info
            .blocks
            .iter()
            .any(|b| !b.carry_is_empty() || b.noise_level != NoiseLevel::NOMINAL);
        if needs_propagate {
            self.full_propagate_assign(ct, streams);
        }
    }

    /// Shuffles `data` into a uniformly random permutation using a bitonic sorting network
    /// with OPRF-generated random sort keys.
    pub fn bitonic_shuffle<T, S, K>(
        &self,
        _oprf_key: &GenericCudaOprfServerKey<K>,
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
        self.check_params_for_shuffle()?;

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
            self.shuffle_clean_inplace(v, streams);
        }

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let input_lwe_dimension = self.bootstrapping_key.input_lwe_dimension();
        let polynomial_size = self.bootstrapping_key.polynomial_size();
        let in_lwe_size = input_lwe_dimension.to_lwe_size();
        let message_bits_count = self.message_modulus.0.ilog2() as u64;
        let key_num_bits = key_num_blocks * message_bits_count;

        let chunks = vec![key_num_bits; data.len()];
        let seeded = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            polynomial_size,
            &chunks,
            message_bits_count,
        );
        let h_seeded_lwe_list: Vec<u64> = seeded
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
    pub fn bitonic_shuffle_with_keys<T>(
        &self,
        mut data: Vec<T>,
        mut keys: Vec<CudaUnsignedRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.check_params_for_shuffle()?;

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
            self.shuffle_clean_inplace(v, streams);
        }
        for k in keys.iter_mut() {
            self.shuffle_clean_inplace(k, streams);
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
