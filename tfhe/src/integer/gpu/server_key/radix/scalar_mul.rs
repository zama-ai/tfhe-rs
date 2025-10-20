use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu, cuda_backend_get_scalar_mul_size_on_gpu,
    cuda_backend_unchecked_scalar_mul, PBSType,
};
use crate::integer::server_key::ScalarMultiplier;
use crate::prelude::CastInto;
use itertools::Itertools;

impl CudaServerKey {
    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.unchecked_scalar_mul(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn unchecked_scalar_mul<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_mul_assign(&mut result, scalar, streams);
        result
    }

    pub fn unchecked_scalar_mul_assign<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if scalar == Scalar::ZERO {
            ct.as_mut().d_blocks.0.d_vec.memset(0, streams, 0);
            return;
        }

        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0;
        if scalar == Scalar::ONE || num_blocks == 0 {
            return;
        }

        if scalar.is_power_of_two() {
            // Shifting cost one bivariate PBS so its always faster
            // than multiplying
            self.unchecked_scalar_left_shift_assign(ct, scalar.ilog2() as u64, streams);
            return;
        }
        let msg_bits = self.message_modulus.0.ilog2() as usize;
        let decomposer = BlockDecomposer::with_early_stop_at_zero(scalar, 1).iter_as::<u8>();

        // We don't want to compute shifts if we are not going to use the
        // resulting value
        let mut has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                has_at_least_one_set[i % msg_bits] = 1;
            }
        }

        let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(scalar, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        if decomposed_scalar.is_empty() {
            return;
        }

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_scalar_mul(
                        streams,
                        ct.as_mut(),
                        decomposed_scalar.as_slice(),
                        has_at_least_one_set.as_slice(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_bsk.decomp_base_log,
                        d_bsk.decomp_level_count,
                        self.key_switching_key.decomposition_base_log(),
                        self.key_switching_key.decomposition_level_count(),
                        decomposed_scalar.len() as u32,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_scalar_mul(
                        streams,
                        ct.as_mut(),
                        decomposed_scalar.as_slice(),
                        has_at_least_one_set.as_slice(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.decomp_level_count,
                        self.key_switching_key.decomposition_base_log(),
                        self.key_switching_key.decomposition_level_count(),
                        decomposed_scalar.len() as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.scalar_mul(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn scalar_mul<Scalar, T>(&self, ct: &T, scalar: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_mul_assign(&mut result, scalar, streams);
        result
    }

    pub fn scalar_mul_assign<Scalar, T>(&self, ct: &mut T, scalar: Scalar, streams: &CudaStreams)
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_scalar_mul_assign(ct, scalar, streams);
    }

    pub fn get_scalar_mul_size_on_gpu<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        if scalar == Scalar::ZERO {
            return 0;
        }

        if scalar == Scalar::ONE || lwe_ciphertext_count.0 == 0 {
            return 0;
        }

        if scalar.is_power_of_two() {
            // Shifting cost one bivariate PBS so its always faster
            // than multiplying
            return self.get_scalar_left_shift_size_on_gpu(ct, streams);
        }

        let full_prop_mem = if ct.block_carries_are_empty() {
            0
        } else {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_get_full_propagate_assign_size_on_gpu(
                        streams,
                        d_bsk.input_lwe_dimension(),
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count(),
                        d_bsk.decomp_base_log(),
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    )
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_get_full_propagate_assign_size_on_gpu(
                        streams,
                        d_multibit_bsk.input_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count(),
                        d_multibit_bsk.decomp_base_log(),
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    )
                }
            }
        };

        let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(scalar, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        if decomposed_scalar.is_empty() {
            return 0;
        }
        let scalar_mul_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_scalar_mul_size_on_gpu(
                streams,
                decomposed_scalar.as_slice(),
                self.message_modulus,
                self.carry_modulus,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                self.key_switching_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                d_bsk.decomp_base_log,
                d_bsk.decomp_level_count,
                self.key_switching_key.decomposition_base_log(),
                self.key_switching_key.decomposition_level_count(),
                lwe_ciphertext_count.0 as u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_scalar_mul_size_on_gpu(
                    streams,
                    decomposed_scalar.as_slice(),
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        full_prop_mem.max(scalar_mul_mem)
    }
}
