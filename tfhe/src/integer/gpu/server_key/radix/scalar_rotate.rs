use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CastFrom, LweBskGroupingFactor};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_get_scalar_rotate_left_size_on_gpu,
    cuda_backend_unchecked_scalar_rotate_left_assign,
    cuda_backend_unchecked_scalar_rotate_right_assign, get_scalar_rotate_right_size_on_gpu,
    CudaServerKey, PBSType,
};

impl CudaServerKey {
    pub fn unchecked_scalar_rotate_left<Scalar, T>(
        &self,
        ct: &T,
        n: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        let mut result = ct.duplicate(stream);
        self.unchecked_scalar_rotate_left_assign(&mut result, n, stream);
        result
    }

    pub fn unchecked_scalar_rotate_left_assign<Scalar, T>(
        &self,
        ct: &mut T,
        n: Scalar,
        stream: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_scalar_rotate_left_assign(
                        stream,
                        ct.as_mut(),
                        u32::cast_from(n),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        lwe_ciphertext_count.0 as u32,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_scalar_rotate_left_assign(
                        stream,
                        ct.as_mut(),
                        u32::cast_from(n),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    pub fn unchecked_scalar_rotate_right<Scalar, T>(
        &self,
        ct: &T,
        n: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        let mut result = ct.duplicate(stream);
        self.unchecked_scalar_rotate_right_assign(&mut result, n, stream);
        result
    }

    pub fn unchecked_scalar_rotate_right_assign<Scalar, T>(
        &self,
        ct: &mut T,
        n: Scalar,
        stream: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_scalar_rotate_right_assign(
                        stream,
                        ct.as_mut(),
                        u32::cast_from(n),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        lwe_ciphertext_count.0 as u32,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_scalar_rotate_right_assign(
                        stream,
                        ct.as_mut(),
                        u32::cast_from(n),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    pub fn scalar_rotate_left_assign<Scalar, T>(&self, ct: &mut T, n: Scalar, stream: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, stream);
        }

        self.unchecked_scalar_rotate_left_assign(ct, n, stream);
    }

    pub fn scalar_rotate_right_assign<Scalar, T>(&self, ct: &mut T, n: Scalar, stream: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, stream);
        }

        self.unchecked_scalar_rotate_right_assign(ct, n, stream);
    }

    pub fn scalar_rotate_left<Scalar, T>(&self, ct: &T, shift: Scalar, stream: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        let mut result = ct.duplicate(stream);
        self.scalar_rotate_left_assign(&mut result, shift, stream);
        result
    }

    pub fn scalar_rotate_right<Scalar, T>(&self, ct: &T, shift: Scalar, stream: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
    {
        let mut result = ct.duplicate(stream);
        self.scalar_rotate_right_assign(&mut result, shift, stream);
        result
    }
    pub fn get_scalar_rotate_left_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

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
        let scalar_shift_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                cuda_backend_get_scalar_rotate_left_size_on_gpu(
                    streams,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    lwe_ciphertext_count.0 as u32,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    d_bsk.ms_noise_reduction_configuration.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_scalar_rotate_left_size_on_gpu(
                    streams,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        full_prop_mem.max(scalar_shift_mem)
    }

    pub fn get_scalar_rotate_right_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

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
        let scalar_shift_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_scalar_rotate_right_size_on_gpu(
                streams,
                self.message_modulus,
                self.carry_modulus,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                self.key_switching_key
                    .input_key_lwe_size()
                    .to_lwe_dimension(),
                self.key_switching_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                self.key_switching_key.decomposition_level_count(),
                self.key_switching_key.decomposition_base_log(),
                d_bsk.decomp_level_count,
                d_bsk.decomp_base_log,
                lwe_ciphertext_count.0 as u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => get_scalar_rotate_right_size_on_gpu(
                streams,
                self.message_modulus,
                self.carry_modulus,
                d_multibit_bsk.glwe_dimension,
                d_multibit_bsk.polynomial_size,
                self.key_switching_key
                    .input_key_lwe_size()
                    .to_lwe_dimension(),
                self.key_switching_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                self.key_switching_key.decomposition_level_count(),
                self.key_switching_key.decomposition_base_log(),
                d_multibit_bsk.decomp_level_count,
                d_multibit_bsk.decomp_base_log,
                lwe_ciphertext_count.0 as u32,
                PBSType::MultiBit,
                d_multibit_bsk.grouping_factor,
                None,
            ),
        };
        full_prop_mem.max(scalar_shift_mem)
    }
}
