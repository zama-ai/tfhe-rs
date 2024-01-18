use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::CastFrom;
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::CudaServerKey;
use std::ops::Rem;

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_rotate_left_async<T>(
        &self,
        ct: &CudaRadixCiphertext,
        n: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u32>,
        u32: CastFrom<T>,
    {
        let mut result = ct.duplicate_async(stream);
        self.unchecked_scalar_rotate_left_assign_async(&mut result, n, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_rotate_left_assign_async<T>(
        &self,
        ct: &mut CudaRadixCiphertext,
        n: T,
        stream: &CudaStream,
    ) where
        T: Rem<T, Output = T> + CastFrom<u32>,
        u32: CastFrom<T>,
    {
        let lwe_ciphertext_count = ct.d_blocks.lwe_ciphertext_count();
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_scalar_rotate_left_integer_radix_classic_kb_assign_async(
                    &mut ct.d_blocks.0.d_vec,
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
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_scalar_rotate_left_integer_radix_multibit_kb_assign_async(
                    &mut ct.d_blocks.0.d_vec,
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
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                );
            }
        }
    }

    pub fn unchecked_scalar_left_rotate<T>(
        &self,
        ct: &CudaRadixCiphertext,
        n: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u32>,
        u32: CastFrom<T>,
    {
        let result = unsafe { self.unchecked_scalar_rotate_left_async(ct, n, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_rotate_right_async<T>(
        &self,
        ct: &CudaRadixCiphertext,
        n: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u32>,
        u32: CastFrom<T>,
    {
        let mut result = ct.duplicate_async(stream);
        self.unchecked_scalar_rotate_right_assign_async(&mut result, n, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_rotate_right_assign_async<T>(
        &self,
        ct: &mut CudaRadixCiphertext,
        n: T,
        stream: &CudaStream,
    ) where
        T: Rem<T, Output = T> + CastFrom<u32>,
        u32: CastFrom<T>,
    {
        let lwe_ciphertext_count = ct.d_blocks.lwe_ciphertext_count();
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_scalar_rotate_right_integer_radix_classic_kb_assign_async(
                    &mut ct.d_blocks.0.d_vec,
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
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_scalar_rotate_right_integer_radix_multibit_kb_assign_async(
                    &mut ct.d_blocks.0.d_vec,
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
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                );
            }
        }
    }

    pub fn unchecked_scalar_right_rotate<T>(
        &self,
        ct: &CudaRadixCiphertext,
        n: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u32>,
        u32: CastFrom<T>,
    {
        let result = unsafe { self.unchecked_scalar_rotate_right_async(ct, n, stream) };
        stream.synchronize();
        result
    }
}
