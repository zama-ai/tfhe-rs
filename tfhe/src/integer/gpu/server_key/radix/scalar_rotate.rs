use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CastFrom, UnsignedNumeric};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaDynamicKeyswitchingKey;
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_get_scalar_rotate_left_size_on_gpu,
    cuda_backend_unchecked_scalar_rotate_left_assign,
    cuda_backend_unchecked_scalar_rotate_right_assign, get_scalar_rotate_right_size_on_gpu,
    CudaServerKey,
};
use crate::integer::server_key::radix_parallel::scalar_rotate::reduce_scalar_rotate_amount;
use std::ops::Rem;

impl CudaServerKey {
    pub fn unchecked_scalar_rotate_left<Scalar, T>(
        &self,
        ct: &T,
        n: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
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
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let total_num_bits = lwe_ciphertext_count.0 as u64 * self.message_modulus.0.ilog2() as u64;
        // Reduce before the u32 cast, which would otherwise truncate large amounts
        let n = reduce_scalar_rotate_amount(n, total_num_bits) as u32;
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            assert_eq!(
                computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.input_lwe_dimension(),
                "KS key output LWE dimension mismatch with BSK input LWE dimension"
            );
            assert_eq!(
                computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.output_lwe_dimension(),
                "KS key input LWE dimension mismatch with BSK big LWE dimension"
            );
            cuda_backend_unchecked_scalar_rotate_left_assign(
                stream,
                ct.as_mut(),
                n,
                &computing_ks_key.d_vec,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                lwe_ciphertext_count.0 as u32,
            );
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
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
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
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let total_num_bits = lwe_ciphertext_count.0 as u64 * self.message_modulus.0.ilog2() as u64;
        // Reduce before the u32 cast, which would otherwise truncate large amounts
        let n = reduce_scalar_rotate_amount(n, total_num_bits) as u32;
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            assert_eq!(
                computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.input_lwe_dimension(),
                "KS key output LWE dimension mismatch with BSK input LWE dimension"
            );
            assert_eq!(
                computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.output_lwe_dimension(),
                "KS key input LWE dimension mismatch with BSK big LWE dimension"
            );
            cuda_backend_unchecked_scalar_rotate_right_assign(
                stream,
                ct.as_mut(),
                n,
                &computing_ks_key.d_vec,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                lwe_ciphertext_count.0 as u32,
            );
        }
    }

    pub fn scalar_rotate_left_assign<Scalar, T>(&self, ct: &mut T, n: Scalar, stream: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, stream);
        }

        self.unchecked_scalar_rotate_left_assign(ct, n, stream);
    }

    pub fn scalar_rotate_right_assign<Scalar, T>(&self, ct: &mut T, n: Scalar, stream: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, stream);
        }

        self.unchecked_scalar_rotate_right_assign(ct, n, stream);
    }

    pub fn scalar_rotate_left<Scalar, T>(&self, ct: &T, shift: Scalar, stream: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
    {
        let mut result = ct.duplicate(stream);
        self.scalar_rotate_left_assign(&mut result, shift, stream);
        result
    }

    pub fn scalar_rotate_right<Scalar, T>(&self, ct: &T, shift: Scalar, stream: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: UnsignedNumeric + CastFrom<u64> + Rem<Scalar, Output = Scalar>,
        u64: CastFrom<Scalar>,
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
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let full_prop_mem = if ct.block_carries_are_empty() {
            0
        } else {
            cuda_backend_get_full_propagate_assign_size_on_gpu(
                streams,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                self.message_modulus,
                self.carry_modulus,
            )
        };
        assert_eq!(
            computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.input_lwe_dimension(),
            "KS key output LWE dimension mismatch with BSK input LWE dimension"
        );
        assert_eq!(
            computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.output_lwe_dimension(),
            "KS key input LWE dimension mismatch with BSK big LWE dimension"
        );
        let scalar_shift_mem = cuda_backend_get_scalar_rotate_left_size_on_gpu(
            streams,
            self.message_modulus,
            self.carry_modulus,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            lwe_ciphertext_count.0 as u32,
        );
        full_prop_mem.max(scalar_shift_mem)
    }

    pub fn get_scalar_rotate_right_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let full_prop_mem = if ct.block_carries_are_empty() {
            0
        } else {
            cuda_backend_get_full_propagate_assign_size_on_gpu(
                streams,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                self.message_modulus,
                self.carry_modulus,
            )
        };
        assert_eq!(
            computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.input_lwe_dimension(),
            "KS key output LWE dimension mismatch with BSK input LWE dimension"
        );
        assert_eq!(
            computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.output_lwe_dimension(),
            "KS key input LWE dimension mismatch with BSK big LWE dimension"
        );
        let scalar_shift_mem = get_scalar_rotate_right_size_on_gpu(
            streams,
            self.message_modulus,
            self.carry_modulus,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            lwe_ciphertext_count.0 as u32,
        );
        full_prop_mem.max(scalar_shift_mem)
    }
}
