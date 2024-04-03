use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

impl CudaServerKey {

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unsigned_unchecked_div_rem_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        quotient: &mut T,
        remainder: &mut T,
        numerator: &T,
        divisor: &T,
        stream: &CudaStream,
    ) {
        // TODO add asserts from `unsigned_unchecked_div_rem_parallelized`
        let num_blocks = divisor.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_unsigned_div_rem_integer_radix_classic_kb_assign_async(
                    &mut quotient.as_mut().d_blocks.0.d_vec,
                    &mut remainder.as_mut().d_blocks.0.d_vec,
                    &numerator.as_ref().d_blocks.0.d_vec,
                    &divisor.as_ref().d_blocks.0.d_vec,
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
                    num_blocks,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_unsigned_div_rem_integer_radix_multibit_kb_assign_async(
                    &mut quotient.as_mut().d_blocks.0.d_vec,
                    &mut remainder.as_mut().d_blocks.0.d_vec,
                    &numerator.as_ref().d_blocks.0.d_vec,
                    &divisor.as_ref().d_blocks.0.d_vec,
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
                    num_blocks,
                );
            }
        };

        // TODO write info update for div_rem
        quotient.as_mut().info = quotient.as_ref().info.after_mul();
        remainder.as_mut().info = remainder.as_ref().info.after_mul();
    }

    pub fn unsigned_unchecked_div_rem<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        divisor: &T,
        stream: &CudaStream,
    ) -> (T, T) {
        let mut quotient = unsafe { numerator.duplicate_async(stream) };
        let mut remainder = unsafe { numerator.duplicate_async(stream) };

        unsafe {
            self.unsigned_unchecked_div_rem_assign_async(&mut quotient, &mut remainder, numerator, divisor, stream);
        }
        (quotient, remainder)
    }

    pub fn unchecked_div_rem<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        divisor: &T,
        stream: &CudaStream,
    ) -> (T, T) {
        //TODO signed operation, now it is only unsigned
        self.unsigned_unchecked_div_rem(numerator, divisor, stream)
    }

    pub fn div_rem<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        divisor: &T,
        stream: &CudaStream,
    ) -> (T, T) {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = unsafe {divisor.duplicate_async(stream) };
                unsafe {self.full_propagate_assign_async(&mut tmp_divisor, stream) };
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = unsafe {numerator.duplicate_async(stream) };
                unsafe { self.full_propagate_assign_async(&mut tmp_numerator, stream) };
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = unsafe { divisor.duplicate_async(stream) };
                tmp_numerator = unsafe {numerator.duplicate_async(stream) };
                unsafe {
                    self.full_propagate_assign_async(&mut tmp_numerator, stream);
                    self.full_propagate_assign_async(&mut tmp_divisor, stream);
                }
                (&tmp_numerator, &tmp_divisor)
            }
        };

        self.unchecked_div_rem(numerator, divisor, stream)
    }

    pub fn div<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        divisor: &T,
        stream: &CudaStream,
    ) -> T {
        let (q, _r) = self.div_rem(numerator, divisor, stream);
        q
    }

}
