use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{unchecked_div_rem_integer_radix_kb_assign_async, PBSType};

impl CudaServerKey {
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_div_rem_assign_async<T>(
        &self,
        quotient: &mut T,
        remainder: &mut T,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        // TODO add asserts from `unchecked_div_rem_parallelized`
        let num_blocks = divisor.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    numerator.as_ref(),
                    divisor.as_ref(),
                    T::IS_SIGNED,
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    numerator.as_ref(),
                    divisor.as_ref(),
                    T::IS_SIGNED,
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
                    num_blocks,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        }
    }

    pub fn unchecked_div_rem_assign<T>(
        &self,
        quotient: &mut T,
        remainder: &mut T,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_div_rem_assign_async(quotient, remainder, numerator, divisor, streams);
        }
        streams.synchronize();
    }

    pub fn unchecked_div_rem<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> (T, T)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut quotient = numerator.duplicate(streams);
        let mut remainder = numerator.duplicate(streams);

        unsafe {
            self.unchecked_div_rem_assign_async(
                &mut quotient,
                &mut remainder,
                numerator,
                divisor,
                streams,
            );
        }
        streams.synchronize();
        (quotient, remainder)
    }

    pub fn div_rem<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> (T, T)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = divisor.duplicate(streams);
                unsafe { self.full_propagate_assign_async(&mut tmp_divisor, streams) };
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = numerator.duplicate(streams);
                unsafe { self.full_propagate_assign_async(&mut tmp_numerator, streams) };
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = divisor.duplicate(streams);
                tmp_numerator = numerator.duplicate(streams);
                unsafe { self.full_propagate_assign_async(&mut tmp_numerator, streams) };
                unsafe { self.full_propagate_assign_async(&mut tmp_divisor, streams) };
                (&tmp_numerator, &tmp_divisor)
            }
        };

        self.unchecked_div_rem(numerator, divisor, streams)
    }

    pub fn div_rem_assign<T>(
        &self,
        quotient: &mut T,
        remainder: &mut T,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = divisor.duplicate(streams);
                unsafe { self.full_propagate_assign_async(&mut tmp_divisor, streams) };
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = numerator.duplicate(streams);
                unsafe { self.full_propagate_assign_async(&mut tmp_numerator, streams) };
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = divisor.duplicate(streams);
                tmp_numerator = numerator.duplicate(streams);
                unsafe { self.full_propagate_assign_async(&mut tmp_numerator, streams) };
                unsafe { self.full_propagate_assign_async(&mut tmp_divisor, streams) };
                (&tmp_numerator, &tmp_divisor)
            }
        };

        unsafe {
            self.unchecked_div_rem_assign_async(quotient, remainder, numerator, divisor, streams);
        }
        streams.synchronize();
    }

    pub fn div<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let (q, _r) = self.div_rem(numerator, divisor, streams);
        q
    }

    pub fn rem<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let (_q, r) = self.div_rem(numerator, divisor, streams);
        r
    }
    pub fn div_assign<T>(&self, numerator: &mut T, divisor: &T, streams: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut remainder = numerator.duplicate(streams);
        self.div_rem_assign(
            numerator,
            &mut remainder,
            &numerator.duplicate(streams),
            divisor,
            streams,
        );
    }

    pub fn rem_assign<T>(&self, numerator: &mut T, divisor: &T, streams: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut quotient = numerator.duplicate(streams);
        self.div_rem_assign(
            &mut quotient,
            numerator,
            &numerator.duplicate(streams),
            divisor,
            streams,
        );
    }
}
