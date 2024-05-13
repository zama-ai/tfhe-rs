use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{unchecked_unsigned_div_rem_integer_radix_kb_assign_async, PBSType};

impl CudaServerKey {
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unsigned_unchecked_div_rem_assign_async(
        &self,
        quotient: &mut CudaUnsignedRadixCiphertext,
        remainder: &mut CudaUnsignedRadixCiphertext,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) {
        // TODO add asserts from `unsigned_unchecked_div_rem_parallelized`
        let num_blocks = divisor.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_unsigned_div_rem_integer_radix_kb_assign_async(
                    streams,
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_unsigned_div_rem_integer_radix_kb_assign_async(
                    streams,
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
                    num_blocks,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        };

        quotient.as_mut().info = quotient.as_ref().info.after_div_rem();
        remainder.as_mut().info = remainder.as_ref().info.after_div_rem();
    }

    pub fn unsigned_unchecked_div_rem_assign(
        &self,
        quotient: &mut CudaUnsignedRadixCiphertext,
        remainder: &mut CudaUnsignedRadixCiphertext,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.unsigned_unchecked_div_rem_assign_async(
                quotient, remainder, numerator, divisor, streams,
            );
        }
        streams.synchronize();
    }

    pub fn unchecked_div_rem(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext) {
        let mut quotient = unsafe { numerator.duplicate_async(streams) };
        let mut remainder = unsafe { numerator.duplicate_async(streams) };

        unsafe {
            self.unsigned_unchecked_div_rem_assign_async(
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

    pub fn div_rem(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext) {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = unsafe { divisor.duplicate_async(streams) };
                unsafe { self.full_propagate_assign_async(&mut tmp_divisor, streams) };
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = unsafe { numerator.duplicate_async(streams) };
                unsafe { self.full_propagate_assign_async(&mut tmp_numerator, streams) };
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = unsafe { divisor.duplicate_async(streams) };
                tmp_numerator = unsafe { numerator.duplicate_async(streams) };
                unsafe {
                    self.full_propagate_assign_async(&mut tmp_numerator, streams);
                    self.full_propagate_assign_async(&mut tmp_divisor, streams);
                }
                (&tmp_numerator, &tmp_divisor)
            }
        };

        self.unchecked_div_rem(numerator, divisor, streams)
    }

    pub fn div_rem_assign(
        &self,
        quotient: &mut CudaUnsignedRadixCiphertext,
        remainder: &mut CudaUnsignedRadixCiphertext,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = unsafe { divisor.duplicate_async(streams) };
                unsafe { self.full_propagate_assign_async(&mut tmp_divisor, streams) };
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = unsafe { numerator.duplicate_async(streams) };
                unsafe { self.full_propagate_assign_async(&mut tmp_numerator, streams) };
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = unsafe { divisor.duplicate_async(streams) };
                tmp_numerator = unsafe { numerator.duplicate_async(streams) };
                unsafe {
                    self.full_propagate_assign_async(&mut tmp_numerator, streams);
                    self.full_propagate_assign_async(&mut tmp_divisor, streams);
                }
                (&tmp_numerator, &tmp_divisor)
            }
        };

        unsafe {
            self.unsigned_unchecked_div_rem_assign_async(
                quotient, remainder, numerator, divisor, streams,
            );
        }
        streams.synchronize();
    }

    pub fn div(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let (q, _r) = self.div_rem(numerator, divisor, streams);
        q
    }

    pub fn rem(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let (_q, r) = self.div_rem(numerator, divisor, streams);
        r
    }
    pub fn div_assign(
        &self,
        numerator: &mut CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) {
        let mut remainder = numerator.duplicate(streams);
        self.div_rem_assign(
            numerator,
            &mut remainder,
            &numerator.duplicate(streams),
            divisor,
            streams,
        );
    }

    pub fn rem_assign(
        &self,
        numerator: &mut CudaUnsignedRadixCiphertext,
        divisor: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) {
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
