use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{cuda_backend_erc20_assign, PBSType};

impl CudaServerKey {
    pub fn unchecked_erc20_assign<T>(
        &self,
        from_amount: &mut T,
        to_amount: &mut T,
        amount: &T,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let num_blocks = amount.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_erc20_assign(
                        streams,
                        from_amount.as_mut(),
                        to_amount.as_mut(),
                        amount.as_ref(),
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
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_erc20_assign(
                        streams,
                        from_amount.as_mut(),
                        to_amount.as_mut(),
                        amount.as_ref(),
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
                        None,
                    );
                }
            }
        }
    }

    pub fn unchecked_erc20<T>(
        &self,
        from_amount: &T,
        to_amount: &T,
        amount: &T,
        streams: &CudaStreams,
    ) -> (T, T)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut from_amount = from_amount.duplicate(streams);
        let mut to_amount = to_amount.duplicate(streams);

        self.unchecked_erc20_assign(&mut from_amount, &mut to_amount, amount, streams);
        (from_amount, to_amount)
    }

    pub fn erc20<T>(
        &self,
        from_amount: &T,
        to_amount: &T,
        amount: &T,
        streams: &CudaStreams,
    ) -> (T, T)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_from_amount;
        let mut tmp_to_amount;

        let (from_amount, to_amount) = match (
            from_amount.block_carries_are_empty(),
            to_amount.block_carries_are_empty(),
        ) {
            (true, true) => (from_amount, to_amount),
            (true, false) => {
                tmp_to_amount = to_amount.duplicate(streams);
                self.full_propagate_assign(&mut tmp_to_amount, streams);
                (from_amount, &tmp_to_amount)
            }
            (false, true) => {
                tmp_from_amount = from_amount.duplicate(streams);
                self.full_propagate_assign(&mut tmp_from_amount, streams);
                (&tmp_from_amount, to_amount)
            }
            (false, false) => {
                tmp_to_amount = to_amount.duplicate(streams);
                tmp_from_amount = from_amount.duplicate(streams);
                self.full_propagate_assign(&mut tmp_from_amount, streams);
                self.full_propagate_assign(&mut tmp_to_amount, streams);
                (&tmp_from_amount, &tmp_to_amount)
            }
        };

        self.unchecked_erc20(from_amount, to_amount, amount, streams)
    }

    pub fn erc20_assign<T>(
        &self,
        from_amount: &mut T,
        to_amount: &mut T,
        amount: &T,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_from_amount;
        let mut tmp_to_amount;

        let (from_amount, to_amount) = match (
            from_amount.block_carries_are_empty(),
            to_amount.block_carries_are_empty(),
        ) {
            (true, true) => (from_amount, to_amount),
            (true, false) => {
                tmp_to_amount = to_amount.duplicate(streams);
                self.full_propagate_assign(&mut tmp_to_amount, streams);
                (from_amount, &mut tmp_to_amount)
            }
            (false, true) => {
                tmp_from_amount = from_amount.duplicate(streams);
                self.full_propagate_assign(&mut tmp_from_amount, streams);
                (&mut tmp_from_amount, to_amount)
            }
            (false, false) => {
                tmp_to_amount = to_amount.duplicate(streams);
                tmp_from_amount = from_amount.duplicate(streams);
                self.full_propagate_assign(&mut tmp_from_amount, streams);
                self.full_propagate_assign(&mut tmp_to_amount, streams);
                (&mut tmp_from_amount, &mut tmp_to_amount)
            }
        };

        self.unchecked_erc20_assign(from_amount, to_amount, amount, streams);
    }
}
