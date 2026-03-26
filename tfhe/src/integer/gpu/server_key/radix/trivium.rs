use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_backend_trivium_generate_keystream, cuda_backend_trivium_init, cuda_backend_trivium_step,
    PBSType,
};
use crate::shortint::parameters::LweBskGroupingFactor;

pub struct CudaTriviumState {
    pub a: CudaUnsignedRadixCiphertext, // 93 bits
    pub b: CudaUnsignedRadixCiphertext, // 84 bits
    pub c: CudaUnsignedRadixCiphertext, // 111 bits
}

impl CudaServerKey {
    /// Generates a Trivium keystream homomorphically on the GPU.
    ///
    /// # Arguments
    /// * `key` - The encrypted secret key.
    /// * `iv` - The encrypted initialization vector.
    /// * `num_steps` - The number of keystream bits to generate per input.
    /// * `streams` - The CUDA streams to use for execution.
    pub fn trivium_generate_keystream(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        let num_key_bits = 80;
        let num_iv_bits = 80;
        let batch_size = 64;

        if key.as_ref().d_blocks.lwe_ciphertext_count().0 != num_key_bits {
            return Err(format!(
                "Input key must contain {} encrypted bits, but contains {}",
                num_key_bits,
                key.as_ref().d_blocks.lwe_ciphertext_count().0
            )
            .into());
        }

        if iv.as_ref().d_blocks.lwe_ciphertext_count().0 != num_iv_bits {
            return Err(format!(
                "Input IV must contain {} encrypted bits, but contains {}",
                num_iv_bits,
                iv.as_ref().d_blocks.lwe_ciphertext_count().0
            )
            .into());
        }

        if !num_steps.is_multiple_of(batch_size) {
            return Err(format!(
                "The number of steps must be a multiple of {batch_size}, but is {num_steps}"
            )
            .into());
        }

        let num_output_bits = num_steps;
        let mut keystream: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_output_bits, streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_trivium_generate_keystream(
                        streams,
                        keystream.as_mut(),
                        key.as_ref(),
                        iv.as_ref(),
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        PBSType::Classical,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                        num_steps as u32,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_trivium_generate_keystream(
                        streams,
                        keystream.as_mut(),
                        key.as_ref(),
                        iv.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        PBSType::MultiBit,
                        None,
                        num_steps as u32,
                    );
                }
            }
        }
        Ok(keystream)
    }

    pub fn trivium_init(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> crate::Result<CudaTriviumState> {
        let num_key_bits = 80;
        let num_iv_bits = 80;

        if key.as_ref().d_blocks.lwe_ciphertext_count().0 != num_key_bits
            || iv.as_ref().d_blocks.lwe_ciphertext_count().0 != num_iv_bits
        {
            return Err("Input key and IV must contain 80 encrypted bits.".into());
        }

        let mut state = CudaTriviumState {
            a: self.create_trivial_zero_radix(93, streams),
            b: self.create_trivial_zero_radix(84, streams),
            c: self.create_trivial_zero_radix(111, streams),
        };

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_trivium_init(
                        streams,
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        key.as_ref(),
                        iv.as_ref(),
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        PBSType::Classical,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_trivium_init(
                        streams,
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        key.as_ref(),
                        iv.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        PBSType::MultiBit,
                        None,
                    );
                }
            }
        }
        Ok(state)
    }

    pub fn trivium_next(
        &self,
        state: &mut CudaTriviumState,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        let batch_size = 64;
        if !num_steps.is_multiple_of(batch_size) {
            return Err(format!("The number of steps must be a multiple of {batch_size}.").into());
        }

        let mut keystream: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_steps, streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_trivium_step(
                        streams,
                        keystream.as_mut(),
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        num_steps as u32,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        PBSType::Classical,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_trivium_step(
                        streams,
                        keystream.as_mut(),
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        num_steps as u32,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        PBSType::MultiBit,
                        None,
                    );
                }
            }
        }
        Ok(keystream)
    }
}
