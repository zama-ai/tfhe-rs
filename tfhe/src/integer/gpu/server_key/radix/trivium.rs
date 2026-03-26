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

const TRIVIUM_KEY_BITS: usize = 80;
const TRIVIUM_IV_BITS: usize = 80;
const REGISTER_A_BITS: usize = 93;
const REGISTER_B_BITS: usize = 84;
const REGISTER_C_BITS: usize = 111;
const BATCH_SIZE: usize = 64;

pub struct CudaTriviumState {
    pub a: CudaUnsignedRadixCiphertext, // REGISTER_A_BITS
    pub b: CudaUnsignedRadixCiphertext, // REGISTER_B_BITS
    pub c: CudaUnsignedRadixCiphertext, // REGISTER_C_BITS
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
        if key.as_ref().d_blocks.lwe_ciphertext_count().0 != TRIVIUM_KEY_BITS {
            return Err(format!(
                "Input key must contain {} encrypted bits, but contains {}",
                TRIVIUM_KEY_BITS,
                key.as_ref().d_blocks.lwe_ciphertext_count().0
            )
            .into());
        }

        if iv.as_ref().d_blocks.lwe_ciphertext_count().0 != TRIVIUM_IV_BITS {
            return Err(format!(
                "Input IV must contain {} encrypted bits, but contains {}",
                TRIVIUM_IV_BITS,
                iv.as_ref().d_blocks.lwe_ciphertext_count().0
            )
            .into());
        }

        if !num_steps.is_multiple_of(BATCH_SIZE) {
            return Err(format!(
                "The number of steps must be a multiple of {BATCH_SIZE}, but is {num_steps}"
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
        if key.as_ref().d_blocks.lwe_ciphertext_count().0 != TRIVIUM_KEY_BITS
            || iv.as_ref().d_blocks.lwe_ciphertext_count().0 != TRIVIUM_IV_BITS
        {
            return Err(format!(
                "Input key must contain {TRIVIUM_KEY_BITS} and IV must contain {TRIVIUM_IV_BITS} encrypted bits."
            ).into());
        }

        let mut state = CudaTriviumState {
            a: self.create_trivial_zero_radix(REGISTER_A_BITS, streams),
            b: self.create_trivial_zero_radix(REGISTER_B_BITS, streams),
            c: self.create_trivial_zero_radix(REGISTER_C_BITS, streams),
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
        if !num_steps.is_multiple_of(BATCH_SIZE) {
            return Err(format!("The number of steps must be a multiple of {BATCH_SIZE}.").into());
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
