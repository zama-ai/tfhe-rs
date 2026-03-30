use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_backend_kreyvium_generate_keystream, cuda_backend_kreyvium_init,
    cuda_backend_kreyvium_step, PBSType,
};
use crate::shortint::parameters::LweBskGroupingFactor;

pub struct CudaKreyviumState {
    pub a: CudaUnsignedRadixCiphertext,  // 93 bits
    pub b: CudaUnsignedRadixCiphertext,  // 84 bits
    pub c: CudaUnsignedRadixCiphertext,  // 111 bits
    pub k: CudaUnsignedRadixCiphertext,  // 128 bits
    pub iv: CudaUnsignedRadixCiphertext, // 128 bits
    pub k_offset: u32,
    pub iv_offset: u32,
}

impl CudaServerKey {
    // Generates a Kreyvium keystream in a single, monolithic call.
    // It handles the initialization, the warmup phase, and the keystream generation,
    // discarding the internal state once finished.
    //
    pub fn kreyvium_generate_keystream(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        let num_key_bits = 128;
        let num_iv_bits = 128;
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
                    cuda_backend_kreyvium_generate_keystream(
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
                    cuda_backend_kreyvium_generate_keystream(
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

    // Initializes the Kreyvium state for stateful keystream generation.
    // It loads the key and IV, executes the warmup steps, and returns the persistent state.
    //
    pub fn kreyvium_init(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> crate::Result<CudaKreyviumState> {
        if key.as_ref().d_blocks.lwe_ciphertext_count().0 != 128
            || iv.as_ref().d_blocks.lwe_ciphertext_count().0 != 128
        {
            return Err("Input key and IV must contain 128 encrypted bits.".into());
        }

        let mut state = CudaKreyviumState {
            a: self.create_trivial_zero_radix(93, streams),
            b: self.create_trivial_zero_radix(84, streams),
            c: self.create_trivial_zero_radix(111, streams),
            k: self.create_trivial_zero_radix(128, streams),
            iv: self.create_trivial_zero_radix(128, streams),
            k_offset: 0,
            iv_offset: 0,
        };

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_kreyvium_init(
                        streams,
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        state.k.as_mut(),
                        state.iv.as_mut(),
                        &mut state.k_offset,
                        &mut state.iv_offset,
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
                    cuda_backend_kreyvium_init(
                        streams,
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        state.k.as_mut(),
                        state.iv.as_mut(),
                        &mut state.k_offset,
                        &mut state.iv_offset,
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

    // Generates the next chunk of keystream bits from an existing Kreyvium state.
    // Updates the state in place, allowing consecutive calls to produce a continuous stream.
    //
    pub fn kreyvium_next(
        &self,
        state: &mut CudaKreyviumState,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        if !num_steps.is_multiple_of(64) {
            return Err("The number of steps must be a multiple of 64.".into());
        }
        let mut keystream: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_steps, streams);
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_kreyvium_step(
                        streams,
                        keystream.as_mut(),
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        state.k.as_mut(),
                        state.iv.as_mut(),
                        &mut state.k_offset,
                        &mut state.iv_offset,
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
                    cuda_backend_kreyvium_step(
                        streams,
                        keystream.as_mut(),
                        state.a.as_mut(),
                        state.b.as_mut(),
                        state.c.as_mut(),
                        state.k.as_mut(),
                        state.iv.as_mut(),
                        &mut state.k_offset,
                        &mut state.iv_offset,
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
