use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::transciphering::{CudaFheKeyStream, CudaIntegerTranscipherer};
use crate::integer::gpu::{cuda_backend_kreyvium_init, cuda_backend_kreyvium_step};

const KREYVIUM_KEY_BITS: usize = 128;
const KREYVIUM_IV_BITS: usize = 128;
const REGISTER_A_BITS: usize = 93;
const REGISTER_B_BITS: usize = 84;
const REGISTER_C_BITS: usize = 111;
const BATCH_SIZE: usize = 64;

pub struct CudaKreyviumState {
    pub a: CudaUnsignedRadixCiphertext,  // REGISTER_A_BITS
    pub b: CudaUnsignedRadixCiphertext,  // REGISTER_B_BITS
    pub c: CudaUnsignedRadixCiphertext,  // REGISTER_C_BITS
    pub k: CudaUnsignedRadixCiphertext,  // KREYVIUM_KEY_BITS
    pub iv: CudaUnsignedRadixCiphertext, // KREYVIUM_IV_BITS
    pub k_offset: u32,
    pub iv_offset: u32,
}

impl CudaServerKey {
    // Generates a Kreyvium keystream in a single call.
    // Initializes a transient state, runs the warmup, generates the keystream,
    // then drops the state.
    pub fn kreyvium_generate_keystream(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        let mut state = self.kreyvium_init(key, iv, streams)?;
        self.kreyvium_next(&mut state, num_steps, streams)
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
        if key.as_ref().d_blocks.lwe_ciphertext_count().0 != KREYVIUM_KEY_BITS
            || iv.as_ref().d_blocks.lwe_ciphertext_count().0 != KREYVIUM_IV_BITS
        {
            return Err(format!(
                "Input key must contain {KREYVIUM_KEY_BITS} and IV must contain {KREYVIUM_IV_BITS} encrypted bits."
            ).into());
        }

        let mut state = CudaKreyviumState {
            a: self.create_trivial_zero_radix(REGISTER_A_BITS, streams),
            b: self.create_trivial_zero_radix(REGISTER_B_BITS, streams),
            c: self.create_trivial_zero_radix(REGISTER_C_BITS, streams),
            k: self.create_trivial_zero_radix(KREYVIUM_KEY_BITS, streams),
            iv: self.create_trivial_zero_radix(KREYVIUM_IV_BITS, streams),
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
                        d_bsk,
                        computing_ks_key.params_ffi(),
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
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
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
                        d_bsk,
                        computing_ks_key.params_ffi(),
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
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        None,
                    );
                }
            }
        }
        Ok(keystream)
    }
}

/// Stateful FHE-side Kreyvium session on GPU, implementing
/// [`CudaIntegerTranscipherer`].
pub struct CudaKreyviumStream {
    state: CudaKreyviumState,
    counter: u64,
}

impl CudaKreyviumStream {
    pub fn new(
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> crate::Result<Self> {
        let state = sks.kreyvium_init(key, iv, streams)?;
        Ok(Self { state, counter: 0 })
    }
}

impl CudaIntegerTranscipherer for CudaKreyviumStream {
    fn next_keystream_bits(
        &mut self,
        sks: &CudaServerKey,
        n_bits: usize,
        streams: &CudaStreams,
    ) -> CudaFheKeyStream {
        assert!(
            n_bits.is_multiple_of(BATCH_SIZE),
            "GPU Kreyvium requires n_bits to be a multiple of {BATCH_SIZE} (got {n_bits})"
        );
        let keystream = sks.kreyvium_next(&mut self.state, n_bits, streams).unwrap();
        self.counter += n_bits as u64;
        CudaFheKeyStream::from_raw_parts(keystream)
    }

    fn trans_cipher_signed_radix(
        &mut self,
        _sks: &CudaServerKey,
        _input_stream: &[u8],
        _streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext {
        unimplemented!("trans_cipher_signed_radix is not yet implemented for GPU Kreyvium")
    }

    fn skip(&mut self, sks: &CudaServerKey, n_bits: usize, streams: &CudaStreams) {
        assert!(
            n_bits.is_multiple_of(BATCH_SIZE),
            "GPU Kreyvium requires n_bits to be a multiple of {BATCH_SIZE} (got {n_bits})"
        );
        let _ = sks.kreyvium_next(&mut self.state, n_bits, streams).unwrap();
        self.counter += n_bits as u64;
    }

    fn current_counter(&self) -> u64 {
        self.counter
    }
}
