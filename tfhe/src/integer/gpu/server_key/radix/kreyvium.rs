use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_backend_fast_kreyvium_init, cuda_backend_fast_kreyvium_step, cuda_backend_kreyvium_init,
    cuda_backend_kreyvium_step,
};

pub(crate) const KREYVIUM_KEY_BITS: usize = 128;
pub(crate) const KREYVIUM_IV_BITS: usize = 128;
pub(crate) const REGISTER_A_BITS: usize = 93;
pub(crate) const REGISTER_B_BITS: usize = 84;
pub(crate) const REGISTER_C_BITS: usize = 111;
pub(crate) const BATCH_SIZE: usize = 64;

/// State for one or more Kreyvium keystreams generated in parallel.
///
/// A single call can drive `num_inputs` independent (key, iv) lanes at once. The CUDA kernels store
/// every register bit-sliced across lanes: for a logical bit position `i`, the `num_inputs` lanes'
/// copies of that bit occupy contiguous blocks `[i * num_inputs, (i + 1) * num_inputs)`. The
/// a/b/c/k/iv registers are therefore sized `REGISTER_*_BITS * num_inputs`, and the FFI layer
/// recovers `num_inputs` from the register block counts. The keystream produced by `kreyvium_next`
/// follows the same layout: step `s` of lane `j` lands at block `s * num_inputs + j`.
pub struct CudaKreyviumState {
    pub a: CudaUnsignedRadixCiphertext, // REGISTER_A_BITS * num_inputs
    pub b: CudaUnsignedRadixCiphertext, // REGISTER_B_BITS * num_inputs
    pub c: CudaUnsignedRadixCiphertext, // REGISTER_C_BITS * num_inputs
    pub k: CudaUnsignedRadixCiphertext, // KREYVIUM_KEY_BITS * num_inputs
    pub iv: CudaUnsignedRadixCiphertext, // KREYVIUM_IV_BITS * num_inputs
    pub k_offset: u32,
    pub iv_offset: u32,
    pub num_inputs: usize,
}

/// Selects which set of CUDA kernels the shared init/next helpers drive.
///
/// Both variants share the register layout and the [`CudaKreyviumState`] type; they differ only in
/// the encoding the keystream loop uses (the original 2_2 Kreyvium kernels vs the FastKreyvium
/// Z4 single-bit-extraction kernels). The variant is matched inside each `bootstrapping_key` arm
/// to pick the concrete `extern` symbol, because those symbols are generic over the bootstrapping
/// key element type and cannot be unified into a single function pointer across the Classic and
/// MultiBit arms.
#[derive(Clone, Copy)]
enum KreyviumVariant {
    Kreyvium,
    Fast,
}

impl CudaServerKey {
    fn kreyvium_init_impl(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
        variant: KreyviumVariant,
    ) -> crate::Result<CudaKreyviumState> {
        let key_bits = key.as_ref().d_blocks.lwe_ciphertext_count().0;
        let iv_bits = iv.as_ref().d_blocks.lwe_ciphertext_count().0;
        if key_bits == 0
            || !key_bits.is_multiple_of(KREYVIUM_KEY_BITS)
            || iv_bits != key_bits / KREYVIUM_KEY_BITS * KREYVIUM_IV_BITS
        {
            return Err(format!(
                "Input key must contain a non-zero multiple of {KREYVIUM_KEY_BITS} encrypted bits \
                 and IV must contain {KREYVIUM_IV_BITS} bits per key lane, got key_bits={key_bits}, \
                 iv_bits={iv_bits}."
            )
            .into());
        }
        let num_inputs = key_bits / KREYVIUM_KEY_BITS;

        let mut state = CudaKreyviumState {
            a: self.create_trivial_zero_radix(REGISTER_A_BITS * num_inputs, streams),
            b: self.create_trivial_zero_radix(REGISTER_B_BITS * num_inputs, streams),
            c: self.create_trivial_zero_radix(REGISTER_C_BITS * num_inputs, streams),
            k: self.create_trivial_zero_radix(KREYVIUM_KEY_BITS * num_inputs, streams),
            iv: self.create_trivial_zero_radix(KREYVIUM_IV_BITS * num_inputs, streams),
            k_offset: 0,
            iv_offset: 0,
            num_inputs,
        };

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => match variant {
                    KreyviumVariant::Kreyvium => cuda_backend_kreyvium_init(
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
                    ),
                    KreyviumVariant::Fast => cuda_backend_fast_kreyvium_init(
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
                    ),
                },
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => match variant {
                    KreyviumVariant::Kreyvium => cuda_backend_kreyvium_init(
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
                    ),
                    KreyviumVariant::Fast => cuda_backend_fast_kreyvium_init(
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
                    ),
                },
            }
        }
        Ok(state)
    }

    fn kreyvium_next_impl(
        &self,
        state: &mut CudaKreyviumState,
        num_steps: usize,
        streams: &CudaStreams,
        variant: KreyviumVariant,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        if !num_steps.is_multiple_of(BATCH_SIZE) {
            return Err(format!("The number of steps must be a multiple of {BATCH_SIZE}.").into());
        }
        let mut keystream: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_steps * state.num_inputs, streams);
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => match variant {
                    KreyviumVariant::Kreyvium => cuda_backend_kreyvium_step(
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
                    ),
                    KreyviumVariant::Fast => cuda_backend_fast_kreyvium_step(
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
                    ),
                },
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => match variant {
                    KreyviumVariant::Kreyvium => cuda_backend_kreyvium_step(
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
                    ),
                    KreyviumVariant::Fast => cuda_backend_fast_kreyvium_step(
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
                    ),
                },
            }
        }
        Ok(keystream)
    }

    /// Generates a Kreyvium keystream in a single call.
    ///
    /// Initializes a transient state, runs the warmup, generates `num_steps` keystream bits, then
    /// drops the state.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key or IV bit count is wrong (see [`Self::kreyvium_init`]) or if
    /// `num_steps` is not a multiple of 64 (see [`Self::kreyvium_next`]).
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

    /// Initializes the Kreyvium state for stateful keystream generation.
    ///
    /// Loads the key and IV, executes the warmup steps, and returns the persistent state.
    ///
    /// `key` and `iv` may each carry `num_inputs` independent lanes, in which case their block
    /// count is `128 * num_inputs` with the lanes bit-sliced (lane `j` of key bit `i` at block
    /// `i * num_inputs + j`). Passing exactly 128 bits each runs a single keystream.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `key`'s bit count is not a non-zero multiple of 128, or if `iv` does not
    /// hold exactly 128 bits per key lane.
    pub fn kreyvium_init(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> crate::Result<CudaKreyviumState> {
        self.kreyvium_init_impl(key, iv, streams, KreyviumVariant::Kreyvium)
    }

    /// Generates the next chunk of keystream bits from an existing Kreyvium state.
    ///
    /// Updates the state in place, allowing consecutive calls to produce a continuous stream.
    /// `num_steps` must be a multiple of the batch size (64).
    ///
    /// The returned keystream holds `num_steps * state.num_inputs` blocks, bit-sliced across lanes:
    /// step `s` of lane `j` is at block `s * num_inputs + j`.
    ///
    /// # Errors
    ///
    /// Returns `Err` (rather than panicking) if `num_steps` is not a multiple of 64.
    pub fn kreyvium_next(
        &self,
        state: &mut CudaKreyviumState,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        self.kreyvium_next_impl(state, num_steps, streams, KreyviumVariant::Kreyvium)
    }

    /// Generates a FastKreyvium keystream in a single call.
    ///
    /// Initializes a transient state, runs the warmup, generates `num_steps` keystream bits, then
    /// drops the state.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key or IV bit count is wrong (see [`Self::fast_kreyvium_init`]) or if
    /// `num_steps` is not a multiple of 64 (see [`Self::fast_kreyvium_next`]).
    pub fn fast_kreyvium_generate_keystream(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        let mut state = self.fast_kreyvium_init(key, iv, streams)?;
        self.fast_kreyvium_next(&mut state, num_steps, streams)
    }

    /// Initializes the FastKreyvium state for stateful keystream generation.
    ///
    /// Loads the key and IV, executes the warmup steps, and returns the persistent state.
    ///
    /// `key` and `iv` may each carry `num_inputs` independent lanes, in which case their block
    /// count is `128 * num_inputs` with the lanes bit-sliced (lane `j` of key bit `i` at block
    /// `i * num_inputs + j`). Passing exactly 128 bits each runs a single keystream.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `key`'s bit count is not a non-zero multiple of 128, or if `iv` does not
    /// hold exactly 128 bits per key lane.
    pub fn fast_kreyvium_init(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> crate::Result<CudaKreyviumState> {
        self.kreyvium_init_impl(key, iv, streams, KreyviumVariant::Fast)
    }

    /// Generates the next chunk of keystream bits from an existing FastKreyvium state.
    ///
    /// Updates the state in place, allowing consecutive calls to produce a continuous stream.
    /// `num_steps` must be a multiple of the batch size (64).
    ///
    /// The returned keystream holds `num_steps * state.num_inputs` blocks, bit-sliced across lanes:
    /// step `s` of lane `j` is at block `s * num_inputs + j`.
    ///
    /// # Errors
    ///
    /// Returns `Err` (rather than panicking) if `num_steps` is not a multiple of 64.
    pub fn fast_kreyvium_next(
        &self,
        state: &mut CudaKreyviumState,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        self.kreyvium_next_impl(state, num_steps, streams, KreyviumVariant::Fast)
    }
}
