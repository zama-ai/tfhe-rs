use crate::core_crypto::backends::default::entities::{
    GgswCiphertext32, GgswCiphertext64, LweCiphertext32, LweCiphertext64,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
};
use crate::core_crypto::backends::fft::engines::{FftEngine, FftError};
use crate::core_crypto::backends::fft::entities::{
    FftFourierLweBootstrapKey32, FftFourierLweBootstrapKey64,
};
use crate::core_crypto::backends::fft::private::crypto::wop_pbs::{
    circuit_bootstrap_boolean, circuit_bootstrap_boolean_scratch,
};
use crate::core_crypto::backends::fft::private::math::fft::Fft;
use crate::core_crypto::prelude::LweCiphertextEntity;
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingCircuitBootstrapBooleanEngine,
    LweCiphertextDiscardingCircuitBootstrapBooleanError,
};
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;
use crate::core_crypto::specification::parameters::DeltaLog;

impl From<FftError> for LweCiphertextDiscardingCircuitBootstrapBooleanError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingCircuitBootstrapBooleanEngine`] for [`FftEngine`]
/// that operates on 32 bits integers.
impl
    LweCiphertextDiscardingCircuitBootstrapBooleanEngine<
        LweCiphertext32,
        GgswCiphertext32,
        FftFourierLweBootstrapKey32,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Define settings for an insecure toy example
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_dimension = GlweDimension(2);
    /// let small_lwe_dimension = LweDimension(10);
    ///
    /// // The following sets of decomposition parameters are independant and can be adapted for
    /// // your use case, having identical parameters for some of them here is a coincidence
    /// let level_bsk = DecompositionLevelCount(2);
    /// let base_log_bsk = DecompositionBaseLog(15);
    ///
    /// let level_pfpksk = DecompositionLevelCount(2);
    /// let base_log_pfpksk = DecompositionBaseLog(15);
    ///
    /// let level_count_cbs = DecompositionLevelCount(1);
    /// let base_log_cbs = DecompositionBaseLog(10);
    ///
    /// let std = LogStandardDev::from_log_standard_dev(-60.);
    /// let noise = Variance(std.get_variance());
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut default_parallel_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    ///
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let small_lwe_sk: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(small_lwe_dimension)?;
    /// let big_lwe_sk: LweSecretKey32 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let std_bsk: LweBootstrapKey32 = default_parallel_engine.generate_new_lwe_bootstrap_key(
    ///     &small_lwe_sk,
    ///     &glwe_sk,
    ///     base_log_bsk,
    ///     level_bsk,
    ///     noise,
    /// )?;
    /// let fbsk: FftFourierLweBootstrapKey32 = fft_engine.convert_lwe_bootstrap_key(&std_bsk)?;
    /// let cbs_pfpksk: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 = default_engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &big_lwe_sk,
    ///         &glwe_sk,
    ///         base_log_pfpksk,
    ///         level_pfpksk,
    ///         noise,
    ///     )?;
    ///
    /// // delta_log indicates where the information bit is stored in the input LWE ciphertext, here
    /// // we put it in the most significant bit, which corresponds to 2 ^ 31
    /// let delta_log = DeltaLog(31);
    ///
    /// let value = 1u32;
    /// // Encryption of 'value' in an LWE ciphertext using delta_log for the encoding
    /// let plaintext: Plaintext32 = default_engine.create_plaintext_from(&(value << delta_log.0))?;
    /// let lwe_in: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&small_lwe_sk, &plaintext, noise)?;
    ///
    /// // Create an empty GGSW ciphertext with a trivial encryption of 0
    /// let zero_plaintext: Plaintext32 = default_engine.create_plaintext_from(&0u32)?;
    /// let mut output_ggsw: GgswCiphertext32 = default_engine
    ///     .trivially_encrypt_scalar_ggsw_ciphertext(
    ///         polynomial_size,
    ///         glwe_dimension.to_glwe_size(),
    ///         level_count_cbs,
    ///         base_log_cbs,
    ///         &zero_plaintext,
    ///     )?;
    ///
    /// fft_engine.discard_circuit_bootstrap_boolean_lwe_ciphertext(
    ///     &mut output_ggsw,
    ///     &lwe_in,
    ///     delta_log,
    ///     &fbsk,
    ///     &cbs_pfpksk,
    /// )?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_circuit_bootstrap_boolean_lwe_ciphertext(
        &mut self,
        output: &mut GgswCiphertext32,
        input: &LweCiphertext32,
        delta_log: DeltaLog,
        bsk: &FftFourierLweBootstrapKey32,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) -> Result<(), LweCiphertextDiscardingCircuitBootstrapBooleanError<Self::EngineError>> {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingCircuitBootstrapBooleanError::perform_generic_checks(
            input, output, bsk, cbs_pfpksk,
        )?;
        unsafe {
            self.discard_circuit_bootstrap_boolean_lwe_ciphertext_unchecked(
                output, input, delta_log, bsk, cbs_pfpksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_circuit_bootstrap_boolean_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut GgswCiphertext32,
        input: &LweCiphertext32,
        delta_log: DeltaLog,
        bsk: &FftFourierLweBootstrapKey32,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) {
        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            circuit_bootstrap_boolean_scratch::<u32>(
                input.lwe_dimension().to_lwe_size(),
                bsk.output_lwe_dimension().to_lwe_size(),
                bsk.polynomial_size(),
                bsk.glwe_dimension().to_glwe_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        circuit_bootstrap_boolean(
            bsk.0.as_view(),
            input.0.as_view(),
            output.0.as_mut_view(),
            delta_log,
            cbs_pfpksk.0.as_view(),
            fft,
            self.stack(),
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingCircuitBootstrapBooleanEngine`] for [`FftEngine`]
/// that operates on 64 bits integers.
impl
    LweCiphertextDiscardingCircuitBootstrapBooleanEngine<
        LweCiphertext64,
        GgswCiphertext64,
        FftFourierLweBootstrapKey64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Define settings for an insecure toy example
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_dimension = GlweDimension(2);
    /// let small_lwe_dimension = LweDimension(10);
    ///
    /// // The following sets of decomposition parameters are independant and can be adapted for
    /// // your use case, having identical parameters for some of them here is a coincidence
    /// let level_bsk = DecompositionLevelCount(2);
    /// let base_log_bsk = DecompositionBaseLog(15);
    ///
    /// let level_pfpksk = DecompositionLevelCount(2);
    /// let base_log_pfpksk = DecompositionBaseLog(15);
    ///
    /// let level_count_cbs = DecompositionLevelCount(1);
    /// let base_log_cbs = DecompositionBaseLog(10);
    ///
    /// let std = LogStandardDev::from_log_standard_dev(-60.);
    /// let noise = Variance(std.get_variance());
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut default_parallel_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    ///
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let small_lwe_sk: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(small_lwe_dimension)?;
    /// let big_lwe_sk: LweSecretKey64 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let std_bsk: LweBootstrapKey64 = default_parallel_engine.generate_new_lwe_bootstrap_key(
    ///     &small_lwe_sk,
    ///     &glwe_sk,
    ///     base_log_bsk,
    ///     level_bsk,
    ///     noise,
    /// )?;
    /// let fbsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&std_bsk)?;
    /// let cbs_pfpksk: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 = default_engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &big_lwe_sk,
    ///         &glwe_sk,
    ///         base_log_pfpksk,
    ///         level_pfpksk,
    ///         noise,
    ///     )?;
    ///
    /// // delta_log indicates where the information bit is stored in the input LWE ciphertext, here
    /// // we put it in the most significant bit, which corresponds to 2 ^ 63
    /// let delta_log = DeltaLog(63);
    ///
    /// let value = 1u64;
    /// // Encryption of 'value' in an LWE ciphertext using delta_log for the encoding
    /// let plaintext: Plaintext64 = default_engine.create_plaintext_from(&(value << delta_log.0))?;
    /// let lwe_in: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&small_lwe_sk, &plaintext, noise)?;
    ///
    /// // Create an empty GGSW ciphertext with a trivial encryption of 0
    /// let zero_plaintext: Plaintext64 = default_engine.create_plaintext_from(&0u64)?;
    /// let mut output_ggsw: GgswCiphertext64 = default_engine
    ///     .trivially_encrypt_scalar_ggsw_ciphertext(
    ///         polynomial_size,
    ///         glwe_dimension.to_glwe_size(),
    ///         level_count_cbs,
    ///         base_log_cbs,
    ///         &zero_plaintext,
    ///     )?;
    ///
    /// fft_engine.discard_circuit_bootstrap_boolean_lwe_ciphertext(
    ///     &mut output_ggsw,
    ///     &lwe_in,
    ///     delta_log,
    ///     &fbsk,
    ///     &cbs_pfpksk,
    /// )?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_circuit_bootstrap_boolean_lwe_ciphertext(
        &mut self,
        output: &mut GgswCiphertext64,
        input: &LweCiphertext64,
        delta_log: DeltaLog,
        bsk: &FftFourierLweBootstrapKey64,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> Result<(), LweCiphertextDiscardingCircuitBootstrapBooleanError<Self::EngineError>> {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingCircuitBootstrapBooleanError::perform_generic_checks(
            input, output, bsk, cbs_pfpksk,
        )?;
        unsafe {
            self.discard_circuit_bootstrap_boolean_lwe_ciphertext_unchecked(
                output, input, delta_log, bsk, cbs_pfpksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_circuit_bootstrap_boolean_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut GgswCiphertext64,
        input: &LweCiphertext64,
        delta_log: DeltaLog,
        bsk: &FftFourierLweBootstrapKey64,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) {
        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            circuit_bootstrap_boolean_scratch::<u64>(
                input.lwe_dimension().to_lwe_size(),
                bsk.output_lwe_dimension().to_lwe_size(),
                bsk.polynomial_size(),
                bsk.glwe_dimension().to_glwe_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        circuit_bootstrap_boolean(
            bsk.0.as_view(),
            input.0.as_view(),
            output.0.as_mut_view(),
            delta_log,
            cbs_pfpksk.0.as_view(),
            fft,
            self.stack(),
        );
    }
}
