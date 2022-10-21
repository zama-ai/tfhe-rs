use crate::core_crypto::backends::fft::engines::{FftEngine, FftError};
use crate::core_crypto::backends::fft::entities::{
    FftFourierLweBootstrapKey32, FftFourierLweBootstrapKey64,
};
use crate::core_crypto::backends::fft::private::crypto::wop_pbs::{
    extract_bits, extract_bits_scratch,
};
use crate::core_crypto::backends::fft::private::math::fft::Fft;
use crate::core_crypto::prelude::{
    CiphertextModulusLog, DeltaLog, ExtractedBitsCount, LweBootstrapKeyEntity, LweCiphertext32,
    LweCiphertext64, LweCiphertextEntity, LweCiphertextVector32, LweCiphertextVector64,
    LweCiphertextVectorMutView32, LweCiphertextVectorMutView64, LweCiphertextView32,
    LweCiphertextView64, LweKeyswitchKey32, LweKeyswitchKey64, LweKeyswitchKeyEntity,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingBitExtractEngine, LweCiphertextDiscardingBitExtractError,
};

impl From<FftError> for LweCiphertextDiscardingBitExtractError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBitExtractEngine`] for [`FftEngine`] that operates
/// on 32 bits integers.
impl
    LweCiphertextDiscardingBitExtractEngine<
        FftFourierLweBootstrapKey32,
        LweKeyswitchKey32,
        LweCiphertext32,
        LweCiphertextVector32,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(1), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let extracted_bits_count = ExtractedBitsCount(1);
    /// let delta_log = DeltaLog(5);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let large_lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, and rely on /dev/random only for tests.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let input_lwe_sk: LweSecretKey32 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let output_lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let bsk: LweBootstrapKey32 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &output_lwe_sk,
    ///     &glwe_sk,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// let ksk: LweKeyswitchKey32 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_lwe_sk,
    ///     &output_lwe_sk,
    ///     dec_lc,
    ///     dec_bl,
    ///     noise,
    /// )?;
    /// let bsk: FftFourierLweBootstrapKey32 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&input_lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext_vector(
    ///     &output_lwe_sk,
    ///     noise,
    ///     LweCiphertextCount(extracted_bits_count.0),
    /// )?;
    ///
    /// fft_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut output,
    ///     &input,
    ///     &bsk,
    ///     &ksk,
    ///     extracted_bits_count,
    ///     delta_log,
    /// )?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim);
    /// assert_eq!(
    ///     output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(extracted_bits_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertext32,
        bsk: &FftFourierLweBootstrapKey32,
        ksk: &LweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(32),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertext32,
        bsk: &FftFourierLweBootstrapKey32,
        ksk: &LweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            extract_bits_scratch::<u32>(
                input.lwe_dimension(),
                ksk.output_lwe_dimension(),
                bsk.glwe_dimension().to_glwe_size(),
                bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        extract_bits(
            output.0.as_mut_view(),
            input.0.as_view(),
            ksk.0.as_view(),
            bsk.0.as_view(),
            delta_log,
            extracted_bits_count,
            fft,
            self.stack(),
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBitExtractEngine`] for [`FftEngine`] that operates
/// on 64 bits integers.
impl
    LweCiphertextDiscardingBitExtractEngine<
        FftFourierLweBootstrapKey64,
        LweKeyswitchKey64,
        LweCiphertext64,
        LweCiphertextVector64,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u64 << 50;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(1), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let extracted_bits_count = ExtractedBitsCount(1);
    /// let delta_log = DeltaLog(5);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let large_lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, and rely on /dev/random only for tests.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let input_lwe_sk: LweSecretKey64 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let output_lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let bsk: LweBootstrapKey64 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &output_lwe_sk,
    ///     &glwe_sk,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// let ksk: LweKeyswitchKey64 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_lwe_sk,
    ///     &output_lwe_sk,
    ///     dec_lc,
    ///     dec_bl,
    ///     noise,
    /// )?;
    /// let bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&input_lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext_vector(
    ///     &output_lwe_sk,
    ///     noise,
    ///     LweCiphertextCount(extracted_bits_count.0),
    /// )?;
    ///
    /// fft_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut output,
    ///     &input,
    ///     &bsk,
    ///     &ksk,
    ///     extracted_bits_count,
    ///     delta_log,
    /// )?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim);
    /// assert_eq!(
    ///     output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(extracted_bits_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertext64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(64),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertext64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            extract_bits_scratch::<u64>(
                input.lwe_dimension(),
                ksk.output_lwe_dimension(),
                bsk.glwe_dimension().to_glwe_size(),
                bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        extract_bits(
            output.0.as_mut_view(),
            input.0.as_view(),
            ksk.0.as_view(),
            bsk.0.as_view(),
            delta_log,
            extracted_bits_count,
            fft,
            self.stack(),
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBitExtractEngine`] for [`FftEngine`] that operates
/// on views containing 32 bits integers.
impl
    LweCiphertextDiscardingBitExtractEngine<
        FftFourierLweBootstrapKey32,
        LweKeyswitchKey32,
        LweCiphertextView32<'_>,
        LweCiphertextVectorMutView32<'_>,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(1), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let extracted_bits_count = ExtractedBitsCount(1);
    /// let delta_log = DeltaLog(5);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let large_lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, and rely on /dev/random only for tests.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let input_lwe_sk: LweSecretKey32 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let output_lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let bsk: LweBootstrapKey32 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &output_lwe_sk,
    ///     &glwe_sk,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// let ksk: LweKeyswitchKey32 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_lwe_sk,
    ///     &output_lwe_sk,
    ///     dec_lc,
    ///     dec_bl,
    ///     noise,
    /// )?;
    /// let bsk: FftFourierLweBootstrapKey32 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// let mut input_ct_container = vec![0u32; input_lwe_sk.lwe_dimension().to_lwe_size().0];
    /// let mut input: LweCiphertextMutView32 =
    ///     default_engine.create_lwe_ciphertext_from(input_ct_container.as_mut_slice())?;
    ///
    /// let mut output_ct_vec_container =
    ///     vec![0u32; output_lwe_sk.lwe_dimension().to_lwe_size().0 * extracted_bits_count.0];
    /// let mut output: LweCiphertextVectorMutView32 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         output_ct_vec_container.as_mut_slice(),
    ///         output_lwe_sk.lwe_dimension().to_lwe_size(),
    ///     )?;
    ///
    /// default_engine.discard_encrypt_lwe_ciphertext(&input_lwe_sk, &mut input, &plaintext, noise)?;
    ///
    /// let input_slice = default_engine.consume_retrieve_lwe_ciphertext(input)?;
    /// let input: LweCiphertextView32 = default_engine.create_lwe_ciphertext_from(&input_slice[..])?;
    ///
    /// fft_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut output,
    ///     &input,
    ///     &bsk,
    ///     &ksk,
    ///     extracted_bits_count,
    ///     delta_log,
    /// )?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim);
    /// assert_eq!(
    ///     output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(extracted_bits_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextVectorMutView32<'_>,
        input: &LweCiphertextView32<'_>,
        bsk: &FftFourierLweBootstrapKey32,
        ksk: &LweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(32),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextVectorMutView32<'_>,
        input: &LweCiphertextView32<'_>,
        bsk: &FftFourierLweBootstrapKey32,
        ksk: &LweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            extract_bits_scratch::<u32>(
                input.lwe_dimension(),
                ksk.output_lwe_dimension(),
                bsk.glwe_dimension().to_glwe_size(),
                bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        extract_bits(
            output.0.as_mut_view(),
            input.0.as_view(),
            ksk.0.as_view(),
            bsk.0.as_view(),
            delta_log,
            extracted_bits_count,
            fft,
            self.stack(),
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBitExtractEngine`] for [`FftEngine`] that operates
/// on views containing 64 bits integers.
impl
    LweCiphertextDiscardingBitExtractEngine<
        FftFourierLweBootstrapKey64,
        LweKeyswitchKey64,
        LweCiphertextView64<'_>,
        LweCiphertextVectorMutView64<'_>,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u64 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(1), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let extracted_bits_count = ExtractedBitsCount(1);
    /// let delta_log = DeltaLog(5);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let large_lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, and rely on /dev/random only for tests.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let input_lwe_sk: LweSecretKey64 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let output_lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let bsk: LweBootstrapKey64 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &output_lwe_sk,
    ///     &glwe_sk,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// let ksk: LweKeyswitchKey64 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_lwe_sk,
    ///     &output_lwe_sk,
    ///     dec_lc,
    ///     dec_bl,
    ///     noise,
    /// )?;
    /// let bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// let mut input_ct_container = vec![0u64; input_lwe_sk.lwe_dimension().to_lwe_size().0];
    /// let mut input: LweCiphertextMutView64 =
    ///     default_engine.create_lwe_ciphertext_from(input_ct_container.as_mut_slice())?;
    ///
    /// let mut output_ct_vec_container =
    ///     vec![0u64; output_lwe_sk.lwe_dimension().to_lwe_size().0 * extracted_bits_count.0];
    /// let mut output: LweCiphertextVectorMutView64 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         output_ct_vec_container.as_mut_slice(),
    ///         output_lwe_sk.lwe_dimension().to_lwe_size(),
    ///     )?;
    ///
    /// default_engine.discard_encrypt_lwe_ciphertext(&input_lwe_sk, &mut input, &plaintext, noise)?;
    ///
    /// let input_slice = default_engine.consume_retrieve_lwe_ciphertext(input)?;
    /// let input: LweCiphertextView64 = default_engine.create_lwe_ciphertext_from(&input_slice[..])?;
    ///
    /// fft_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut output,
    ///     &input,
    ///     &bsk,
    ///     &ksk,
    ///     extracted_bits_count,
    ///     delta_log,
    /// )?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim);
    /// assert_eq!(
    ///     output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(extracted_bits_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextVectorMutView64<'_>,
        input: &LweCiphertextView64<'_>,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(64),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextVectorMutView64<'_>,
        input: &LweCiphertextView64<'_>,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            extract_bits_scratch::<u64>(
                input.lwe_dimension(),
                ksk.output_lwe_dimension(),
                bsk.glwe_dimension().to_glwe_size(),
                bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        extract_bits(
            output.0.as_mut_view(),
            input.0.as_view(),
            ksk.0.as_view(),
            bsk.0.as_view(),
            delta_log,
            extracted_bits_count,
            fft,
            self.stack(),
        );
    }
}
