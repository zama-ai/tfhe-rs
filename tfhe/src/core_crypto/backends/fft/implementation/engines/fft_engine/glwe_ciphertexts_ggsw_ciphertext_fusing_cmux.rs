use super::{FftEngine, FftError};
use crate::core_crypto::backends::fft::private::crypto::ggsw::{cmux, cmux_scratch};
use crate::core_crypto::backends::fft::private::math::fft::Fft;
use crate::core_crypto::prelude::{
    FftFourierGgswCiphertext32, FftFourierGgswCiphertext64, GlweCiphertext32, GlweCiphertext64,
    GlweCiphertextEntity, GlweCiphertextsGgswCiphertextFusingCmuxEngine,
    GlweCiphertextsGgswCiphertextFusingCmuxError,
};

impl From<FftError> for GlweCiphertextsGgswCiphertextFusingCmuxError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
///
/// Implementation of [`GlweCiphertextsGgswCiphertextFusingCmuxEngine`] for [`FftEngine`] that
/// operates on 32 bit integers.
impl
    GlweCiphertextsGgswCiphertextFusingCmuxEngine<
        GlweCiphertext32,
        GlweCiphertext32,
        FftFourierGgswCiphertext32,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purposes, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 buts)
    /// let input_ggsw = 1_u32 << 20;
    /// let output_glwe = vec![1_u32 << 20; polynomial_size.0];
    /// let input_glwe = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_ggsw = default_engine.create_plaintext_from(&input_ggsw)?;
    /// let plaintext_output_glwe = default_engine.create_plaintext_vector_from(&output_glwe)?;
    /// let plaintext_input_glwe = default_engine.create_plaintext_vector_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let complex_ggsw: FftFourierGgswCiphertext32 = fft_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let mut glwe_output =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_output_glwe, noise)?;
    /// let mut glwe_input =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_input_glwe, noise)?;
    ///
    /// // Compute the cmux.
    /// fft_engine.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
    ///     &mut glwe_output,
    ///     &mut glwe_input,
    ///     &complex_ggsw,
    /// )?;
    /// #
    /// assert_eq!(glwe_output.polynomial_size(), glwe_input.polynomial_size(),);
    /// assert_eq!(glwe_output.glwe_dimension(), glwe_input.glwe_dimension(),);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
        &mut self,
        glwe_output: &mut GlweCiphertext32,
        glwe_input: &mut GlweCiphertext32,
        ggsw_input: &FftFourierGgswCiphertext32,
    ) -> Result<(), GlweCiphertextsGgswCiphertextFusingCmuxError<Self::EngineError>> {
        FftError::perform_fft_checks(glwe_output.polynomial_size())?;
        GlweCiphertextsGgswCiphertextFusingCmuxError::perform_generic_checks(
            glwe_output,
            glwe_input,
            ggsw_input,
        )?;
        unsafe {
            self.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
                glwe_output,
                glwe_input,
                ggsw_input,
            )
        };
        Ok(())
    }

    unsafe fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_output: &mut GlweCiphertext32,
        glwe_input: &mut GlweCiphertext32,
        ggsw_input: &FftFourierGgswCiphertext32,
    ) {
        let glwe_size = glwe_input.0.size();
        let polynomial_size = glwe_input.0.polynomial_size();
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        self.resize(
            cmux_scratch::<u32>(glwe_size, polynomial_size, fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.stack();
        cmux(
            glwe_output.0.as_mut_view(),
            glwe_input.0.as_mut_view(),
            ggsw_input.0.as_view(),
            fft,
            stack,
        );
    }
}

/// # Description
///
/// Implementation of [`GlweCiphertextsGgswCiphertextFusingCmuxEngine`] for [`FftEngine`] that
/// operates on 64 bit integers.
impl
    GlweCiphertextsGgswCiphertextFusingCmuxEngine<
        GlweCiphertext64,
        GlweCiphertext64,
        FftFourierGgswCiphertext64,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purposes, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 buts)
    /// let input_ggsw = 1_u64 << 50;
    /// let output_glwe = vec![1_u64 << 50; polynomial_size.0];
    /// let input_glwe = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_ggsw = default_engine.create_plaintext_from(&input_ggsw)?;
    /// let plaintext_output_glwe = default_engine.create_plaintext_vector_from(&output_glwe)?;
    /// let plaintext_input_glwe = default_engine.create_plaintext_vector_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let complex_ggsw: FftFourierGgswCiphertext64 = fft_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let mut glwe_output =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_output_glwe, noise)?;
    /// let mut glwe_input =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_input_glwe, noise)?;
    ///
    /// // Compute the cmux.
    /// fft_engine.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
    ///     &mut glwe_output,
    ///     &mut glwe_input,
    ///     &complex_ggsw,
    /// )?;
    /// #
    /// assert_eq!(glwe_output.polynomial_size(), glwe_input.polynomial_size(),);
    /// assert_eq!(glwe_output.glwe_dimension(), glwe_input.glwe_dimension(),);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
        &mut self,
        glwe_output: &mut GlweCiphertext64,
        glwe_input: &mut GlweCiphertext64,
        ggsw_input: &FftFourierGgswCiphertext64,
    ) -> Result<(), GlweCiphertextsGgswCiphertextFusingCmuxError<Self::EngineError>> {
        FftError::perform_fft_checks(glwe_output.polynomial_size())?;
        GlweCiphertextsGgswCiphertextFusingCmuxError::perform_generic_checks(
            glwe_output,
            glwe_input,
            ggsw_input,
        )?;
        unsafe {
            self.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
                glwe_output,
                glwe_input,
                ggsw_input,
            )
        };
        Ok(())
    }

    unsafe fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_output: &mut GlweCiphertext64,
        glwe_input: &mut GlweCiphertext64,
        ggsw_input: &FftFourierGgswCiphertext64,
    ) {
        let glwe_size = glwe_input.0.size();
        let polynomial_size = glwe_input.0.polynomial_size();
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        self.resize(
            cmux_scratch::<u64>(glwe_size, polynomial_size, fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.stack();
        cmux(
            glwe_output.0.as_mut_view(),
            glwe_input.0.as_mut_view(),
            ggsw_input.0.as_view(),
            fft,
            stack,
        );
    }
}
