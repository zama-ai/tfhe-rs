use super::{FftEngine, FftError};
use crate::core_crypto::backends::fft::private::crypto::ggsw::{
    external_product, external_product_scratch,
};
use crate::core_crypto::backends::fft::private::math::fft::Fft;
use crate::core_crypto::prelude::{
    FftFourierGgswCiphertext32, FftFourierGgswCiphertext64, GlweCiphertext32, GlweCiphertext64,
    GlweCiphertextEntity, GlweCiphertextGgswCiphertextDiscardingExternalProductEngine,
    GlweCiphertextGgswCiphertextDiscardingExternalProductError,
};

impl From<FftError> for GlweCiphertextGgswCiphertextDiscardingExternalProductError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
///
/// Implementation of [`GlweCiphertextGgswCiphertextDiscardingExternalProductEngine`] for
/// [`FftEngine`] that operates on 32 bit integers.
impl
    GlweCiphertextGgswCiphertextDiscardingExternalProductEngine<
        GlweCiphertext32,
        FftFourierGgswCiphertext32,
        GlweCiphertext32,
    > for FftEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_ggsw = 3_u32 << 20;
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
    /// let plaintext_glwe = default_engine.create_plaintext_vector_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let complex_ggsw: FftFourierGgswCiphertext32 = fft_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let glwe = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_glwe, noise)?;
    ///
    /// // We allocate an output ciphertext simply by cloning the input.
    /// // The content of this output ciphertext will by wiped by the external product.
    /// let mut product = glwe.clone();
    /// fft_engine.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
    ///     &glwe,
    ///     &complex_ggsw,
    ///     &mut product,
    /// )?;
    /// #
    /// # assert_eq!(
    /// #     product.polynomial_size(),
    /// #     glwe.polynomial_size(),
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
        &mut self,
        glwe_input: &GlweCiphertext32,
        ggsw_input: &FftFourierGgswCiphertext32,
        output: &mut GlweCiphertext32,
    ) -> Result<(), GlweCiphertextGgswCiphertextDiscardingExternalProductError<Self::EngineError>>
    {
        FftError::perform_fft_checks(glwe_input.polynomial_size())?;
        GlweCiphertextGgswCiphertextDiscardingExternalProductError::perform_generic_checks(
            glwe_input, ggsw_input, output,
        )?;
        unsafe {
            self.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
                glwe_input, ggsw_input, output,
            )
        };
        Ok(())
    }

    unsafe fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_input: &GlweCiphertext32,
        ggsw_input: &FftFourierGgswCiphertext32,
        output: &mut GlweCiphertext32,
    ) {
        let glwe_size = glwe_input.0.size();
        let polynomial_size = glwe_input.0.polynomial_size();
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        self.resize(
            external_product_scratch::<u32>(glwe_size, polynomial_size, fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.stack();
        external_product(
            output.0.as_mut_view(),
            ggsw_input.0.as_view(),
            glwe_input.0.as_view(),
            fft,
            stack,
        )
    }
}

/// # Description
///
/// Implementation of [`GlweCiphertextGgswCiphertextDiscardingExternalProductEngine`] for
/// [`FftEngine`] that operates on 64 bit integers.
impl
    GlweCiphertextGgswCiphertextDiscardingExternalProductEngine<
        GlweCiphertext64,
        FftFourierGgswCiphertext64,
        GlweCiphertext64,
    > for FftEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_ggsw = 3_u64 << 50;
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
    /// let plaintext_glwe = default_engine.create_plaintext_vector_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let complex_ggsw: FftFourierGgswCiphertext64 = fft_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let glwe = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_glwe, noise)?;
    ///
    /// // We allocate an output ciphertext simply by cloning the input.
    /// // The content of this output ciphertext will by wiped by the external product.
    /// let mut product = glwe.clone();
    /// fft_engine.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
    ///     &glwe,
    ///     &complex_ggsw,
    ///     &mut product,
    /// )?;
    /// #
    /// # assert_eq!(
    /// #     product.polynomial_size(),
    /// #     glwe.polynomial_size(),
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
        &mut self,
        glwe_input: &GlweCiphertext64,
        ggsw_input: &FftFourierGgswCiphertext64,
        output: &mut GlweCiphertext64,
    ) -> Result<(), GlweCiphertextGgswCiphertextDiscardingExternalProductError<Self::EngineError>>
    {
        FftError::perform_fft_checks(glwe_input.polynomial_size())?;
        GlweCiphertextGgswCiphertextDiscardingExternalProductError::perform_generic_checks(
            glwe_input, ggsw_input, output,
        )?;
        unsafe {
            self.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
                glwe_input, ggsw_input, output,
            )
        };
        Ok(())
    }

    unsafe fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_input: &GlweCiphertext64,
        ggsw_input: &FftFourierGgswCiphertext64,
        output: &mut GlweCiphertext64,
    ) {
        let glwe_size = glwe_input.0.size();
        let polynomial_size = glwe_input.0.polynomial_size();
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        self.resize(
            external_product_scratch::<u64>(glwe_size, polynomial_size, fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.stack();
        external_product(
            output.0.as_mut_view(),
            ggsw_input.0.as_view(),
            glwe_input.0.as_view(),
            fft,
            stack,
        )
    }
}
