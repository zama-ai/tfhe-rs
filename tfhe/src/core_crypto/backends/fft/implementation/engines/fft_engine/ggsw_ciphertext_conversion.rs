use super::{FftEngine, FftError};
use crate::core_crypto::backends::fft::entities::FftFourierGgswCiphertext32;
use crate::core_crypto::backends::fft::private::crypto::ggsw::FourierGgswCiphertext;
use crate::core_crypto::prelude::{
    FftFourierGgswCiphertext64, GgswCiphertext32, GgswCiphertext64, GgswCiphertextConversionError,
    GgswCiphertextDiscardingConversionEngine,
};
use crate::core_crypto::specification::engines::GgswCiphertextConversionEngine;
use crate::core_crypto::specification::entities::GgswCiphertextEntity;
use aligned_vec::avec;
use concrete_fft::c64;

impl From<FftError> for GgswCiphertextConversionError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
///
/// Implementation of [`GgswCiphertextConversionEngine`] for [`FftEngine`] that operates on 32
/// bit integers. It converts a GGSW ciphertext from the standard to the Fourier domain.
impl GgswCiphertextConversionEngine<GgswCiphertext32, FftFourierGgswCiphertext32> for FftEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
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
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftFourierGgswCiphertext32 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(fourier_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(fourier_ciphertext.decomposition_level_count(), level);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &GgswCiphertext32,
    ) -> Result<FftFourierGgswCiphertext32, GgswCiphertextConversionError<Self::EngineError>> {
        FftError::perform_fft_checks(input.polynomial_size())?;
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &GgswCiphertext32,
    ) -> FftFourierGgswCiphertext32 {
        let glwe_size = input.glwe_dimension().to_glwe_size();
        let mut output = FftFourierGgswCiphertext32(FourierGgswCiphertext::new(
            avec![
                c64::default();
                (input.polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * input.decomposition_level_count().0)
                    / 2
            ]
            .into_boxed_slice(),
            input.polynomial_size(),
            glwe_size,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
        ));

        self.discard_convert_ggsw_ciphertext_unchecked(&mut output, input);
        output
    }
}

/// # Description
///
/// Implementation of [`GgswCiphertextConversionEngine`] for [`FftEngine`] that operates on 64
/// bit integers. It converts a GGSW ciphertext from the standard to the Fourier domain.
impl GgswCiphertextConversionEngine<GgswCiphertext64, FftFourierGgswCiphertext64> for FftEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
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
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftFourierGgswCiphertext64 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(fourier_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(fourier_ciphertext.decomposition_level_count(), level);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &GgswCiphertext64,
    ) -> Result<FftFourierGgswCiphertext64, GgswCiphertextConversionError<Self::EngineError>> {
        FftError::perform_fft_checks(input.polynomial_size())?;
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &GgswCiphertext64,
    ) -> FftFourierGgswCiphertext64 {
        let glwe_size = input.glwe_dimension().to_glwe_size();
        let mut output = FftFourierGgswCiphertext64(FourierGgswCiphertext::new(
            avec![
                c64::default();
                (input.polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * input.decomposition_level_count().0)
                    / 2
            ]
            .into_boxed_slice(),
            input.polynomial_size(),
            glwe_size,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
        ));

        self.discard_convert_ggsw_ciphertext_unchecked(&mut output, input);
        output
    }
}
