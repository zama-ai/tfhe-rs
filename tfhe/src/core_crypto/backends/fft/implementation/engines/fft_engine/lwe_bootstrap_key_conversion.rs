use super::{FftEngine, FftError};
use crate::core_crypto::backends::fft::private::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::backends::fft::private::crypto::ggsw::fill_with_forward_fourier_scratch;
use crate::core_crypto::backends::fft::private::math::fft::Fft;
use crate::core_crypto::prelude::{
    FftFourierLweBootstrapKey32, FftFourierLweBootstrapKey64, LweBootstrapKey32, LweBootstrapKey64,
    LweBootstrapKeyConversionEngine, LweBootstrapKeyConversionError, LweBootstrapKeyEntity,
};
use aligned_vec::avec;
use concrete_fft::c64;

impl From<FftError> for LweBootstrapKeyConversionError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
///
/// Implementation of [`LweBootstrapKeyConversionEngine`] for [`FftEngine`] that operates on
/// 32 bit integers. It converts a bootstrap key from the standard to the Fourier domain.
impl LweBootstrapKeyConversionEngine<LweBootstrapKey32, FftFourierLweBootstrapKey32> for FftEngine {
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
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftFourierLweBootstrapKey32 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// #
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> Result<FftFourierLweBootstrapKey32, LweBootstrapKeyConversionError<Self::EngineError>>
    {
        FftError::perform_fft_checks(input.polynomial_size())?;
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> FftFourierLweBootstrapKey32 {
        let glwe_size = input.0.glwe_size();

        let boxed = avec![
            c64::default();
            input.0.polynomial_size().0
                * input.0.key_size().0
                * input.0.level_count().0
                * glwe_size.0
                * glwe_size.0
                / 2
        ]
        .into_boxed_slice();
        let fft = Fft::new(input.0.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            fill_with_forward_fourier_scratch(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.stack();

        let mut output = FourierLweBootstrapKey::new(
            boxed,
            input.0.key_size(),
            input.0.polynomial_size(),
            input.0.glwe_size(),
            input.0.base_log(),
            input.0.level_count(),
        );
        output
            .as_mut_view()
            .fill_with_forward_fourier(input.0.as_view(), fft, stack);
        FftFourierLweBootstrapKey32(output)
    }
}

/// # Description
///
/// Implementation of [`LweBootstrapKeyConversionEngine`] for [`FftEngine`] that operates on
/// 64 bit integers. It converts a bootstrap key from the standard to the Fourier domain.
impl LweBootstrapKeyConversionEngine<LweBootstrapKey64, FftFourierLweBootstrapKey64> for FftEngine {
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
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// #
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> Result<FftFourierLweBootstrapKey64, LweBootstrapKeyConversionError<Self::EngineError>>
    {
        FftError::perform_fft_checks(input.polynomial_size())?;
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> FftFourierLweBootstrapKey64 {
        let glwe_size = input.0.glwe_size();

        let boxed = avec![
            c64::default();
            input.0.polynomial_size().0
                * input.0.key_size().0
                * input.0.level_count().0
                * glwe_size.0
                * glwe_size.0
                / 2
        ]
        .into_boxed_slice();

        let fft = Fft::new(input.0.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            fill_with_forward_fourier_scratch(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.stack();

        let mut output = FourierLweBootstrapKey::new(
            boxed,
            input.0.key_size(),
            input.0.polynomial_size(),
            input.0.glwe_size(),
            input.0.base_log(),
            input.0.level_count(),
        );
        output
            .as_mut_view()
            .fill_with_forward_fourier(input.0.as_view(), fft, stack);
        FftFourierLweBootstrapKey64(output)
    }
}

impl<Key> LweBootstrapKeyConversionEngine<Key, Key> for FftEngine
where
    Key: LweBootstrapKeyEntity + Clone,
{
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &Key,
    ) -> Result<Key, LweBootstrapKeyConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(&mut self, input: &Key) -> Key {
        (*input).clone()
    }
}
