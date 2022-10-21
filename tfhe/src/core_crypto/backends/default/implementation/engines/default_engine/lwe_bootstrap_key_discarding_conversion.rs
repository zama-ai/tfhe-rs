use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    LweBootstrapKey32, LweBootstrapKey64, LweBootstrapKeyMutView32, LweBootstrapKeyMutView64,
};
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::specification::engines::{
    LweBootstrapKeyDiscardingConversionEngine, LweBootstrapKeyDiscardingConversionError,
};

impl LweBootstrapKeyDiscardingConversionEngine<LweBootstrapKey32, LweBootstrapKeyMutView32<'_>>
    for DefaultEngine
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut owned_container = vec![
    ///     0_u32;
    ///     lwe_dim.0
    ///         * dec_lc.0
    ///         * glwe_dim.to_glwe_size().0
    ///         * glwe_dim.to_glwe_size().0
    ///         * poly_size.0
    /// ];
    ///
    /// let mut out_bsk_mut_view: LweBootstrapKeyMutView32 = default_engine
    ///     .create_lwe_bootstrap_key_from(
    ///         owned_container.as_mut_slice(),
    ///         glwe_dim.to_glwe_size(),
    ///         poly_size,
    ///         dec_bl,
    ///         dec_lc,
    ///     )?;
    ///
    /// default_engine.discard_convert_lwe_bootstrap_key(&mut out_bsk_mut_view, &bsk)?;
    /// #
    /// assert_eq!(out_bsk_mut_view.glwe_dimension(), glwe_dim);
    /// assert_eq!(out_bsk_mut_view.polynomial_size(), poly_size);
    /// assert_eq!(out_bsk_mut_view.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(out_bsk_mut_view.decomposition_base_log(), dec_bl);
    /// assert_eq!(out_bsk_mut_view.decomposition_level_count(), dec_lc);
    ///
    /// // Check content is the same
    ///
    /// let original_bsk_container = default_engine.consume_retrieve_lwe_bootstrap_key(bsk)?;
    /// let mut_view_bsk_container =
    ///     default_engine.consume_retrieve_lwe_bootstrap_key(out_bsk_mut_view)?;
    ///
    /// assert_eq!(original_bsk_container, mut_view_bsk_container);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_bootstrap_key(
        &mut self,
        output: &mut LweBootstrapKeyMutView32<'_>,
        input: &LweBootstrapKey32,
    ) -> Result<(), LweBootstrapKeyDiscardingConversionError<Self::EngineError>> {
        LweBootstrapKeyDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_lwe_bootstrap_key_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_bootstrap_key_unchecked(
        &mut self,
        output: &mut LweBootstrapKeyMutView32<'_>,
        input: &LweBootstrapKey32,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
    }
}

impl LweBootstrapKeyDiscardingConversionEngine<LweBootstrapKey64, LweBootstrapKeyMutView64<'_>>
    for DefaultEngine
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut owned_container = vec![
    ///     0_u64;
    ///     lwe_dim.0
    ///         * dec_lc.0
    ///         * glwe_dim.to_glwe_size().0
    ///         * glwe_dim.to_glwe_size().0
    ///         * poly_size.0
    /// ];
    ///
    /// let mut out_bsk_mut_view: LweBootstrapKeyMutView64 = default_engine
    ///     .create_lwe_bootstrap_key_from(
    ///         owned_container.as_mut_slice(),
    ///         glwe_dim.to_glwe_size(),
    ///         poly_size,
    ///         dec_bl,
    ///         dec_lc,
    ///     )?;
    ///
    /// default_engine.discard_convert_lwe_bootstrap_key(&mut out_bsk_mut_view, &bsk)?;
    /// #
    /// assert_eq!(out_bsk_mut_view.glwe_dimension(), glwe_dim);
    /// assert_eq!(out_bsk_mut_view.polynomial_size(), poly_size);
    /// assert_eq!(out_bsk_mut_view.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(out_bsk_mut_view.decomposition_base_log(), dec_bl);
    /// assert_eq!(out_bsk_mut_view.decomposition_level_count(), dec_lc);
    ///
    /// // Check content is the same
    ///
    /// let original_bsk_container = default_engine.consume_retrieve_lwe_bootstrap_key(bsk)?;
    /// let mut_view_bsk_container =
    ///     default_engine.consume_retrieve_lwe_bootstrap_key(out_bsk_mut_view)?;
    ///
    /// assert_eq!(original_bsk_container, mut_view_bsk_container);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_bootstrap_key(
        &mut self,
        output: &mut LweBootstrapKeyMutView64<'_>,
        input: &LweBootstrapKey64,
    ) -> Result<(), LweBootstrapKeyDiscardingConversionError<Self::EngineError>> {
        LweBootstrapKeyDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_lwe_bootstrap_key_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_bootstrap_key_unchecked(
        &mut self,
        output: &mut LweBootstrapKeyMutView64<'_>,
        input: &LweBootstrapKey64,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
    }
}
