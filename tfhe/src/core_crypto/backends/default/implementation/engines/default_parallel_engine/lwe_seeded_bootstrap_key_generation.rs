use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::implementation::engines::DefaultParallelEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweSecretKey32, GlweSecretKey64, LweSecretKey32, LweSecretKey64, LweSeededBootstrapKey32,
    LweSeededBootstrapKey64,
};
use crate::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey as ImplStandardSeededBootstrapKey;
use crate::core_crypto::commons::math::random::{CompressionSeed, Seeder};
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSecretKeyEntity, LweSecretKeyEntity,
    Variance,
};
use crate::core_crypto::specification::engines::{
    LweSeededBootstrapKeyGenerationEngine, LweSeededBootstrapKeyGenerationError,
};

/// # Description:
/// Implementation of [`LweSeededBootstrapKeyGenerationEngine`] for [`DefaultParallelEngine`] that
/// operates on 32 bits integers. It outputs a seeded bootstrap key in the standard domain.
impl LweSeededBootstrapKeyGenerationEngine<LweSecretKey32, GlweSecretKey32, LweSeededBootstrapKey32>
    for DefaultParallelEngine
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
    /// let mut default_parallel_engine =
    ///     DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweSeededBootstrapKey32 = default_parallel_engine
    ///     .generate_new_lwe_seeded_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// #
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_seeded_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweSeededBootstrapKey32, LweSeededBootstrapKeyGenerationError<Self::EngineError>>
    {
        LweSeededBootstrapKeyGenerationError::perform_generic_checks(
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_seeded_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_seeded_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweSeededBootstrapKey32 {
        let mut key = ImplStandardSeededBootstrapKey::<Vec<u32>>::allocate(
            output_key.glwe_dimension().to_glwe_size(),
            output_key.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.par_fill_with_new_key::<_, _, _, _, _, ActivatedRandomGenerator>(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.seeder,
        );
        LweSeededBootstrapKey32(key)
    }
}

/// # Description:
/// Implementation of [`LweSeededBootstrapKeyGenerationEngine`] for [`DefaultParallelEngine`] that
/// operates on 64 bits integers. It outputs a seeded bootstrap key in the standard domain.
impl LweSeededBootstrapKeyGenerationEngine<LweSecretKey64, GlweSecretKey64, LweSeededBootstrapKey64>
    for DefaultParallelEngine
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
    /// let mut default_parallel_engine =
    ///     DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweSeededBootstrapKey64 = default_parallel_engine
    ///     .generate_new_lwe_seeded_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// #
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_seeded_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweSeededBootstrapKey64, LweSeededBootstrapKeyGenerationError<Self::EngineError>>
    {
        LweSeededBootstrapKeyGenerationError::perform_generic_checks(
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_seeded_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_seeded_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweSeededBootstrapKey64 {
        let mut key = ImplStandardSeededBootstrapKey::<Vec<u64>>::allocate(
            output_key.glwe_dimension().to_glwe_size(),
            output_key.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.par_fill_with_new_key::<_, _, _, _, _, ActivatedRandomGenerator>(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.seeder,
        );
        LweSeededBootstrapKey64(key)
    }
}
