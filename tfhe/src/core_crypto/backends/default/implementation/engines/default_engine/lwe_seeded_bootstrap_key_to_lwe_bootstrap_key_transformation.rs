use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    LweBootstrapKey32, LweBootstrapKey64, LweSeededBootstrapKey32, LweSeededBootstrapKey64,
};
use crate::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey as ImplStandardBootstrapKey;
use crate::core_crypto::specification::engines::{
    LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine,
    LweSeededBootstrapKeyToLweBootstrapKeyTransformationError,
};
use crate::core_crypto::specification::entities::LweSeededBootstrapKeyEntity;

/// # Description:
/// Implementation of [`LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers. It outputs a bootstrap key in the
/// standard domain.
impl
    LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine<
        LweSeededBootstrapKey32,
        LweBootstrapKey32,
    > for DefaultEngine
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
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let seeded_bsk: LweSeededBootstrapKey32 =
    ///     engine.generate_new_lwe_seeded_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let bsk = engine.transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(seeded_bsk)?;
    ///
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
    fn transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(
        &mut self,
        lwe_seeded_bootstrap_key: LweSeededBootstrapKey32,
    ) -> Result<
        LweBootstrapKey32,
        LweSeededBootstrapKeyToLweBootstrapKeyTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked(
                lwe_seeded_bootstrap_key,
            )
        })
    }

    unsafe fn transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked(
        &mut self,
        lwe_seeded_bootstrap_key: LweSeededBootstrapKey32,
    ) -> LweBootstrapKey32 {
        let mut output = ImplStandardBootstrapKey::allocate(
            0u32,
            lwe_seeded_bootstrap_key.glwe_dimension().to_glwe_size(),
            lwe_seeded_bootstrap_key.polynomial_size(),
            lwe_seeded_bootstrap_key.decomposition_level_count(),
            lwe_seeded_bootstrap_key.decomposition_base_log(),
            lwe_seeded_bootstrap_key.input_lwe_dimension(),
        );

        lwe_seeded_bootstrap_key
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);
        LweBootstrapKey32(output)
    }
}

/// # Description:
/// Implementation of [`LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers. It outputs a bootstrap key in the
/// standard domain.
impl
    LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine<
        LweSeededBootstrapKey64,
        LweBootstrapKey64,
    > for DefaultEngine
{
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
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let seeded_bsk: LweSeededBootstrapKey64 =
    ///     engine.generate_new_lwe_seeded_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let bsk = engine.transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(seeded_bsk)?;
    ///
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
    fn transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(
        &mut self,
        lwe_seeded_bootstrap_key: LweSeededBootstrapKey64,
    ) -> Result<
        LweBootstrapKey64,
        LweSeededBootstrapKeyToLweBootstrapKeyTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked(
                lwe_seeded_bootstrap_key,
            )
        })
    }

    unsafe fn transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked(
        &mut self,
        lwe_seeded_bootstrap_key: LweSeededBootstrapKey64,
    ) -> LweBootstrapKey64 {
        let mut output = ImplStandardBootstrapKey::allocate(
            0u64,
            lwe_seeded_bootstrap_key.glwe_dimension().to_glwe_size(),
            lwe_seeded_bootstrap_key.polynomial_size(),
            lwe_seeded_bootstrap_key.decomposition_level_count(),
            lwe_seeded_bootstrap_key.decomposition_base_log(),
            lwe_seeded_bootstrap_key.input_lwe_dimension(),
        );

        lwe_seeded_bootstrap_key
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);
        LweBootstrapKey64(output)
    }
}
