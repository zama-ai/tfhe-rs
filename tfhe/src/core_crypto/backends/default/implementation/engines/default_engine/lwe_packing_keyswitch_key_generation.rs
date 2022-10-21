use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, Variance};

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey as ImplLwePackingKeyswitchKey;
use crate::core_crypto::prelude::{
    GlweSecretKey32, GlweSecretKey64, GlweSecretKeyEntity, LwePackingKeyswitchKey32,
    LwePackingKeyswitchKey64, LwePackingKeyswitchKeyGenerationError,
};
use crate::core_crypto::specification::engines::LwePackingKeyswitchKeyGenerationEngine;
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LwePackingKeyswitchKeyGenerationEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LwePackingKeyswitchKeyGenerationEngine<
        LweSecretKey32,
        GlweSecretKey32,
        LwePackingKeyswitchKey32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let output_polynomial_size = PolynomialSize(512);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey32 = engine.generate_new_glwe_secret_key(
    ///     output_glwe_dimension,
    ///     output_polynomial_size
    /// )?;
    ///
    /// let packing_keyswitch_key = engine.generate_new_lwe_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     packing_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     packing_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(packing_keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(packing_keyswitch_key.output_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(packing_keyswitch_key.output_polynomial_size(), output_polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_packing_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LwePackingKeyswitchKey32, LwePackingKeyswitchKeyGenerationError<Self::EngineError>>
    {
        LwePackingKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            32,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_packing_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_packing_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LwePackingKeyswitchKey32 {
        let mut ksk = ImplLwePackingKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.glwe_dimension(),
            output_key.polynomial_size(),
        );
        ksk.fill_with_packing_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LwePackingKeyswitchKey32(ksk)
    }
}

/// # Description:
/// Implementation of [`LwePackingKeyswitchKeyGenerationEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LwePackingKeyswitchKeyGenerationEngine<
        LweSecretKey64,
        GlweSecretKey64,
        LwePackingKeyswitchKey64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let output_polynomial_size = PolynomialSize(512);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey64 = engine.generate_new_glwe_secret_key(
    ///     output_glwe_dimension,
    ///     output_polynomial_size
    /// )?;
    ///
    /// let packing_keyswitch_key = engine.generate_new_lwe_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     packing_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     packing_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(packing_keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(packing_keyswitch_key.output_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(packing_keyswitch_key.output_polynomial_size(), output_polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_packing_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LwePackingKeyswitchKey64, LwePackingKeyswitchKeyGenerationError<Self::EngineError>>
    {
        LwePackingKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            64,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_packing_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_packing_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LwePackingKeyswitchKey64 {
        let mut ksk = ImplLwePackingKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.glwe_dimension(),
            output_key.polynomial_size(),
        );
        ksk.fill_with_packing_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LwePackingKeyswitchKey64(ksk)
    }
}
