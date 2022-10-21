use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, Variance};

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweKeyswitchKey32, LweKeyswitchKey64, LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::commons::crypto::lwe::LweKeyswitchKey as ImplLweKeyswitchKey;
use crate::core_crypto::specification::engines::{
    LweKeyswitchKeyGenerationEngine, LweKeyswitchKeyGenerationError,
};
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LweKeyswitchKeyGenerationEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweKeyswitchKeyGenerationEngine<LweSecretKey32, LweSecretKey32, LweKeyswitchKey32>
    for DefaultEngine
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
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &LweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweKeyswitchKey32, LweKeyswitchKeyGenerationError<Self::EngineError>> {
        LweKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            32,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &LweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LweKeyswitchKey32 {
        let mut ksk = ImplLweKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.lwe_dimension(),
        );
        ksk.fill_with_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweKeyswitchKey32(ksk)
    }
}

/// # Description:
/// Implementation of [`LweKeyswitchKeyGenerationEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweKeyswitchKeyGenerationEngine<LweSecretKey64, LweSecretKey64, LweKeyswitchKey64>
    for DefaultEngine
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
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweKeyswitchKey64, LweKeyswitchKeyGenerationError<Self::EngineError>> {
        LweKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            64,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LweKeyswitchKey64 {
        let mut ksk = ImplLweKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.lwe_dimension(),
        );
        ksk.fill_with_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweKeyswitchKey64(ksk)
    }
}
