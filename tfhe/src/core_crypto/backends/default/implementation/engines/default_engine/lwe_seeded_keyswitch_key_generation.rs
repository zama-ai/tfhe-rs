use super::ActivatedRandomGenerator;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, Variance};

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweSecretKey32, LweSecretKey64, LweSeededKeyswitchKey32, LweSeededKeyswitchKey64,
};
use crate::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey as ImplLweSeededKeyswitchKey;
use crate::core_crypto::commons::math::random::{CompressionSeed, Seeder};
use crate::core_crypto::specification::engines::{
    LweSeededKeyswitchKeyGenerationEngine, LweSeededKeyswitchKeyGenerationError,
};
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

impl LweSeededKeyswitchKeyGenerationEngine<LweSecretKey32, LweSecretKey32, LweSeededKeyswitchKey32>
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
    /// let seeded_keyswitch_key = engine.generate_new_lwe_seeded_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     seeded_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     seeded_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(seeded_keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(seeded_keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_seeded_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &LweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweSeededKeyswitchKey32, LweSeededKeyswitchKeyGenerationError<Self::EngineError>>
    {
        LweSeededKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            32,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_seeded_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_seeded_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &LweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LweSeededKeyswitchKey32 {
        let mut ksk = ImplLweSeededKeyswitchKey::allocate(
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.lwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        ksk.fill_with_seeded_keyswitch_key::<_, _, _, _, _, ActivatedRandomGenerator>(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.seeder,
        );
        LweSeededKeyswitchKey32(ksk)
    }
}

impl LweSeededKeyswitchKeyGenerationEngine<LweSecretKey64, LweSecretKey64, LweSeededKeyswitchKey64>
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
    /// let seeded_keyswitch_key = engine.generate_new_lwe_seeded_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     seeded_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     seeded_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(seeded_keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(seeded_keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_seeded_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweSeededKeyswitchKey64, LweSeededKeyswitchKeyGenerationError<Self::EngineError>>
    {
        LweSeededKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            64,
        )?;
        Ok(unsafe {
            self.generate_new_lwe_seeded_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn generate_new_lwe_seeded_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LweSeededKeyswitchKey64 {
        let mut ksk = ImplLweSeededKeyswitchKey::allocate(
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.lwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        ksk.fill_with_seeded_keyswitch_key::<_, _, _, _, _, ActivatedRandomGenerator>(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.seeder,
        );
        LweSeededKeyswitchKey64(ksk)
    }
}
