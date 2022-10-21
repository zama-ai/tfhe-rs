use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    LweKeyswitchKey32, LweKeyswitchKey64, LweSeededKeyswitchKey32, LweSeededKeyswitchKey64,
};
use crate::core_crypto::commons::crypto::lwe::LweKeyswitchKey as ImplLweKeyswitchKey;
use crate::core_crypto::specification::engines::{
    LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine,
    LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationError,
};
use crate::core_crypto::specification::entities::LweSeededKeyswitchKeyEntity;

impl
    LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine<
        LweSeededKeyswitchKey32,
        LweKeyswitchKey32,
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
    ///
    /// let keyswitch_key = engine.transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key(seeded_keyswitch_key)?;
    ///
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
    fn transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key(
        &mut self,
        lwe_seeded_keyswitch_key: LweSeededKeyswitchKey32,
    ) -> Result<
        LweKeyswitchKey32,
        LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked(
                lwe_seeded_keyswitch_key,
            )
        })
    }

    unsafe fn transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked(
        &mut self,
        lwe_seeded_keyswitch_key: LweSeededKeyswitchKey32,
    ) -> LweKeyswitchKey32 {
        let mut ksk = ImplLweKeyswitchKey::allocate(
            0,
            lwe_seeded_keyswitch_key.decomposition_level_count(),
            lwe_seeded_keyswitch_key.decomposition_base_log(),
            lwe_seeded_keyswitch_key.input_lwe_dimension(),
            lwe_seeded_keyswitch_key.output_lwe_dimension(),
        );

        lwe_seeded_keyswitch_key
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut ksk);

        LweKeyswitchKey32(ksk)
    }
}

impl
    LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine<
        LweSeededKeyswitchKey64,
        LweKeyswitchKey64,
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
    ///
    /// let keyswitch_key = engine.transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key(seeded_keyswitch_key)?;
    ///
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
    fn transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key(
        &mut self,
        lwe_seeded_keyswitch_key: LweSeededKeyswitchKey64,
    ) -> Result<
        LweKeyswitchKey64,
        LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked(
                lwe_seeded_keyswitch_key,
            )
        })
    }

    unsafe fn transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked(
        &mut self,
        lwe_seeded_keyswitch_key: LweSeededKeyswitchKey64,
    ) -> LweKeyswitchKey64 {
        let mut ksk = ImplLweKeyswitchKey::allocate(
            0,
            lwe_seeded_keyswitch_key.decomposition_level_count(),
            lwe_seeded_keyswitch_key.decomposition_base_log(),
            lwe_seeded_keyswitch_key.input_lwe_dimension(),
            lwe_seeded_keyswitch_key.output_lwe_dimension(),
        );

        lwe_seeded_keyswitch_key
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut ksk);

        LweKeyswitchKey64(ksk)
    }
}
