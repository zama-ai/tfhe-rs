use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweKeyswitchKey32, LweKeyswitchKey64, LweKeyswitchKeyMutView32, LweKeyswitchKeyMutView64,
    LweKeyswitchKeyView32, LweKeyswitchKeyView64,
};
use crate::core_crypto::commons::crypto::lwe::LweKeyswitchKey as ImplLweKeyswitchKey;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
use crate::core_crypto::specification::engines::{
    LweKeyswitchKeyCreationEngine, LweKeyswitchKeyCreationError,
};

impl LweKeyswitchKeyCreationEngine<Vec<u32>, LweKeyswitchKey32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let owned_container = vec![
    ///     0u32;
    ///     input_lwe_dimension.0
    ///         * output_lwe_dimension.to_lwe_size().0
    ///         * decomposition_level_count.0
    /// ];
    ///
    /// let keyswitch_key: LweKeyswitchKey32 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// assert_eq!(
    ///     keyswitch_key.decomposition_level_count(),
    ///     decomposition_level_count
    /// );
    /// assert_eq!(
    ///     keyswitch_key.decomposition_base_log(),
    ///     decomposition_base_log
    /// );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key_from(
        &mut self,
        container: Vec<u32>,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweKeyswitchKey32, LweKeyswitchKeyCreationError<Self::EngineError>> {
        LweKeyswitchKeyCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;

        Ok(unsafe {
            self.create_lwe_keyswitch_key_from_unchecked(
                container,
                output_lwe_dimension,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_from_unchecked(
        &mut self,
        container: Vec<u32>,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweKeyswitchKey32 {
        LweKeyswitchKey32(ImplLweKeyswitchKey::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            output_lwe_dimension,
        ))
    }
}

impl LweKeyswitchKeyCreationEngine<Vec<u64>, LweKeyswitchKey64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let owned_container = vec![
    ///     0u64;
    ///     input_lwe_dimension.0
    ///         * output_lwe_dimension.to_lwe_size().0
    ///         * decomposition_level_count.0
    /// ];
    ///
    /// let keyswitch_key: LweKeyswitchKey64 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// assert_eq!(
    ///     keyswitch_key.decomposition_level_count(),
    ///     decomposition_level_count
    /// );
    /// assert_eq!(
    ///     keyswitch_key.decomposition_base_log(),
    ///     decomposition_base_log
    /// );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key_from(
        &mut self,
        container: Vec<u64>,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweKeyswitchKey64, LweKeyswitchKeyCreationError<Self::EngineError>> {
        LweKeyswitchKeyCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;

        Ok(unsafe {
            self.create_lwe_keyswitch_key_from_unchecked(
                container,
                output_lwe_dimension,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_from_unchecked(
        &mut self,
        container: Vec<u64>,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweKeyswitchKey64 {
        LweKeyswitchKey64(ImplLweKeyswitchKey::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            output_lwe_dimension,
        ))
    }
}

impl<'data> LweKeyswitchKeyCreationEngine<&'data mut [u32], LweKeyswitchKeyMutView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut owned_container = vec![
    ///     0u32;
    ///     input_lwe_dimension.0
    ///         * output_lwe_dimension.to_lwe_size().0
    ///         * decomposition_level_count.0
    /// ];
    ///
    /// let keyswitch_key: LweKeyswitchKeyMutView32 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container.as_mut_slice(),
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// assert_eq!(
    ///     keyswitch_key.decomposition_level_count(),
    ///     decomposition_level_count
    /// );
    /// assert_eq!(
    ///     keyswitch_key.decomposition_base_log(),
    ///     decomposition_base_log
    /// );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key_from(
        &mut self,
        container: &'data mut [u32],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweKeyswitchKeyMutView32<'data>, LweKeyswitchKeyCreationError<Self::EngineError>>
    {
        LweKeyswitchKeyCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;

        Ok(unsafe {
            self.create_lwe_keyswitch_key_from_unchecked(
                container,
                output_lwe_dimension,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_from_unchecked(
        &mut self,
        container: &'data mut [u32],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweKeyswitchKeyMutView32<'data> {
        LweKeyswitchKeyMutView32(ImplLweKeyswitchKey::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            output_lwe_dimension,
        ))
    }
}

impl<'data> LweKeyswitchKeyCreationEngine<&'data mut [u64], LweKeyswitchKeyMutView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut owned_container = vec![
    ///     0u64;
    ///     input_lwe_dimension.0
    ///         * output_lwe_dimension.to_lwe_size().0
    ///         * decomposition_level_count.0
    /// ];
    ///
    /// let keyswitch_key: LweKeyswitchKeyMutView64 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container.as_mut_slice(),
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// assert_eq!(
    ///     keyswitch_key.decomposition_level_count(),
    ///     decomposition_level_count
    /// );
    /// assert_eq!(
    ///     keyswitch_key.decomposition_base_log(),
    ///     decomposition_base_log
    /// );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key_from(
        &mut self,
        container: &'data mut [u64],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweKeyswitchKeyMutView64<'data>, LweKeyswitchKeyCreationError<Self::EngineError>>
    {
        LweKeyswitchKeyCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;

        Ok(unsafe {
            self.create_lwe_keyswitch_key_from_unchecked(
                container,
                output_lwe_dimension,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_from_unchecked(
        &mut self,
        container: &'data mut [u64],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweKeyswitchKeyMutView64<'data> {
        LweKeyswitchKeyMutView64(ImplLweKeyswitchKey::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            output_lwe_dimension,
        ))
    }
}

impl<'data> LweKeyswitchKeyCreationEngine<&'data [u32], LweKeyswitchKeyView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let owned_container = vec![
    ///     0u32;
    ///     input_lwe_dimension.0
    ///         * output_lwe_dimension.to_lwe_size().0
    ///         * decomposition_level_count.0
    /// ];
    ///
    /// let keyswitch_key: LweKeyswitchKeyView32 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container.as_slice(),
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// assert_eq!(
    ///     keyswitch_key.decomposition_level_count(),
    ///     decomposition_level_count
    /// );
    /// assert_eq!(
    ///     keyswitch_key.decomposition_base_log(),
    ///     decomposition_base_log
    /// );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key_from(
        &mut self,
        container: &'data [u32],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweKeyswitchKeyView32<'data>, LweKeyswitchKeyCreationError<Self::EngineError>> {
        LweKeyswitchKeyCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;

        Ok(unsafe {
            self.create_lwe_keyswitch_key_from_unchecked(
                container,
                output_lwe_dimension,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_from_unchecked(
        &mut self,
        container: &'data [u32],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweKeyswitchKeyView32<'data> {
        LweKeyswitchKeyView32(ImplLweKeyswitchKey::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            output_lwe_dimension,
        ))
    }
}

impl<'data> LweKeyswitchKeyCreationEngine<&'data [u64], LweKeyswitchKeyView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let owned_container = vec![
    ///     0u64;
    ///     input_lwe_dimension.0
    ///         * output_lwe_dimension.to_lwe_size().0
    ///         * decomposition_level_count.0
    /// ];
    ///
    /// let keyswitch_key: LweKeyswitchKeyView64 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container.as_slice(),
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// assert_eq!(
    ///     keyswitch_key.decomposition_level_count(),
    ///     decomposition_level_count
    /// );
    /// assert_eq!(
    ///     keyswitch_key.decomposition_base_log(),
    ///     decomposition_base_log
    /// );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key_from(
        &mut self,
        container: &'data [u64],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweKeyswitchKeyView64<'data>, LweKeyswitchKeyCreationError<Self::EngineError>> {
        LweKeyswitchKeyCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;

        Ok(unsafe {
            self.create_lwe_keyswitch_key_from_unchecked(
                container,
                output_lwe_dimension,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_from_unchecked(
        &mut self,
        container: &'data [u64],
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweKeyswitchKeyView64<'data> {
        LweKeyswitchKeyView64(ImplLweKeyswitchKey::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            output_lwe_dimension,
        ))
    }
}
