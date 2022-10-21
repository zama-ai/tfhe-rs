use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweKeyswitchKey32, LweKeyswitchKey64, LweKeyswitchKeyMutView32, LweKeyswitchKeyMutView64,
    LweKeyswitchKeyView32, LweKeyswitchKeyView64,
};
use crate::core_crypto::commons::math::tensor::IntoTensor;
use crate::core_crypto::specification::engines::{
    LweKeyswitchKeyConsumingRetrievalEngine, LweKeyswitchKeyConsumingRetrievalError,
};

impl LweKeyswitchKeyConsumingRetrievalEngine<LweKeyswitchKey32, Vec<u32>> for DefaultEngine {
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
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// let keyswitch_key: LweKeyswitchKey32 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    /// let retrieved_container = engine.consume_retrieve_lwe_keyswitch_key(keyswitch_key)?;
    ///
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_keyswitch_key(
        &mut self,
        keyswitch_key: LweKeyswitchKey32,
    ) -> Result<Vec<u32>, LweKeyswitchKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_keyswitch_key_unchecked(keyswitch_key) })
    }

    unsafe fn consume_retrieve_lwe_keyswitch_key_unchecked(
        &mut self,
        keyswitch_key: LweKeyswitchKey32,
    ) -> Vec<u32> {
        keyswitch_key.0.into_tensor().into_container()
    }
}

impl LweKeyswitchKeyConsumingRetrievalEngine<LweKeyswitchKey64, Vec<u64>> for DefaultEngine {
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
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// let keyswitch_key: LweKeyswitchKey64 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    /// let retrieved_container = engine.consume_retrieve_lwe_keyswitch_key(keyswitch_key)?;
    ///
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_keyswitch_key(
        &mut self,
        keyswitch_key: LweKeyswitchKey64,
    ) -> Result<Vec<u64>, LweKeyswitchKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_keyswitch_key_unchecked(keyswitch_key) })
    }

    unsafe fn consume_retrieve_lwe_keyswitch_key_unchecked(
        &mut self,
        keyswitch_key: LweKeyswitchKey64,
    ) -> Vec<u64> {
        keyswitch_key.0.into_tensor().into_container()
    }
}

impl<'data>
    LweKeyswitchKeyConsumingRetrievalEngine<LweKeyswitchKeyMutView32<'data>, &'data mut [u32]>
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
    /// let slice = owned_container.as_mut_slice();
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// let keyswitch_key: LweKeyswitchKeyMutView32 = engine.create_lwe_keyswitch_key_from(
    ///     slice,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_keyswitch_key(keyswitch_key)?;
    ///
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_keyswitch_key(
        &mut self,
        keyswitch_key: LweKeyswitchKeyMutView32<'data>,
    ) -> Result<&'data mut [u32], LweKeyswitchKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_keyswitch_key_unchecked(keyswitch_key) })
    }

    unsafe fn consume_retrieve_lwe_keyswitch_key_unchecked(
        &mut self,
        keyswitch_key: LweKeyswitchKeyMutView32<'data>,
    ) -> &'data mut [u32] {
        keyswitch_key.0.into_tensor().into_container()
    }
}

impl<'data>
    LweKeyswitchKeyConsumingRetrievalEngine<LweKeyswitchKeyMutView64<'data>, &'data mut [u64]>
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
    /// let slice = owned_container.as_mut_slice();
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// let keyswitch_key: LweKeyswitchKeyMutView64 = engine.create_lwe_keyswitch_key_from(
    ///     slice,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_keyswitch_key(keyswitch_key)?;
    ///
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_keyswitch_key(
        &mut self,
        keyswitch_key: LweKeyswitchKeyMutView64<'data>,
    ) -> Result<&'data mut [u64], LweKeyswitchKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_keyswitch_key_unchecked(keyswitch_key) })
    }

    unsafe fn consume_retrieve_lwe_keyswitch_key_unchecked(
        &mut self,
        keyswitch_key: LweKeyswitchKeyMutView64<'data>,
    ) -> &'data mut [u64] {
        keyswitch_key.0.into_tensor().into_container()
    }
}

impl<'data> LweKeyswitchKeyConsumingRetrievalEngine<LweKeyswitchKeyView32<'data>, &'data [u32]>
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
    /// let slice = owned_container.as_slice();
    ///
    /// let keyswitch_key: LweKeyswitchKeyView32 = engine.create_lwe_keyswitch_key_from(
    ///     slice,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_keyswitch_key(keyswitch_key)?;
    ///
    /// assert_eq!(slice, retrieved_slice);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_keyswitch_key(
        &mut self,
        keyswitch_key: LweKeyswitchKeyView32<'data>,
    ) -> Result<&'data [u32], LweKeyswitchKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_keyswitch_key_unchecked(keyswitch_key) })
    }

    unsafe fn consume_retrieve_lwe_keyswitch_key_unchecked(
        &mut self,
        keyswitch_key: LweKeyswitchKeyView32<'data>,
    ) -> &'data [u32] {
        keyswitch_key.0.into_tensor().into_container()
    }
}

impl<'data> LweKeyswitchKeyConsumingRetrievalEngine<LweKeyswitchKeyView64<'data>, &'data [u64]>
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
    /// let slice = owned_container.as_slice();
    ///
    /// let keyswitch_key: LweKeyswitchKeyView64 = engine.create_lwe_keyswitch_key_from(
    ///     slice,
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_keyswitch_key(keyswitch_key)?;
    ///
    /// assert_eq!(slice, retrieved_slice);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_keyswitch_key(
        &mut self,
        keyswitch_key: LweKeyswitchKeyView64<'data>,
    ) -> Result<&'data [u64], LweKeyswitchKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_keyswitch_key_unchecked(keyswitch_key) })
    }

    unsafe fn consume_retrieve_lwe_keyswitch_key_unchecked(
        &mut self,
        keyswitch_key: LweKeyswitchKeyView64<'data>,
    ) -> &'data [u64] {
        keyswitch_key.0.into_tensor().into_container()
    }
}
