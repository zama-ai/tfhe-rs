use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweCiphertextMutView32, LweCiphertextMutView64,
    LweCiphertextView32, LweCiphertextView64, LweKeyswitchKey32, LweKeyswitchKey64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingKeyswitchEngine, LweCiphertextDiscardingKeyswitchError,
};

/// # Description:
/// Implementation of [`LweCiphertextDiscardingKeyswitchEngine`] for [`DefaultEngine`] that operates
/// on 32 bits integers.
impl LweCiphertextDiscardingKeyswitchEngine<LweKeyswitchKey32, LweCiphertext32, LweCiphertext32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&input_key, &plaintext, noise)?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_keyswitch_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1, &keyswitch_key)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        ksk: &LweKeyswitchKey32,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<Self::EngineError>> {
        LweCiphertextDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        ksk: &LweKeyswitchKey32,
    ) {
        ksk.0.keyswitch_ciphertext(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingKeyswitchEngine`] for [`DefaultEngine`] that operates
/// on 64 bits integers.
impl LweCiphertextDiscardingKeyswitchEngine<LweKeyswitchKey64, LweCiphertext64, LweCiphertext64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&input_key, &plaintext, noise)?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_keyswitch_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1, &keyswitch_key)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        ksk: &LweKeyswitchKey64,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<Self::EngineError>> {
        LweCiphertextDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        ksk: &LweKeyswitchKey64,
    ) {
        ksk.0.keyswitch_ciphertext(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingKeyswitchEngine`] for [`DefaultEngine`] that operates
/// on views containing 32 bits integers.
impl
    LweCiphertextDiscardingKeyswitchEngine<
        LweKeyswitchKey32,
        LweCiphertextView32<'_>,
        LweCiphertextMutView32<'_>,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let mut raw_ciphertext_1_container = vec![0_u32; input_key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_1: LweCiphertextMutView32 =
    ///     engine.create_lwe_ciphertext_from(&mut raw_ciphertext_1_container[..])?;
    /// engine.discard_encrypt_lwe_ciphertext(&input_key, &mut ciphertext_1, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_1 = engine.consume_retrieve_lwe_ciphertext(ciphertext_1)?;
    /// let ciphertext_1: LweCiphertextView32 =
    ///     engine.create_lwe_ciphertext_from(&raw_ciphertext_1[..])?;
    ///
    /// let mut raw_ciphertext_2_container = vec![0_u32; output_key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_2: LweCiphertextMutView32 =
    ///     engine.create_lwe_ciphertext_from(&mut raw_ciphertext_2_container[..])?;
    ///
    /// engine.discard_keyswitch_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1, &keyswitch_key)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView32<'_>,
        input: &LweCiphertextView32<'_>,
        ksk: &LweKeyswitchKey32,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<Self::EngineError>> {
        LweCiphertextDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView32<'_>,
        input: &LweCiphertextView32<'_>,
        ksk: &LweKeyswitchKey32,
    ) {
        ksk.0.keyswitch_ciphertext(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingKeyswitchEngine`] for [`DefaultEngine`] that operates
/// on views containing 64 bits integers.
impl
    LweCiphertextDiscardingKeyswitchEngine<
        LweKeyswitchKey64,
        LweCiphertextView64<'_>,
        LweCiphertextMutView64<'_>,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let mut raw_ciphertext_1_container = vec![0_u64; input_key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_1: LweCiphertextMutView64 =
    ///     engine.create_lwe_ciphertext_from(&mut raw_ciphertext_1_container[..])?;
    /// engine.discard_encrypt_lwe_ciphertext(&input_key, &mut ciphertext_1, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_1 = engine.consume_retrieve_lwe_ciphertext(ciphertext_1)?;
    /// let ciphertext_1: LweCiphertextView64 =
    ///     engine.create_lwe_ciphertext_from(&raw_ciphertext_1[..])?;
    ///
    /// let mut raw_ciphertext_2_container = vec![0_u64; output_key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_2: LweCiphertextMutView64 =
    ///     engine.create_lwe_ciphertext_from(&mut raw_ciphertext_2_container[..])?;
    ///
    /// engine.discard_keyswitch_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1, &keyswitch_key)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView64<'_>,
        input: &LweCiphertextView64<'_>,
        ksk: &LweKeyswitchKey64,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<Self::EngineError>> {
        LweCiphertextDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64<'_>,
        input: &LweCiphertextView64<'_>,
        ksk: &LweKeyswitchKey64,
    ) {
        ksk.0.keyswitch_ciphertext(&mut output.0, &input.0);
    }
}
