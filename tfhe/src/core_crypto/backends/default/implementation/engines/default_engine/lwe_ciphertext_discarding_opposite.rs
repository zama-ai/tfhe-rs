use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweCiphertextMutView32, LweCiphertextMutView64,
    LweCiphertextView32, LweCiphertextView64,
};
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingOppositeEngine, LweCiphertextDiscardingOppositeError,
};

/// # Description:
/// Implementation of [`LweCiphertextDiscardingOppositeEngine`] for [`DefaultEngine`] that operates
/// on 32 bits integers.
impl LweCiphertextDiscardingOppositeEngine<LweCiphertext32, LweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_opp_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_opp_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweCiphertextDiscardingOppositeError<Self::EngineError>> {
        LweCiphertextDiscardingOppositeError::perform_generic_checks(output, input)?;
        unsafe { self.discard_opp_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_opp_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
        output.0.update_with_neg();
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingOppositeEngine`] for [`DefaultEngine`] that operates
/// on 64 bits integers.
impl LweCiphertextDiscardingOppositeEngine<LweCiphertext64, LweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_opp_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_opp_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweCiphertextDiscardingOppositeError<Self::EngineError>> {
        LweCiphertextDiscardingOppositeError::perform_generic_checks(output, input)?;
        unsafe { self.discard_opp_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_opp_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
        output.0.update_with_neg();
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingOppositeEngine`] for [`DefaultEngine`] that operates
/// on views containing 32 bits integers.
impl LweCiphertextDiscardingOppositeEngine<LweCiphertextView32<'_>, LweCiphertextMutView32<'_>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let mut ciphertext_1_container = vec![0_u32; key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_1: LweCiphertextMutView32 =
    ///     engine.create_lwe_ciphertext_from(&mut ciphertext_1_container[..])?;
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut ciphertext_1, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_1 = engine.consume_retrieve_lwe_ciphertext(ciphertext_1)?;
    /// let ciphertext_1: LweCiphertextView32 =
    ///     engine.create_lwe_ciphertext_from(&raw_ciphertext_1[..])?;
    ///
    /// let mut ciphertext_2_container = vec![0_u32; key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_2: LweCiphertextMutView32 =
    ///     engine.create_lwe_ciphertext_from(&mut ciphertext_2_container[..])?;
    ///
    /// engine.discard_opp_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_opp_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input: &LweCiphertextView32,
    ) -> Result<(), LweCiphertextDiscardingOppositeError<Self::EngineError>> {
        LweCiphertextDiscardingOppositeError::perform_generic_checks(output, input)?;
        unsafe { self.discard_opp_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_opp_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input: &LweCiphertextView32,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
        output.0.update_with_neg();
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingOppositeEngine`] for [`DefaultEngine`] that operates
/// on views containing 64 bits integers.
impl LweCiphertextDiscardingOppositeEngine<LweCiphertextView64<'_>, LweCiphertextMutView64<'_>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let mut ciphertext_1_container = vec![0_u64; key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_1: LweCiphertextMutView64 =
    ///     engine.create_lwe_ciphertext_from(&mut ciphertext_1_container[..])?;
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut ciphertext_1, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_1 = engine.consume_retrieve_lwe_ciphertext(ciphertext_1)?;
    /// let ciphertext_1: LweCiphertextView64 =
    ///     engine.create_lwe_ciphertext_from(&raw_ciphertext_1[..])?;
    ///
    /// let mut ciphertext_2_container = vec![0_u64; key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_2: LweCiphertextMutView64 =
    ///     engine.create_lwe_ciphertext_from(&mut ciphertext_2_container[..])?;
    ///
    /// engine.discard_opp_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_opp_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &LweCiphertextView64,
    ) -> Result<(), LweCiphertextDiscardingOppositeError<Self::EngineError>> {
        LweCiphertextDiscardingOppositeError::perform_generic_checks(output, input)?;
        unsafe { self.discard_opp_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_opp_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &LweCiphertextView64,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
        output.0.update_with_neg();
    }
}
