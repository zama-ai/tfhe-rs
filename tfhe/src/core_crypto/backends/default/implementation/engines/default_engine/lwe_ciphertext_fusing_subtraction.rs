use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextFusingSubtractionEngine, LweCiphertextFusingSubtractionError,
};

/// # Description:
/// Implementation of [`LweCiphertextFusingSubtractionEngine`] for [`DefaultEngine`] that operates
/// on 32 bits integers.
impl LweCiphertextFusingSubtractionEngine<LweCiphertext32, LweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_1 = 3_u32 << 20;
    /// let input_2 = 5_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_1 = engine.create_plaintext_from(&input_1)?;
    /// let plaintext_2 = engine.create_plaintext_from(&input_2)?;
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext_1, noise)?;
    /// let mut ciphertext_2 = engine.encrypt_lwe_ciphertext(&key, &plaintext_2, noise)?;
    ///
    /// engine.fuse_sub_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_sub_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweCiphertextFusingSubtractionError<Self::EngineError>> {
        LweCiphertextFusingSubtractionError::perform_generic_checks(output, input)?;
        unsafe { self.fuse_sub_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_sub_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) {
        output.0.update_with_sub(&input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextFusingSubtractionEngine`] for [`DefaultEngine`] that operates
/// on 64 bits integers.
impl LweCiphertextFusingSubtractionEngine<LweCiphertext64, LweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_1 = 3_u64 << 50;
    /// let input_2 = 5_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_1 = engine.create_plaintext_from(&input_1)?;
    /// let plaintext_2 = engine.create_plaintext_from(&input_2)?;
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext_1, noise)?;
    /// let mut ciphertext_2 = engine.encrypt_lwe_ciphertext(&key, &plaintext_2, noise)?;
    ///
    /// engine.fuse_sub_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_sub_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweCiphertextFusingSubtractionError<Self::EngineError>> {
        LweCiphertextFusingSubtractionError::perform_generic_checks(output, input)?;
        unsafe { self.fuse_sub_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_sub_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) {
        output.0.update_with_sub(&input.0);
    }
}
