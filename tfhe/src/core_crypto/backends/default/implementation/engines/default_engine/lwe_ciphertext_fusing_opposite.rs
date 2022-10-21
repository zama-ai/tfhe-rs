use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextFusingOppositeEngine, LweCiphertextFusingOppositeError,
};

/// # Description:
/// Implementation of [`LweCiphertextFusingOppositeEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl LweCiphertextFusingOppositeEngine<LweCiphertext32> for DefaultEngine {
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
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// engine.fuse_opp_lwe_ciphertext(&mut ciphertext)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_opp_lwe_ciphertext(
        &mut self,
        input: &mut LweCiphertext32,
    ) -> Result<(), LweCiphertextFusingOppositeError<Self::EngineError>> {
        unsafe { self.fuse_opp_lwe_ciphertext_unchecked(input) };
        Ok(())
    }

    unsafe fn fuse_opp_lwe_ciphertext_unchecked(&mut self, input: &mut LweCiphertext32) {
        input.0.update_with_neg();
    }
}

/// # Description:
/// Implementation of [`LweCiphertextFusingOppositeEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl LweCiphertextFusingOppositeEngine<LweCiphertext64> for DefaultEngine {
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
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// engine.fuse_opp_lwe_ciphertext(&mut ciphertext)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_opp_lwe_ciphertext(
        &mut self,
        input: &mut LweCiphertext64,
    ) -> Result<(), LweCiphertextFusingOppositeError<Self::EngineError>> {
        unsafe { self.fuse_opp_lwe_ciphertext_unchecked(input) };
        Ok(())
    }

    unsafe fn fuse_opp_lwe_ciphertext_unchecked(&mut self, input: &mut LweCiphertext64) {
        input.0.update_with_neg();
    }
}
