use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    Cleartext32, Cleartext64, LweCiphertext32, LweCiphertext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextCleartextFusingMultiplicationEngine,
    LweCiphertextCleartextFusingMultiplicationError,
};

/// # Description:
/// Implementation of [`LweCiphertextCleartextFusingMultiplicationEngine`] for [`DefaultEngine`]
/// that operates on 32 bits integers.
impl LweCiphertextCleartextFusingMultiplicationEngine<LweCiphertext32, Cleartext32>
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
    /// let cleartext_input = 12_u32;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext32 = engine.create_cleartext_from(&cleartext_input)?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// engine.fuse_mul_lwe_ciphertext_cleartext(&mut ciphertext, &cleartext)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) -> Result<(), LweCiphertextCleartextFusingMultiplicationError<Self::EngineError>> {
        unsafe { self.fuse_mul_lwe_ciphertext_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCleartextFusingMultiplicationEngine`] for [`DefaultEngine`]
/// that operates on 64 bits integers.
impl LweCiphertextCleartextFusingMultiplicationEngine<LweCiphertext64, Cleartext64>
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
    /// let cleartext_input = 12_u64;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&cleartext_input)?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// engine.fuse_mul_lwe_ciphertext_cleartext(&mut ciphertext, &cleartext)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) -> Result<(), LweCiphertextCleartextFusingMultiplicationError<Self::EngineError>> {
        unsafe { self.fuse_mul_lwe_ciphertext_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}
