use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64,
};
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingSubtractionEngine, LweCiphertextDiscardingSubtractionError,
};

/// # Description:
/// Implementation of [`LweCiphertextDiscardingSubtractionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextDiscardingSubtractionEngine<LweCiphertext32, LweCiphertext32> for DefaultEngine {
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
    /// let input_2 = 7_u32 << 20;
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
    /// let ciphertext_2 = engine.encrypt_lwe_ciphertext(&key, &plaintext_2, noise)?;
    /// let mut ciphertext_3 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_sub_lwe_ciphertext(&mut ciphertext_3, &ciphertext_1, &ciphertext_2)?;
    /// #
    /// assert_eq!(ciphertext_3.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_sub_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &LweCiphertext32,
    ) -> Result<(), LweCiphertextDiscardingSubtractionError<Self::EngineError>> {
        LweCiphertextDiscardingSubtractionError::perform_generic_checks(output, input_1, input_2)?;
        unsafe { self.discard_sub_lwe_ciphertext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_sub_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &LweCiphertext32,
    ) {
        output
            .0
            .as_mut_tensor()
            .fill_with_copy(input_1.0.as_tensor());
        output.0.update_with_sub(&input_2.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingSubtractionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextDiscardingSubtractionEngine<LweCiphertext64, LweCiphertext64> for DefaultEngine {
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
    /// let input_2 = 7_u64 << 50;
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
    /// let ciphertext_2 = engine.encrypt_lwe_ciphertext(&key, &plaintext_2, noise)?;
    /// let mut ciphertext_3 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_sub_lwe_ciphertext(&mut ciphertext_3, &ciphertext_1, &ciphertext_2)?;
    /// #
    /// assert_eq!(ciphertext_3.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_sub_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &LweCiphertext64,
    ) -> Result<(), LweCiphertextDiscardingSubtractionError<Self::EngineError>> {
        LweCiphertextDiscardingSubtractionError::perform_generic_checks(output, input_1, input_2)?;
        unsafe { self.discard_sub_lwe_ciphertext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_sub_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &LweCiphertext64,
    ) {
        output
            .0
            .as_mut_tensor()
            .fill_with_copy(input_1.0.as_tensor());
        output.0.update_with_sub(&input_2.0);
    }
}
