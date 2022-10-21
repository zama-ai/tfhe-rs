use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, Plaintext32, Plaintext64,
};
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::specification::engines::{
    LweCiphertextPlaintextDiscardingSubtractionEngine,
    LweCiphertextPlaintextDiscardingSubtractionError,
};

/// # Description:
/// Implementation of [`LweCiphertextPlaintextDiscardingSubtractionEngine`] for [`DefaultEngine`]
/// that operates on 32 bits integers.
impl
    LweCiphertextPlaintextDiscardingSubtractionEngine<LweCiphertext32, Plaintext32, LweCiphertext32>
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
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_sub_lwe_ciphertext_plaintext(&mut ciphertext_2, &ciphertext_1, &plaintext)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_sub_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Plaintext32,
    ) -> Result<(), LweCiphertextPlaintextDiscardingSubtractionError<Self::EngineError>> {
        LweCiphertextPlaintextDiscardingSubtractionError::perform_generic_checks(output, input_1)?;
        unsafe { self.discard_sub_lwe_ciphertext_plaintext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_sub_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Plaintext32,
    ) {
        output
            .0
            .as_mut_tensor()
            .fill_with_copy(input_1.0.as_tensor());
        output.0.get_mut_body().0 = output.0.get_body().0.wrapping_sub(input_2.0 .0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextPlaintextDiscardingSubtractionEngine`] for [`DefaultEngine`]
/// that operates on 64 bits integers.
impl
    LweCiphertextPlaintextDiscardingSubtractionEngine<LweCiphertext64, Plaintext64, LweCiphertext64>
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
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_sub_lwe_ciphertext_plaintext(&mut ciphertext_2, &ciphertext_1, &plaintext)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_sub_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Plaintext64,
    ) -> Result<(), LweCiphertextPlaintextDiscardingSubtractionError<Self::EngineError>> {
        LweCiphertextPlaintextDiscardingSubtractionError::perform_generic_checks(output, input_1)?;
        unsafe { self.discard_sub_lwe_ciphertext_plaintext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_sub_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Plaintext64,
    ) {
        output
            .0
            .as_mut_tensor()
            .fill_with_copy(input_1.0.as_tensor());
        output.0.get_mut_body().0 = output.0.get_body().0.wrapping_sub(input_2.0 .0);
    }
}
