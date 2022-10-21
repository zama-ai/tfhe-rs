use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    Cleartext32, Cleartext64, LweCiphertext32, LweCiphertext64, LweCiphertextMutView32,
    LweCiphertextMutView64, LweCiphertextView32, LweCiphertextView64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextCleartextDiscardingMultiplicationEngine,
    LweCiphertextCleartextDiscardingMultiplicationError,
};

/// # Description:
/// Implementation of [`LweCiphertextCleartextDiscardingMultiplicationEngine`] for [`DefaultEngine`]
/// that operates on 32 bits integers.
impl
    LweCiphertextCleartextDiscardingMultiplicationEngine<
        LweCiphertext32,
        Cleartext32,
        LweCiphertext32,
    > for DefaultEngine
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
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let mut ciphertext_2 =
    ///     engine.trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &plaintext)?;
    ///
    /// engine.discard_mul_lwe_ciphertext_cleartext(&mut ciphertext_2, &ciphertext_1, &cleartext)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Cleartext32,
    ) -> Result<(), LweCiphertextCleartextDiscardingMultiplicationError<Self::EngineError>> {
        LweCiphertextCleartextDiscardingMultiplicationError::perform_generic_checks(
            output, input_1,
        )?;
        unsafe { self.discard_mul_lwe_ciphertext_cleartext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Cleartext32,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCleartextDiscardingMultiplicationEngine`] for [`DefaultEngine`]
/// that operates on 64 bits integers.
impl
    LweCiphertextCleartextDiscardingMultiplicationEngine<
        LweCiphertext64,
        Cleartext64,
        LweCiphertext64,
    > for DefaultEngine
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
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&cleartext_input)?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let ciphertext_1 = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let mut ciphertext_2 =
    ///     engine.trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &plaintext)?;
    ///
    /// engine.discard_mul_lwe_ciphertext_cleartext(&mut ciphertext_2, &ciphertext_1, &cleartext)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Cleartext64,
    ) -> Result<(), LweCiphertextCleartextDiscardingMultiplicationError<Self::EngineError>> {
        LweCiphertextCleartextDiscardingMultiplicationError::perform_generic_checks(
            output, input_1,
        )?;
        unsafe { self.discard_mul_lwe_ciphertext_cleartext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Cleartext64,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCleartextDiscardingMultiplicationEngine`] for [`DefaultEngine`]
/// that operates on views containing 32 bits integers.
impl
    LweCiphertextCleartextDiscardingMultiplicationEngine<
        LweCiphertextView32<'_>,
        Cleartext32,
        LweCiphertextMutView32<'_>,
    > for DefaultEngine
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
    /// engine.discard_mul_lwe_ciphertext_cleartext(&mut ciphertext_2, &ciphertext_1, &cleartext)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input_1: &LweCiphertextView32,
        input_2: &Cleartext32,
    ) -> Result<(), LweCiphertextCleartextDiscardingMultiplicationError<Self::EngineError>> {
        LweCiphertextCleartextDiscardingMultiplicationError::perform_generic_checks(
            output, input_1,
        )?;
        unsafe { self.discard_mul_lwe_ciphertext_cleartext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input_1: &LweCiphertextView32,
        input_2: &Cleartext32,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCleartextDiscardingMultiplicationEngine`] for [`DefaultEngine`]
/// that operates on views containing 64 bits integers.
impl
    LweCiphertextCleartextDiscardingMultiplicationEngine<
        LweCiphertextView64<'_>,
        Cleartext64,
        LweCiphertextMutView64<'_>,
    > for DefaultEngine
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
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&cleartext_input)?;
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
    /// engine.discard_mul_lwe_ciphertext_cleartext(&mut ciphertext_2, &ciphertext_1, &cleartext)?;
    /// #
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input_1: &LweCiphertextView64,
        input_2: &Cleartext64,
    ) -> Result<(), LweCiphertextCleartextDiscardingMultiplicationError<Self::EngineError>> {
        LweCiphertextCleartextDiscardingMultiplicationError::perform_generic_checks(
            output, input_1,
        )?;
        unsafe { self.discard_mul_lwe_ciphertext_cleartext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input_1: &LweCiphertextView64,
        input_2: &Cleartext64,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}
