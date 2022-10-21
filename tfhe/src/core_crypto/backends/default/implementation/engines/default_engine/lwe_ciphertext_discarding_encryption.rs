use crate::core_crypto::prelude::Variance;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweCiphertextMutView32, LweCiphertextMutView64,
    LweSecretKey32, LweSecretKey64, Plaintext32, Plaintext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingEncryptionEngine, LweCiphertextDiscardingEncryptionError,
};

/// # Description:
/// Implementation of [`LweCiphertextDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextDiscardingEncryptionEngine<LweSecretKey32, Plaintext32, LweCiphertext32>
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
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut ciphertext, &plaintext, noise)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
        noise: Variance,
    ) -> Result<(), LweCiphertextDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextDiscardingEncryptionError::perform_generic_checks(key, output)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextDiscardingEncryptionEngine<LweSecretKey64, Plaintext64, LweCiphertext64>
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
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut ciphertext, &plaintext, noise)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<(), LweCiphertextDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextDiscardingEncryptionError::perform_generic_checks(key, output)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextDiscardingEncryptionEngine<LweSecretKey32, Plaintext32, LweCiphertextMutView32<'_>>
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
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let mut output_cipertext_container = vec![0_32; lwe_dimension.to_lwe_size().0];
    /// let mut output_ciphertext: LweCiphertextMutView32 =
    ///     engine.create_lwe_ciphertext_from(&mut output_cipertext_container[..])?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut output_ciphertext, &plaintext, noise)?;
    /// #
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextMutView32,
        input: &Plaintext32,
        noise: Variance,
    ) -> Result<(), LweCiphertextDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextDiscardingEncryptionError::perform_generic_checks(key, output)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextMutView32,
        input: &Plaintext32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextDiscardingEncryptionEngine<LweSecretKey64, Plaintext64, LweCiphertextMutView64<'_>>
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
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let mut output_cipertext_container = vec![0_64; lwe_dimension.to_lwe_size().0];
    /// let mut output_ciphertext: LweCiphertextMutView64 =
    ///     engine.create_lwe_ciphertext_from(&mut output_cipertext_container[..])?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut output_ciphertext, &plaintext, noise)?;
    /// #
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextMutView64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<(), LweCiphertextDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextDiscardingEncryptionError::perform_generic_checks(key, output)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextMutView64,
        input: &Plaintext64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
