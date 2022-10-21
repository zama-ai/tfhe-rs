use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LwePublicKey32, LwePublicKey64, Plaintext32, Plaintext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingPublicKeyEncryptionEngine,
    LweCiphertextDiscardingPublicKeyEncryptionError,
};
use crate::core_crypto::specification::entities::LwePublicKeyEntity;

/// # Description:
/// Implementation of [`LweCiphertextDiscardingPublicKeyEncryptionEngine`] for [`DefaultEngine`]
/// that operates on 32 bits integers.
impl LweCiphertextDiscardingPublicKeyEncryptionEngine<LwePublicKey32, Plaintext32, LweCiphertext32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let lwe_public_key_zero_encryption_count = LwePublicKeyZeroEncryptionCount(7);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let secret_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let public_key: LwePublicKey32 = engine.generate_new_lwe_public_key(
    ///     &secret_key,
    ///     noise,
    ///     lwe_public_key_zero_encryption_count,
    /// )?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext_container = vec![0u32; lwe_dimension.to_lwe_size().0];
    ///
    /// let mut ciphertext = engine.create_lwe_ciphertext_from(ciphertext_container)?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_with_public_key(
    ///     &public_key,
    ///     &mut ciphertext,
    ///     &plaintext,
    /// )?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_with_public_key(
        &mut self,
        key: &LwePublicKey32,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) -> Result<(), LweCiphertextDiscardingPublicKeyEncryptionError<Self::EngineError>> {
        LweCiphertextDiscardingPublicKeyEncryptionError::perform_generic_checks(key, output)?;
        unsafe {
            self.discard_encrypt_lwe_ciphertext_with_public_key_unchecked(key, output, input)
        };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_with_public_key_unchecked(
        &mut self,
        key: &LwePublicKey32,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) {
        // Fills output masks with zeros, store input in the body
        output.0.fill_with_trivial_encryption(&input.0);
        let ct_choice = self
            .secret_generator
            .random_binary_tensor::<u32>(key.lwe_zero_encryption_count().0);

        // Add the public encryption of zeros to get the encryption
        for (&chosen, public_encryption_of_zero) in
            ct_choice.as_container().iter().zip(key.0.ciphertext_iter())
        {
            if chosen == 1 {
                output.0.update_with_add(&public_encryption_of_zero);
            }
        }
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingPublicKeyEncryptionEngine`] for [`DefaultEngine`]
/// that operates on 64 bits integers.
impl LweCiphertextDiscardingPublicKeyEncryptionEngine<LwePublicKey64, Plaintext64, LweCiphertext64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let lwe_public_key_zero_encryption_count = LwePublicKeyZeroEncryptionCount(7);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let secret_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let public_key: LwePublicKey64 = engine.generate_new_lwe_public_key(
    ///     &secret_key,
    ///     noise,
    ///     lwe_public_key_zero_encryption_count,
    /// )?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext_container = vec![0u64; lwe_dimension.to_lwe_size().0];
    ///
    /// let mut ciphertext = engine.create_lwe_ciphertext_from(ciphertext_container)?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_with_public_key(
    ///     &public_key,
    ///     &mut ciphertext,
    ///     &plaintext,
    /// )?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_with_public_key(
        &mut self,
        key: &LwePublicKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) -> Result<(), LweCiphertextDiscardingPublicKeyEncryptionError<Self::EngineError>> {
        LweCiphertextDiscardingPublicKeyEncryptionError::perform_generic_checks(key, output)?;
        unsafe {
            self.discard_encrypt_lwe_ciphertext_with_public_key_unchecked(key, output, input)
        };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_with_public_key_unchecked(
        &mut self,
        key: &LwePublicKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) {
        // Fills output masks with zeros, store input in the body
        output.0.fill_with_trivial_encryption(&input.0);
        let ct_choice = self
            .secret_generator
            .random_binary_tensor::<u64>(key.lwe_zero_encryption_count().0);

        // Add the public encryption of zeros to get the encryption
        for (&chosen, public_encryption_of_zero) in
            ct_choice.as_container().iter().zip(key.0.ciphertext_iter())
        {
            if chosen == 1 {
                output.0.update_with_add(&public_encryption_of_zero);
            }
        }
    }
}
