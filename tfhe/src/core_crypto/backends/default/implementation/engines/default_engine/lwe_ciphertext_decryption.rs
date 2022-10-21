use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweCiphertextView32, LweCiphertextView64, LweSecretKey32,
    LweSecretKey64, Plaintext32, Plaintext64,
};
use crate::core_crypto::commons::crypto::encoding::Plaintext as ImplPlaintext;
use crate::core_crypto::specification::engines::{
    LweCiphertextDecryptionEngine, LweCiphertextDecryptionError,
};

/// # Description:
/// Implementation of [`LweCiphertextDecryptionEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl LweCiphertextDecryptionEngine<LweSecretKey32, LweCiphertext32, Plaintext32> for DefaultEngine {
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
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &ciphertext)?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertext32,
    ) -> Result<Plaintext32, LweCiphertextDecryptionError<Self::EngineError>> {
        Ok(unsafe { self.decrypt_lwe_ciphertext_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertext32,
    ) -> Plaintext32 {
        let mut plaintext = ImplPlaintext(0u32);
        key.0.decrypt_lwe(&mut plaintext, &input.0);
        Plaintext32(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDecryptionEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl LweCiphertextDecryptionEngine<LweSecretKey64, LweCiphertext64, Plaintext64> for DefaultEngine {
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
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &ciphertext)?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertext64,
    ) -> Result<Plaintext64, LweCiphertextDecryptionError<Self::EngineError>> {
        Ok(unsafe { self.decrypt_lwe_ciphertext_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertext64,
    ) -> Plaintext64 {
        let mut plaintext = ImplPlaintext(0u64);
        key.0.decrypt_lwe(&mut plaintext, &input.0);
        Plaintext64(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDecryptionEngine`] for [`DefaultEngine`] that operates on
/// an [`LweCiphertextView32`] containing 32 bits integers.
impl LweCiphertextDecryptionEngine<LweSecretKey32, LweCiphertextView32<'_>, Plaintext32>
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
    /// let mut raw_ciphertext = vec![0_u32; key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_view: LweCiphertextMutView32 =
    ///     engine.create_lwe_ciphertext_from(&mut raw_ciphertext[..])?;
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut ciphertext_view, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext = engine.consume_retrieve_lwe_ciphertext(ciphertext_view)?;
    /// let ciphertext_view: LweCiphertextView32 =
    ///     engine.create_lwe_ciphertext_from(&raw_ciphertext[..])?;
    ///
    /// let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &ciphertext_view)?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextView32<'_>,
    ) -> Result<Plaintext32, LweCiphertextDecryptionError<Self::EngineError>> {
        Ok(unsafe { self.decrypt_lwe_ciphertext_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextView32<'_>,
    ) -> Plaintext32 {
        let mut plaintext = ImplPlaintext(0u32);
        key.0.decrypt_lwe(&mut plaintext, &input.0);
        Plaintext32(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDecryptionEngine`] for [`DefaultEngine`] that operates on
/// an [`LweCiphertextView64`] containing 64 bits integers.
impl LweCiphertextDecryptionEngine<LweSecretKey64, LweCiphertextView64<'_>, Plaintext64>
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
    /// let input = 3_u64 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let mut raw_ciphertext = vec![0_u64; key.lwe_dimension().to_lwe_size().0];
    /// let mut ciphertext_view: LweCiphertextMutView64 =
    ///     engine.create_lwe_ciphertext_from(&mut raw_ciphertext[..])?;
    /// engine.discard_encrypt_lwe_ciphertext(&key, &mut ciphertext_view, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext = engine.consume_retrieve_lwe_ciphertext(ciphertext_view)?;
    /// let ciphertext_view: LweCiphertextView64 =
    ///     engine.create_lwe_ciphertext_from(&raw_ciphertext[..])?;
    ///
    /// let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &ciphertext_view)?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextView64<'_>,
    ) -> Result<Plaintext64, LweCiphertextDecryptionError<Self::EngineError>> {
        Ok(unsafe { self.decrypt_lwe_ciphertext_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextView64<'_>,
    ) -> Plaintext64 {
        let mut plaintext = ImplPlaintext(0u64);
        key.0.decrypt_lwe(&mut plaintext, &input.0);
        Plaintext64(plaintext)
    }
}
