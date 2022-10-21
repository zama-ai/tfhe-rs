use crate::core_crypto::prelude::Variance;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::commons::crypto::encoding::Plaintext as ImplPlaintext;
use crate::core_crypto::commons::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::core_crypto::specification::engines::{
    LweCiphertextZeroEncryptionEngine, LweCiphertextZeroEncryptionError,
};
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LweCiphertextZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextZeroEncryptionEngine<LweSecretKey32, LweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
    ) -> Result<LweCiphertext32, LweCiphertextZeroEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_unchecked(key, noise) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
    ) -> LweCiphertext32 {
        let mut ciphertext = ImplLweCiphertext::allocate(0u32, key.lwe_dimension().to_lwe_size());
        key.0.encrypt_lwe(
            &mut ciphertext,
            &ImplPlaintext(0u32),
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertext32(ciphertext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextZeroEncryptionEngine<LweSecretKey64, LweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
    ) -> Result<LweCiphertext64, LweCiphertextZeroEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_unchecked(key, noise) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
    ) -> LweCiphertext64 {
        let mut ciphertext = ImplLweCiphertext::allocate(0u64, key.lwe_dimension().to_lwe_size());
        key.0.encrypt_lwe(
            &mut ciphertext,
            &ImplPlaintext(0u64),
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertext64(ciphertext)
    }
}
