use crate::core_crypto::prelude::{
    DefaultEngine, LweCiphertext32, LweCiphertext64, LweSize, Plaintext32, Plaintext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextTrivialEncryptionEngine, LweCiphertextTrivialEncryptionError,
};

use crate::core_crypto::commons::crypto::lwe::LweCiphertext as ImplLweCiphertext;

impl LweCiphertextTrivialEncryptionEngine<Plaintext32, LweCiphertext32> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext32 = engine.create_plaintext_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext: LweCiphertext32 =
    ///     engine.trivially_encrypt_lwe_ciphertext(lwe_size, &plaintext)?;
    ///
    /// assert_eq!(ciphertext.lwe_dimension().to_lwe_size(), lwe_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_lwe_ciphertext(
        &mut self,
        lwe_size: LweSize,
        input: &Plaintext32,
    ) -> Result<LweCiphertext32, LweCiphertextTrivialEncryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_encrypt_lwe_ciphertext_unchecked(lwe_size, input)) }
    }

    unsafe fn trivially_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &Plaintext32,
    ) -> LweCiphertext32 {
        let ciphertext = ImplLweCiphertext::new_trivial_encryption(lwe_size, &input.0);
        LweCiphertext32(ciphertext)
    }
}

impl LweCiphertextTrivialEncryptionEngine<Plaintext64, LweCiphertext64> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = 3_u64 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext64 = engine.create_plaintext_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext: LweCiphertext64 =
    ///     engine.trivially_encrypt_lwe_ciphertext(lwe_size, &plaintext)?;
    ///
    /// assert_eq!(ciphertext.lwe_dimension().to_lwe_size(), lwe_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_lwe_ciphertext(
        &mut self,
        lwe_size: LweSize,
        input: &Plaintext64,
    ) -> Result<LweCiphertext64, LweCiphertextTrivialEncryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_encrypt_lwe_ciphertext_unchecked(lwe_size, input)) }
    }

    unsafe fn trivially_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &Plaintext64,
    ) -> LweCiphertext64 {
        let ciphertext = ImplLweCiphertext::new_trivial_encryption(lwe_size, &input.0);
        LweCiphertext64(ciphertext)
    }
}
