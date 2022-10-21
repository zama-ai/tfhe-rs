use crate::core_crypto::prelude::PlaintextCount;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorDecryptionEngine, GlweCiphertextVectorDecryptionError,
};
use crate::core_crypto::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity,
};

/// # Description:
/// Implementation of [`GlweCiphertextVectorDecryptionEngine`] for [`DefaultEngine`] that operates
/// on 32 bits integers.
impl
    GlweCiphertextVectorDecryptionEngine<GlweSecretKey32, GlweCiphertextVector32, PlaintextVector32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PlaintextCount, PolynomialSize};
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let decrypted_plaintext_vector =
    ///     engine.decrypt_glwe_ciphertext_vector(&key, &ciphertext_vector)?;
    /// #
    /// assert_eq!(
    /// #     decrypted_plaintext_vector.plaintext_count(),
    /// #     PlaintextCount(8)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        input: &GlweCiphertextVector32,
    ) -> Result<PlaintextVector32, GlweCiphertextVectorDecryptionError<Self::EngineError>> {
        GlweCiphertextVectorDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_glwe_ciphertext_vector_unchecked(key, input) })
    }

    unsafe fn decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &GlweCiphertextVector32,
    ) -> PlaintextVector32 {
        let mut plaintext_list = ImplPlaintextList::allocate(
            0u32,
            PlaintextCount(key.polynomial_size().0 * input.glwe_ciphertext_count().0),
        );
        key.0.decrypt_glwe_list(&mut plaintext_list, &input.0);
        PlaintextVector32(plaintext_list)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorDecryptionEngine`] for [`DefaultEngine`] that operates
/// on 64 bits integers.
impl
    GlweCiphertextVectorDecryptionEngine<GlweSecretKey64, GlweCiphertextVector64, PlaintextVector64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PlaintextCount, PolynomialSize};
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let decrypted_plaintext_vector =
    ///     engine.decrypt_glwe_ciphertext_vector(&key, &ciphertext_vector)?;
    /// #
    /// assert_eq!(
    /// #     decrypted_plaintext_vector.plaintext_count(),
    /// #     PlaintextCount(8)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        input: &GlweCiphertextVector64,
    ) -> Result<PlaintextVector64, GlweCiphertextVectorDecryptionError<Self::EngineError>> {
        GlweCiphertextVectorDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_glwe_ciphertext_vector_unchecked(key, input) })
    }

    unsafe fn decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &GlweCiphertextVector64,
    ) -> PlaintextVector64 {
        let mut plaintext_list = ImplPlaintextList::allocate(
            0u64,
            PlaintextCount(key.polynomial_size().0 * input.glwe_ciphertext_count().0),
        );
        key.0.decrypt_glwe_list(&mut plaintext_list, &input.0);
        PlaintextVector64(plaintext_list)
    }
}
