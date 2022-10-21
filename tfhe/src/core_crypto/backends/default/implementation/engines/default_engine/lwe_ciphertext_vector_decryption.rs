use crate::core_crypto::prelude::PlaintextCount;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32, LweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::core_crypto::prelude::{LweCiphertextVectorView32, LweCiphertextVectorView64};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDecryptionEngine, LweCiphertextVectorDecryptionError,
};
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

/// # Description:
/// Implementation of [`LweCiphertextVectorDecryptionEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl LweCiphertextVectorDecryptionEngine<LweSecretKey32, LweCiphertextVector32, PlaintextVector32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, PlaintextCount, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector: LweCiphertextVector32 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let decrypted_plaintext_vector =
    ///     engine.decrypt_lwe_ciphertext_vector(&key, &ciphertext_vector)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_vector.plaintext_count(),
    ///     PlaintextCount(18)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextVector32,
    ) -> Result<PlaintextVector32, LweCiphertextVectorDecryptionError<Self::EngineError>> {
        LweCiphertextVectorDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_vector_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextVector32,
    ) -> PlaintextVector32 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u32, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextVector32(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDecryptionEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl LweCiphertextVectorDecryptionEngine<LweSecretKey64, LweCiphertextVector64, PlaintextVector64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, PlaintextCount, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector: LweCiphertextVector64 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let decrypted_plaintext_vector =
    ///     engine.decrypt_lwe_ciphertext_vector(&key, &ciphertext_vector)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_vector.plaintext_count(),
    ///     PlaintextCount(18)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextVector64,
    ) -> Result<PlaintextVector64, LweCiphertextVectorDecryptionError<Self::EngineError>> {
        LweCiphertextVectorDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_vector_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextVector64,
    ) -> PlaintextVector64 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u64, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextVector64(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextVectorDecryptionEngine<
        LweSecretKey32,
        LweCiphertextVectorView32<'_>,
        PlaintextVector32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(18);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut raw_ciphertext_vector = vec![0_u32; key.lwe_dimension().to_lwe_size().0 * lwe_count.0];
    /// let mut ciphertext_vector_view: LweCiphertextVectorMutView32 = engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         &mut raw_ciphertext_vector[..],
    ///         lwe_dimension.to_lwe_size(),
    ///     )?;
    /// engine.discard_encrypt_lwe_ciphertext_vector(
    ///     &key,
    ///     &mut ciphertext_vector_view,
    ///     &plaintext_vector,
    ///     noise,
    /// )?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_vector =
    ///     engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector_view)?;
    /// let ciphertext_vector_view: LweCiphertextVectorView32 = engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         &raw_ciphertext_vector[..],
    ///         lwe_dimension.to_lwe_size(),
    ///     )?;
    ///
    /// let decrypted_plaintext_vector =
    ///     engine.decrypt_lwe_ciphertext_vector(&key, &ciphertext_vector_view)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_vector.plaintext_count(),
    ///     PlaintextCount(lwe_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextVectorView32<'_>,
    ) -> Result<PlaintextVector32, LweCiphertextVectorDecryptionError<Self::EngineError>> {
        LweCiphertextVectorDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_vector_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextVectorView32<'_>,
    ) -> PlaintextVector32 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u32, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextVector32(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextVectorDecryptionEngine<
        LweSecretKey64,
        LweCiphertextVectorView64<'_>,
        PlaintextVector64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(18);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut raw_ciphertext_vector = vec![0_u64; key.lwe_dimension().to_lwe_size().0 * lwe_count.0];
    /// let mut ciphertext_vector_view: LweCiphertextVectorMutView64 = engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         &mut raw_ciphertext_vector[..],
    ///         lwe_dimension.to_lwe_size(),
    ///     )?;
    /// engine.discard_encrypt_lwe_ciphertext_vector(
    ///     &key,
    ///     &mut ciphertext_vector_view,
    ///     &plaintext_vector,
    ///     noise,
    /// )?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_vector =
    ///     engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector_view)?;
    /// let ciphertext_vector_view: LweCiphertextVectorView64 = engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         &raw_ciphertext_vector[..],
    ///         lwe_dimension.to_lwe_size(),
    ///     )?;
    ///
    /// let decrypted_plaintext_vector =
    ///     engine.decrypt_lwe_ciphertext_vector(&key, &ciphertext_vector_view)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_vector.plaintext_count(),
    ///     PlaintextCount(lwe_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextVectorView64<'_>,
    ) -> Result<PlaintextVector64, LweCiphertextVectorDecryptionError<Self::EngineError>> {
        LweCiphertextVectorDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_vector_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextVectorView64<'_>,
    ) -> PlaintextVector64 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u64, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextVector64(plaintext)
    }
}
