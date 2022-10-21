use crate::core_crypto::prelude::Variance;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32, LweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::prelude::{
    LweCiphertextVectorMutView32, LweCiphertextVectorMutView64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDiscardingEncryptionEngine, LweCiphertextVectorDiscardingEncryptionError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextVectorDiscardingEncryptionEngine<
        LweSecretKey32,
        PlaintextVector32,
        LweCiphertextVector32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension};
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// let mut ciphertext_vector: LweCiphertextVector32 =
    ///     engine.zero_encrypt_lwe_ciphertext_vector(&key, noise, LweCiphertextCount(3))?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_vector(
    ///     &key,
    ///     &mut ciphertext_vector,
    ///     &plaintext_vector,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_vector.lwe_ciphertext_count(),
    /// #     LweCiphertextCount(3)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextVectorDiscardingEncryptionEngine<
        LweSecretKey64,
        PlaintextVector64,
        LweCiphertextVector64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension};
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// let mut ciphertext_vector: LweCiphertextVector64 =
    ///     engine.zero_encrypt_lwe_ciphertext_vector(&key, noise, LweCiphertextCount(3))?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_vector(
    ///     &key,
    ///     &mut ciphertext_vector,
    ///     &plaintext_vector,
    ///     noise,
    /// );
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_vector.lwe_ciphertext_count(),
    /// #     LweCiphertextCount(3)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextVectorDiscardingEncryptionEngine<
        LweSecretKey32,
        PlaintextVector32,
        LweCiphertextVectorMutView32<'_>,
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
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut output_ciphertext_vector_container = vec![0_32; lwe_dimension.to_lwe_size().0 *
    ///     lwe_count.0];
    /// let mut ciphertext_vector: LweCiphertextVectorMutView32 =
    ///     engine.create_lwe_ciphertext_vector_from(&mut output_ciphertext_vector_container[..],
    ///     lwe_dimension.to_lwe_size())?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_vector(&key, &mut ciphertext_vector,
    ///     &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_vector.lwe_ciphertext_count(),
    /// #     lwe_count,
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVectorMutView32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVectorMutView32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextVectorDiscardingEncryptionEngine<
        LweSecretKey64,
        PlaintextVector64,
        LweCiphertextVectorMutView64<'_>,
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
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut output_ciphertext_vector_container = vec![0_64; lwe_dimension.to_lwe_size().0 *
    ///     lwe_count.0];
    /// let mut ciphertext_vector: LweCiphertextVectorMutView64 =
    ///     engine.create_lwe_ciphertext_vector_from(&mut output_ciphertext_vector_container[..],
    ///     lwe_dimension.to_lwe_size())?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_vector(&key, &mut ciphertext_vector,
    ///     &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_vector.lwe_ciphertext_count(),
    /// #     lwe_count,
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVectorMutView64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVectorMutView64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
