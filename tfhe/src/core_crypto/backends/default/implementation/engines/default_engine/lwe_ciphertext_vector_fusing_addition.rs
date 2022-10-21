use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorFusingAdditionEngine, LweCiphertextVectorFusingAdditionError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorFusingAdditionEngine`] for [`DefaultEngine`]
/// that operates on 32 bits integers.
impl LweCiphertextVectorFusingAdditionEngine<LweCiphertextVector32, LweCiphertextVector32>
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
    /// let input_vector = vec![3_u32 << 20; 8];
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input_vector)?;
    /// let ciphertext_vector = engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    /// let mut output_ciphertext_vector =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// engine.fuse_add_lwe_ciphertext_vector(&mut output_ciphertext_vector, &ciphertext_vector)?;
    /// #
    /// assert_eq!(output_ciphertext_vector.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertextVector32,
    ) -> Result<(), LweCiphertextVectorFusingAdditionError<Self::EngineError>> {
        LweCiphertextVectorFusingAdditionError::perform_generic_checks(output, input)?;
        unsafe { self.fuse_add_lwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertextVector32,
    ) {
        for (mut out, inp) in output
            .0
            .ciphertext_iter_mut()
            .zip(input.0.ciphertext_iter())
        {
            out.update_with_add(&inp);
        }
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorFusingAdditionEngine`] for [`DefaultEngine`]
/// that operates on 64 bits integers.
impl LweCiphertextVectorFusingAdditionEngine<LweCiphertextVector64, LweCiphertextVector64>
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
    /// let input_vector = vec![3_u64 << 50; 8];
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input_vector)?;
    /// let ciphertext_vector = engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    /// let mut output_ciphertext_vector =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// engine.fuse_add_lwe_ciphertext_vector(&mut output_ciphertext_vector, &ciphertext_vector)?;
    /// #
    /// assert_eq!(output_ciphertext_vector.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorFusingAdditionError<Self::EngineError>> {
        LweCiphertextVectorFusingAdditionError::perform_generic_checks(output, input)?;
        unsafe { self.fuse_add_lwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
    ) {
        for (mut out, inp) in output
            .0
            .ciphertext_iter_mut()
            .zip(input.0.ciphertext_iter())
        {
            out.update_with_add(&inp);
        }
    }
}
