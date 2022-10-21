use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64,
};
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDiscardingAdditionEngine, LweCiphertextVectorDiscardingAdditionError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingAdditionEngine`] for [`DefaultEngine`]
/// that operates on 32 bits integers.
impl LweCiphertextVectorDiscardingAdditionEngine<LweCiphertextVector32, LweCiphertextVector32>
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
    /// engine.discard_add_lwe_ciphertext_vector(
    ///     &mut output_ciphertext_vector,
    ///     &ciphertext_vector,
    ///     &ciphertext_vector,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext_vector.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector32,
        input_1: &LweCiphertextVector32,
        input_2: &LweCiphertextVector32,
    ) -> Result<(), LweCiphertextVectorDiscardingAdditionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingAdditionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe { self.discard_add_lwe_ciphertext_vector_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input_1: &LweCiphertextVector32,
        input_2: &LweCiphertextVector32,
    ) {
        for (mut out, (in_1, in_2)) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter().zip(input_2.0.ciphertext_iter()))
        {
            out.as_mut_tensor().fill_with_copy(in_1.as_tensor());
            out.update_with_add(&in_2);
        }
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingAdditionEngine`] for [`DefaultEngine`]
/// that operates on 64 bits integers.
impl LweCiphertextVectorDiscardingAdditionEngine<LweCiphertextVector64, LweCiphertextVector64>
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
    /// engine.discard_add_lwe_ciphertext_vector(
    ///     &mut output_ciphertext_vector,
    ///     &ciphertext_vector,
    ///     &ciphertext_vector,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext_vector.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector64,
        input_1: &LweCiphertextVector64,
        input_2: &LweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorDiscardingAdditionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingAdditionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe { self.discard_add_lwe_ciphertext_vector_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input_1: &LweCiphertextVector64,
        input_2: &LweCiphertextVector64,
    ) {
        for (mut out, (in_1, in_2)) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter().zip(input_2.0.ciphertext_iter()))
        {
            out.as_mut_tensor().fill_with_copy(in_1.as_tensor());
            out.update_with_add(&in_2);
        }
    }
}
