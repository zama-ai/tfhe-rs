use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    CleartextVector32, CleartextVector64, LweCiphertext32, LweCiphertext64, LweCiphertextVector32,
    LweCiphertextVector64, Plaintext32, Plaintext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDiscardingAffineTransformationEngine,
    LweCiphertextVectorDiscardingAffineTransformationError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingAffineTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweCiphertextVectorDiscardingAffineTransformationEngine<
        LweCiphertextVector32,
        CleartextVector32,
        Plaintext32,
        LweCiphertext32,
    > for DefaultEngine
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
    /// let weights_input = vec![2_u32; 8];
    /// let bias_input = 8_u32 << 20;
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let weights: CleartextVector32 = engine.create_cleartext_vector_from(&input_vector)?;
    /// let bias: Plaintext32 = engine.create_plaintext_from(&bias_input)?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input_vector)?;
    /// let ciphertext_vector = engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    /// let mut output_ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_affine_transform_lwe_ciphertext_vector(
    ///     &mut output_ciphertext,
    ///     &ciphertext_vector,
    ///     &weights,
    ///     &bias,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_affine_transform_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) -> Result<(), LweCiphertextVectorDiscardingAffineTransformationError<Self::EngineError>> {
        LweCiphertextVectorDiscardingAffineTransformationError::perform_generic_checks(
            output, inputs, weights,
        )?;
        unsafe {
            self.discard_affine_transform_lwe_ciphertext_vector_unchecked(
                output, inputs, weights, bias,
            )
        };
        Ok(())
    }

    unsafe fn discard_affine_transform_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingAffineTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweCiphertextVectorDiscardingAffineTransformationEngine<
        LweCiphertextVector64,
        CleartextVector64,
        Plaintext64,
        LweCiphertext64,
    > for DefaultEngine
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
    /// let weights_input = vec![2_u64; 8];
    /// let bias_input = 8_u64 << 50;
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let weights: CleartextVector64 = engine.create_cleartext_vector_from(&input_vector)?;
    /// let bias: Plaintext64 = engine.create_plaintext_from(&bias_input)?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input_vector)?;
    /// let ciphertext_vector = engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    /// let mut output_ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_affine_transform_lwe_ciphertext_vector(
    ///     &mut output_ciphertext,
    ///     &ciphertext_vector,
    ///     &weights,
    ///     &bias,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_affine_transform_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) -> Result<(), LweCiphertextVectorDiscardingAffineTransformationError<Self::EngineError>> {
        LweCiphertextVectorDiscardingAffineTransformationError::perform_generic_checks(
            output, inputs, weights,
        )?;
        unsafe {
            self.discard_affine_transform_lwe_ciphertext_vector_unchecked(
                output, inputs, weights, bias,
            )
        };
        Ok(())
    }

    unsafe fn discard_affine_transform_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}
