use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::prelude::{
    GlweCiphertext32, GlweCiphertext64, LweCiphertextVector32, LweCiphertextVector64,
    LwePackingKeyswitchKey32, LwePackingKeyswitchKey64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchEngine,
    LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchEngine<
        LwePackingKeyswitchKey32,
        LweCiphertextVector32,
        GlweCiphertext32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let polynomial_size = PolynomialSize(256);
    /// let noise = Variance(2_f64.powf(-25.));
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_vector = vec![3_u32 << 20, 256];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    /// let packing_keyswitch_key = engine.generate_new_lwe_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input_vector)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_lwe_ciphertext_vector(&input_key, &plaintext_vector, noise)?;
    /// let mut ciphertext_output = engine.zero_encrypt_glwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_packing_keyswitch_lwe_ciphertext_vector(
    ///     &mut ciphertext_output,
    ///     &ciphertext_vector,
    ///     &packing_keyswitch_key,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_output.glwe_dimension(), output_glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &LweCiphertextVector32,
        ksk: &LwePackingKeyswitchKey32,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError<Self::EngineError>,
    > {
        LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError::perform_generic_checks(
            output, input, ksk,
        )?;
        unsafe {
            self.discard_packing_keyswitch_lwe_ciphertext_vector_unchecked(output, input, ksk)
        };
        Ok(())
    }

    unsafe fn discard_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &LweCiphertextVector32,
        ksk: &LwePackingKeyswitchKey32,
    ) {
        ksk.0.packing_keyswitch(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchEngine<
        LwePackingKeyswitchKey64,
        LweCiphertextVector64,
        GlweCiphertext64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let polynomial_size = PolynomialSize(256);
    /// let noise = Variance(2_f64.powf(-25.));
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_vector = vec![3_u64 << 50, 256];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    /// let packing_keyswitch_key = engine.generate_new_lwe_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input_vector)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_lwe_ciphertext_vector(&input_key, &plaintext_vector, noise)?;
    /// let mut ciphertext_output = engine.zero_encrypt_glwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_packing_keyswitch_lwe_ciphertext_vector(
    ///     &mut ciphertext_output,
    ///     &ciphertext_vector,
    ///     &packing_keyswitch_key,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_output.glwe_dimension(), output_glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &LweCiphertextVector64,
        ksk: &LwePackingKeyswitchKey64,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError<Self::EngineError>,
    > {
        LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError::perform_generic_checks(
            output, input, ksk,
        )?;
        unsafe {
            self.discard_packing_keyswitch_lwe_ciphertext_vector_unchecked(output, input, ksk)
        };
        Ok(())
    }

    unsafe fn discard_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &LweCiphertextVector64,
        ksk: &LwePackingKeyswitchKey64,
    ) {
        ksk.0.packing_keyswitch(&mut output.0, &input.0);
    }
}
