#[allow(deprecated)]
use crate::core_crypto::prelude::{MonomialDegree, MonomialIndex};

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, LweCiphertext32, LweCiphertext64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingExtractionEngine, LweCiphertextDiscardingExtractionError,
};

/// # Description:
/// Implementation of [`LweCiphertextDiscardingExtractionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextDiscardingExtractionEngine<GlweCiphertext32, LweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweDimension, LweDimension, MonomialIndex, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // The target LWE dimension should be equal to the polynomial size + 1
    /// // since we're going to extract one sample from the GLWE ciphertext
    /// let lwe_dimension = LweDimension(8);
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // We're going to extract the first one
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let lwe_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    /// let glwe_ciphertext = engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector, noise)?;
    /// // We first create an LWE ciphertext encrypting zeros
    /// let mut lwe_ciphertext = engine.zero_encrypt_lwe_ciphertext(&lwe_key, noise)?;
    ///
    /// // Then we extract the first sample from the GLWE ciphertext to store it into the LWE
    /// engine.discard_extract_lwe_ciphertext(
    ///     &mut lwe_ciphertext,
    ///     &glwe_ciphertext,
    ///     MonomialIndex(0),
    /// )?;
    /// #
    /// assert_eq!(lwe_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphertext32,
        nth: MonomialIndex,
    ) -> Result<(), LweCiphertextDiscardingExtractionError<Self::EngineError>> {
        LweCiphertextDiscardingExtractionError::perform_generic_checks(output, input, nth)?;
        unsafe { self.discard_extract_lwe_ciphertext_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn discard_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphertext32,
        nth: MonomialIndex,
    ) {
        #[allow(deprecated)]
        output
            .0
            .fill_with_glwe_sample_extraction(&input.0, MonomialDegree(nth.0));
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingExtractionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextDiscardingExtractionEngine<GlweCiphertext64, LweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweDimension, LweDimension, MonomialIndex, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // The target LWE dimension should be equal to the polynomial size + 1
    /// // since we're going to extract one sample from the GLWE ciphertext
    /// let lwe_dimension = LweDimension(8);
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // We're going to extract the first one
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let lwe_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    /// let glwe_ciphertext = engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector, noise)?;
    /// // We first create an LWE ciphertext encrypting zeros
    /// let mut lwe_ciphertext = engine.zero_encrypt_lwe_ciphertext(&lwe_key, noise)?;
    ///
    /// // Then we extract the first sample from the GLWE ciphertext to store it into the LWE
    /// engine.discard_extract_lwe_ciphertext(
    ///     &mut lwe_ciphertext,
    ///     &glwe_ciphertext,
    ///     MonomialIndex(0),
    /// )?;
    /// #
    /// assert_eq!(lwe_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphertext64,
        nth: MonomialIndex,
    ) -> Result<(), LweCiphertextDiscardingExtractionError<Self::EngineError>> {
        LweCiphertextDiscardingExtractionError::perform_generic_checks(output, input, nth)?;
        unsafe { self.discard_extract_lwe_ciphertext_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn discard_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphertext64,
        nth: MonomialIndex,
    ) {
        #[allow(deprecated)]
        output
            .0
            .fill_with_glwe_sample_extraction(&input.0, MonomialDegree(nth.0));
    }
}
