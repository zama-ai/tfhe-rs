use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweSeededCiphertext32, GlweSeededCiphertext64,
};
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::core_crypto::specification::engines::{
    GlweSeededCiphertextToGlweCiphertextTransformationEngine,
    GlweSeededCiphertextToGlweCiphertextTransformationError,
};
use crate::core_crypto::specification::entities::GlweSeededCiphertextEntity;

/// # Description:
/// Implementation of [`GlweSeededCiphertextToGlweCiphertextTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    GlweSeededCiphertextToGlweCiphertextTransformationEngine<
        GlweSeededCiphertext32,
        GlweCiphertext32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let seeded_ciphertext =
    ///     engine.encrypt_glwe_seeded_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let ciphertext =
    ///     engine.transform_glwe_seeded_ciphertext_to_glwe_ciphertext(seeded_ciphertext)?;
    ///
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext(
        &mut self,
        glwe_seeded_ciphertext: GlweSeededCiphertext32,
    ) -> Result<
        GlweCiphertext32,
        GlweSeededCiphertextToGlweCiphertextTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_glwe_seeded_ciphertext_to_glwe_ciphertext_unchecked(
                glwe_seeded_ciphertext,
            )
        })
    }

    unsafe fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext_unchecked(
        &mut self,
        glwe_seeded_ciphertext: GlweSeededCiphertext32,
    ) -> GlweCiphertext32 {
        let mut output = ImplGlweCiphertext::allocate(
            0,
            glwe_seeded_ciphertext.polynomial_size(),
            glwe_seeded_ciphertext.glwe_dimension().to_glwe_size(),
        );

        glwe_seeded_ciphertext
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);

        GlweCiphertext32(output)
    }
}

/// # Description:
/// Implementation of [`GlweSeededCiphertextToGlweCiphertextTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    GlweSeededCiphertextToGlweCiphertextTransformationEngine<
        GlweSeededCiphertext64,
        GlweCiphertext64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let seeded_ciphertext =
    ///     engine.encrypt_glwe_seeded_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let ciphertext =
    ///     engine.transform_glwe_seeded_ciphertext_to_glwe_ciphertext(seeded_ciphertext)?;
    ///
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext(
        &mut self,
        glwe_seeded_ciphertext: GlweSeededCiphertext64,
    ) -> Result<
        GlweCiphertext64,
        GlweSeededCiphertextToGlweCiphertextTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_glwe_seeded_ciphertext_to_glwe_ciphertext_unchecked(
                glwe_seeded_ciphertext,
            )
        })
    }

    unsafe fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext_unchecked(
        &mut self,
        glwe_seeded_ciphertext: GlweSeededCiphertext64,
    ) -> GlweCiphertext64 {
        let mut output = ImplGlweCiphertext::allocate(
            0,
            glwe_seeded_ciphertext.polynomial_size(),
            glwe_seeded_ciphertext.glwe_dimension().to_glwe_size(),
        );

        glwe_seeded_ciphertext
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);

        GlweCiphertext64(output)
    }
}
