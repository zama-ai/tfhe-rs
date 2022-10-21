use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSeededCiphertextVector32,
    GlweSeededCiphertextVector64,
};
use crate::core_crypto::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::core_crypto::prelude::CiphertextCount;
use crate::core_crypto::specification::engines::{
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine,
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError,
};
use crate::core_crypto::specification::entities::GlweSeededCiphertextVectorEntity;

/// # Description:
/// Implementation of [`GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine<
        GlweSeededCiphertextVector32,
        GlweCiphertextVector32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
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
    ///
    /// let seeded_ciphertext_vector =
    ///     engine.encrypt_glwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let ciphertext_vector = engine.transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(seeded_ciphertext_vector)?;
    ///
    /// assert_eq!(
    /// #     ciphertext_vector.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
        &mut self,
        glwe_seeded_ciphertext_vector: GlweSeededCiphertextVector32,
    ) -> Result<
        GlweCiphertextVector32,
        GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector_unchecked(
                glwe_seeded_ciphertext_vector,
            )
        })
    }

    unsafe fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector_unchecked(
        &mut self,
        glwe_seeded_ciphertext_vector: GlweSeededCiphertextVector32,
    ) -> GlweCiphertextVector32 {
        let mut output = ImplGlweList::allocate(
            0,
            glwe_seeded_ciphertext_vector.polynomial_size(),
            glwe_seeded_ciphertext_vector.glwe_dimension(),
            CiphertextCount(glwe_seeded_ciphertext_vector.glwe_ciphertext_count().0),
        );

        glwe_seeded_ciphertext_vector
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);

        GlweCiphertextVector32(output)
    }
}

/// # Description:
/// Implementation of [`GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine<
        GlweSeededCiphertextVector64,
        GlweCiphertextVector64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
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
    ///
    /// let seeded_ciphertext_vector =
    ///     engine.encrypt_glwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let ciphertext_vector = engine.transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(seeded_ciphertext_vector)?;
    ///
    /// assert_eq!(
    /// #     ciphertext_vector.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
        &mut self,
        glwe_seeded_ciphertext_vector: GlweSeededCiphertextVector64,
    ) -> Result<
        GlweCiphertextVector64,
        GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector_unchecked(
                glwe_seeded_ciphertext_vector,
            )
        })
    }

    unsafe fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector_unchecked(
        &mut self,
        glwe_seeded_ciphertext_vector: GlweSeededCiphertextVector64,
    ) -> GlweCiphertextVector64 {
        let mut output = ImplGlweList::allocate(
            0,
            glwe_seeded_ciphertext_vector.polynomial_size(),
            glwe_seeded_ciphertext_vector.glwe_dimension(),
            CiphertextCount(glwe_seeded_ciphertext_vector.glwe_ciphertext_count().0),
        );

        glwe_seeded_ciphertext_vector
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);

        GlweCiphertextVector64(output)
    }
}
