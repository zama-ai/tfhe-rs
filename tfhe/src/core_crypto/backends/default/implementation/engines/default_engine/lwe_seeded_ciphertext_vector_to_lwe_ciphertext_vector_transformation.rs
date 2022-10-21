use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    LweCiphertextVector32, LweCiphertextVector64, LweSeededCiphertextVector32,
    LweSeededCiphertextVector64,
};
use crate::core_crypto::commons::crypto::lwe::LweList as ImplLweList;
use crate::core_crypto::prelude::CiphertextCount;
use crate::core_crypto::specification::engines::{
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine,
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationError,
};
use crate::core_crypto::specification::entities::LweSeededCiphertextVectorEntity;

/// # Description:
/// Implementation of [`LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine<
        LweSeededCiphertextVector32,
        LweCiphertextVector32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    ///
    /// let mut seeded_ciphertext_vector: LweSeededCiphertextVector32 =
    ///     engine.encrypt_lwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let ciphertext_vector = engine
    ///     .transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
    ///         seeded_ciphertext_vector,
    ///     )?;
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
        &mut self,
        lwe_seeded_ciphertext_vector: LweSeededCiphertextVector32,
    ) -> Result<
        LweCiphertextVector32,
        LweSeededCiphertextVectorToLweCiphertextVectorTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_unchecked(
                lwe_seeded_ciphertext_vector,
            )
        })
    }

    unsafe fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_unchecked(
        &mut self,
        lwe_seeded_ciphertext_vector: LweSeededCiphertextVector32,
    ) -> LweCiphertextVector32 {
        let mut output_ciphertext_vector = ImplLweList::allocate(
            0_u32,
            lwe_seeded_ciphertext_vector.lwe_dimension().to_lwe_size(),
            CiphertextCount(lwe_seeded_ciphertext_vector.lwe_ciphertext_count().0),
        );
        lwe_seeded_ciphertext_vector
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output_ciphertext_vector);

        LweCiphertextVector32(output_ciphertext_vector)
    }
}

/// # Description:
/// Implementation of [`LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine<
        LweSeededCiphertextVector64,
        LweCiphertextVector64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    ///
    /// let mut seeded_ciphertext_vector: LweSeededCiphertextVector64 =
    ///     engine.encrypt_lwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let ciphertext_vector = engine
    ///     .transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
    ///         seeded_ciphertext_vector,
    ///     )?;
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
        &mut self,
        lwe_seeded_ciphertext_vector: LweSeededCiphertextVector64,
    ) -> Result<
        LweCiphertextVector64,
        LweSeededCiphertextVectorToLweCiphertextVectorTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_unchecked(
                lwe_seeded_ciphertext_vector,
            )
        })
    }

    unsafe fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_unchecked(
        &mut self,
        lwe_seeded_ciphertext_vector: LweSeededCiphertextVector64,
    ) -> LweCiphertextVector64 {
        let mut output_ciphertext_vector = ImplLweList::allocate(
            0_u64,
            lwe_seeded_ciphertext_vector.lwe_dimension().to_lwe_size(),
            CiphertextCount(lwe_seeded_ciphertext_vector.lwe_ciphertext_count().0),
        );
        lwe_seeded_ciphertext_vector
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output_ciphertext_vector);

        LweCiphertextVector64(output_ciphertext_vector)
    }
}
