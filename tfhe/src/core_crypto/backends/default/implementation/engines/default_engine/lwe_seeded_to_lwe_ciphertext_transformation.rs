use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    LweCiphertext32, LweCiphertext64, LweSeededCiphertext32, LweSeededCiphertext64,
};
use crate::core_crypto::commons::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::core_crypto::specification::engines::{
    LweSeededCiphertextToLweCiphertextTransformationEngine,
    LweSeededCiphertextToLweCiphertextTransformationError,
};
use crate::core_crypto::specification::entities::LweSeededCiphertextEntity;

/// # Description:
/// Implementation of [`LweSeededCiphertextToLweCiphertextTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl LweSeededCiphertextToLweCiphertextTransformationEngine<LweSeededCiphertext32, LweCiphertext32>
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
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let seeded_ciphertext = engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
    /// let ciphertext = engine.transform_lwe_seeded_ciphertext_to_lwe_ciphertext(seeded_ciphertext)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext(
        &mut self,
        lwe_seeded_ciphertext: LweSeededCiphertext32,
    ) -> Result<
        LweCiphertext32,
        LweSeededCiphertextToLweCiphertextTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_ciphertext_to_lwe_ciphertext_unchecked(lwe_seeded_ciphertext)
        })
    }

    unsafe fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext_unchecked(
        &mut self,
        lwe_seeded_ciphertext: LweSeededCiphertext32,
    ) -> LweCiphertext32 {
        let mut output_ciphertext =
            ImplLweCiphertext::allocate(0_u32, lwe_seeded_ciphertext.lwe_dimension().to_lwe_size());
        lwe_seeded_ciphertext
            .0
            .expand_into::<_, ActivatedRandomGenerator>(&mut output_ciphertext);

        LweCiphertext32(output_ciphertext)
    }
}

/// # Description:
/// Implementation of [`LweSeededCiphertextToLweCiphertextTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl LweSeededCiphertextToLweCiphertextTransformationEngine<LweSeededCiphertext64, LweCiphertext64>
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
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let seeded_ciphertext = engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
    /// let ciphertext = engine.transform_lwe_seeded_ciphertext_to_lwe_ciphertext(seeded_ciphertext)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext(
        &mut self,
        lwe_seeded_ciphertext: LweSeededCiphertext64,
    ) -> Result<
        LweCiphertext64,
        LweSeededCiphertextToLweCiphertextTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_ciphertext_to_lwe_ciphertext_unchecked(lwe_seeded_ciphertext)
        })
    }

    unsafe fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext_unchecked(
        &mut self,
        lwe_seeded_ciphertext: LweSeededCiphertext64,
    ) -> LweCiphertext64 {
        let mut output_ciphertext =
            ImplLweCiphertext::allocate(0_u64, lwe_seeded_ciphertext.lwe_dimension().to_lwe_size());
        lwe_seeded_ciphertext
            .0
            .expand_into::<_, ActivatedRandomGenerator>(&mut output_ciphertext);

        LweCiphertext64(output_ciphertext)
    }
}
