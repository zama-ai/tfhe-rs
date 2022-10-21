use crate::core_crypto::prelude::{CiphertextCount, Variance};

use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweSecretKey32, LweSecretKey64, LweSeededCiphertextVector32, LweSeededCiphertextVector64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::lwe::LweSeededList as ImplLweSeededList;
use crate::core_crypto::commons::math::random::{CompressionSeed, Seeder};
use crate::core_crypto::specification::engines::{
    LweSeededCiphertextVectorEncryptionEngine, LweSeededCiphertextVectorEncryptionError,
};
use crate::core_crypto::specification::entities::{LweSecretKeyEntity, PlaintextVectorEntity};

/// # Description:
/// Implementation of [`LweSeededCiphertextVectorEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweSeededCiphertextVectorEncryptionEngine<
        LweSecretKey32,
        PlaintextVector32,
        LweSeededCiphertextVector32,
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
    ///
    /// let mut ciphertext_vector: LweSeededCiphertextVector32 =
    ///     engine.encrypt_lwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #    ciphertext_vector.lwe_ciphertext_count(),
    /// #    LweCiphertextCount(3)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_lwe_seeded_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<
        LweSeededCiphertextVector32,
        LweSeededCiphertextVectorEncryptionError<Self::EngineError>,
    > {
        Ok(unsafe { self.encrypt_lwe_seeded_ciphertext_vector_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_seeded_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> LweSeededCiphertextVector32 {
        let mut vector = ImplLweSeededList::allocate(
            key.lwe_dimension(),
            CiphertextCount(input.plaintext_count().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.0
            .encrypt_seeded_lwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut vector,
                &input.0,
                noise,
                &mut self.seeder,
            );
        LweSeededCiphertextVector32(vector)
    }
}

/// # Description:
/// Implementation of [`LweSeededCiphertextVectorEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweSeededCiphertextVectorEncryptionEngine<
        LweSecretKey64,
        PlaintextVector64,
        LweSeededCiphertextVector64,
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
    ///
    /// let mut ciphertext_vector: LweSeededCiphertextVector64 =
    ///     engine.encrypt_lwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
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
    fn encrypt_lwe_seeded_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<
        LweSeededCiphertextVector64,
        LweSeededCiphertextVectorEncryptionError<Self::EngineError>,
    > {
        Ok(unsafe { self.encrypt_lwe_seeded_ciphertext_vector_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_seeded_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> LweSeededCiphertextVector64 {
        let mut vector = ImplLweSeededList::allocate(
            key.lwe_dimension(),
            CiphertextCount(input.plaintext_count().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.0
            .encrypt_seeded_lwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut vector,
                &input.0,
                noise,
                &mut self.seeder,
            );
        LweSeededCiphertextVector64(vector)
    }
}
