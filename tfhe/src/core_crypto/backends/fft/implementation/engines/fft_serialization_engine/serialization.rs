#![allow(clippy::missing_safety_doc)]

use super::{FftSerializationEngine, FftSerializationError};
use crate::core_crypto::backends::fft::private::crypto::bootstrap::FourierLweBootstrapKeyView;
use crate::core_crypto::backends::fft::private::crypto::ggsw::FourierGgswCiphertextView;
use crate::core_crypto::prelude::{
    EntitySerializationEngine, EntitySerializationError, FftFourierGgswCiphertext32,
    FftFourierGgswCiphertext32Version, FftFourierGgswCiphertext64,
    FftFourierGgswCiphertext64Version, FftFourierLweBootstrapKey32,
    FftFourierLweBootstrapKey32Version, FftFourierLweBootstrapKey64,
    FftFourierLweBootstrapKey64Version,
};
use serde::Serialize;

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftSerializationEngine`] that operates on
/// 32 bits integers. It serializes a GGSW ciphertext in the Fourier domain.
impl EntitySerializationEngine<FftFourierGgswCiphertext32, Vec<u8>> for FftSerializationEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftFourierGgswCiphertext32 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// let mut serialization_engine = FftSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &FftFourierGgswCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        let entity = entity.0.as_view();
        #[derive(Serialize)]
        struct SerializableFftFourierGgswCiphertext32<'a> {
            version: FftFourierGgswCiphertext32Version,
            inner: FourierGgswCiphertextView<'a>,
        }
        let value = SerializableFftFourierGgswCiphertext32 {
            version: FftFourierGgswCiphertext32Version::V0,
            inner: entity,
        };
        bincode::serialize(&value)
            .map_err(FftSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftFourierGgswCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftSerializationEngine`] that operates on
/// 64 bits integers. It serializes a GGSW ciphertext in the Fourier domain.
impl EntitySerializationEngine<FftFourierGgswCiphertext64, Vec<u8>> for FftSerializationEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftFourierGgswCiphertext64 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// let mut serialization_engine = FftSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &FftFourierGgswCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        let entity = entity.0.as_view();
        #[derive(Serialize)]
        struct SerializableFftFourierGgswCiphertext64<'a> {
            version: FftFourierGgswCiphertext64Version,
            inner: FourierGgswCiphertextView<'a>,
        }
        let value = SerializableFftFourierGgswCiphertext64 {
            version: FftFourierGgswCiphertext64Version::V0,
            inner: entity,
        };
        bincode::serialize(&value)
            .map_err(FftSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftFourierGgswCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftSerializationEngine`] that operates on
/// 32 bits integers. It serializes an LWE bootstrap key in the Fourier domain.
impl EntitySerializationEngine<FftFourierLweBootstrapKey32, Vec<u8>> for FftSerializationEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftFourierLweBootstrapKey32 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    ///
    /// let mut serialization_engine = FftSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &FftFourierLweBootstrapKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        let entity = entity.0.as_view();
        #[derive(Serialize)]
        struct SerializableFftFourierLweBootstrapKey32<'a> {
            version: FftFourierLweBootstrapKey32Version,
            inner: FourierLweBootstrapKeyView<'a>,
        }
        let value = SerializableFftFourierLweBootstrapKey32 {
            version: FftFourierLweBootstrapKey32Version::V0,
            inner: entity,
        };
        bincode::serialize(&value)
            .map_err(FftSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftFourierLweBootstrapKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftSerializationEngine`] that operates on
/// 64 bits integers. It serializes an LWE bootstrap key in the Fourier domain.
impl EntitySerializationEngine<FftFourierLweBootstrapKey64, Vec<u8>> for FftSerializationEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    ///
    /// let mut serialization_engine = FftSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &FftFourierLweBootstrapKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        let entity = entity.0.as_view();
        #[derive(Serialize)]
        struct SerializableFftFourierLweBootstrapKey64<'a> {
            version: FftFourierLweBootstrapKey64Version,
            inner: FourierLweBootstrapKeyView<'a>,
        }
        let value = SerializableFftFourierLweBootstrapKey64 {
            version: FftFourierLweBootstrapKey64Version::V0,
            inner: entity,
        };
        bincode::serialize(&value)
            .map_err(FftSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftFourierLweBootstrapKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}
