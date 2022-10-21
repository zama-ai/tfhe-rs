#![allow(clippy::missing_safety_doc)]

use super::{FftSerializationEngine, FftSerializationError};
use crate::core_crypto::backends::fft::private::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::backends::fft::private::crypto::ggsw::FourierGgswCiphertext;
use crate::core_crypto::prelude::{
    EntityDeserializationEngine, EntityDeserializationError, FftFourierGgswCiphertext32,
    FftFourierGgswCiphertext32Version, FftFourierGgswCiphertext64,
    FftFourierGgswCiphertext64Version, FftFourierLweBootstrapKey32,
    FftFourierLweBootstrapKey32Version, FftFourierLweBootstrapKey64,
    FftFourierLweBootstrapKey64Version,
};
use aligned_vec::ABox;
use concrete_fft::c64;
use serde::Deserialize;

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftSerializationEngine`] that operates
/// on 32 bits integers. It deserializes a GGSW ciphertext in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftFourierGgswCiphertext32> for FftSerializationEngine {
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
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftFourierGgswCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct SerializableFftFourierGgswCiphertext32 {
            version: FftFourierGgswCiphertext32Version,
            inner: FourierGgswCiphertext<ABox<[c64]>>,
        }
        let deserialized: SerializableFftFourierGgswCiphertext32 = bincode::deserialize(serialized)
            .map_err(FftSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            SerializableFftFourierGgswCiphertext32 {
                version: FftFourierGgswCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftSerializationError::UnsupportedVersion,
            )),
            SerializableFftFourierGgswCiphertext32 {
                version: FftFourierGgswCiphertext32Version::V0,
                inner,
            } => Ok(FftFourierGgswCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftFourierGgswCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftSerializationEngine`] that operates
/// on 64 bits integers. It deserializes a GGSW ciphertext in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftFourierGgswCiphertext64> for FftSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftFourierGgswCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct SerializableFftFourierGgswCiphertext64 {
            version: FftFourierGgswCiphertext64Version,
            inner: FourierGgswCiphertext<ABox<[c64]>>,
        }
        let deserialized: SerializableFftFourierGgswCiphertext64 = bincode::deserialize(serialized)
            .map_err(FftSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            SerializableFftFourierGgswCiphertext64 {
                version: FftFourierGgswCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftSerializationError::UnsupportedVersion,
            )),
            SerializableFftFourierGgswCiphertext64 {
                version: FftFourierGgswCiphertext64Version::V0,
                inner,
            } => Ok(FftFourierGgswCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftFourierGgswCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftSerializationEngine`] that operates
/// on 32 bits integers. It deserializes an LWE bootstrap key in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftFourierLweBootstrapKey32> for FftSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftFourierLweBootstrapKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct SerializableFftFourierLweBootstrapKey32 {
            version: FftFourierLweBootstrapKey32Version,
            inner: FourierLweBootstrapKey<ABox<[c64]>>,
        }
        let deserialized: SerializableFftFourierLweBootstrapKey32 =
            bincode::deserialize(serialized)
                .map_err(FftSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            SerializableFftFourierLweBootstrapKey32 {
                version: FftFourierLweBootstrapKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftSerializationError::UnsupportedVersion,
            )),
            SerializableFftFourierLweBootstrapKey32 {
                version: FftFourierLweBootstrapKey32Version::V0,
                inner,
            } => Ok(FftFourierLweBootstrapKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftFourierLweBootstrapKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftSerializationEngine`] that operates
/// on 64 bits integers. It deserializes an LWE bootstrap key in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftFourierLweBootstrapKey64> for FftSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftFourierLweBootstrapKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct SerializableFftFourierLweBootstrapKey64 {
            version: FftFourierLweBootstrapKey64Version,
            inner: FourierLweBootstrapKey<ABox<[c64]>>,
        }
        let deserialized: SerializableFftFourierLweBootstrapKey64 =
            bincode::deserialize(serialized)
                .map_err(FftSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            SerializableFftFourierLweBootstrapKey64 {
                version: FftFourierLweBootstrapKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftSerializationError::UnsupportedVersion,
            )),
            SerializableFftFourierLweBootstrapKey64 {
                version: FftFourierLweBootstrapKey64Version::V0,
                inner,
            } => Ok(FftFourierLweBootstrapKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftFourierLweBootstrapKey64 {
        self.deserialize(serialized).unwrap()
    }
}
