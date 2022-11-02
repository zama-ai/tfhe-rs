#![allow(clippy::missing_safety_doc)]
use crate::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey as ImplStandardBootstrapKey;
use crate::core_crypto::commons::crypto::encoding::{
    Cleartext as ImplCleartext, Plaintext as ImplPlaintext, PlaintextList as ImplPlaintextList,
};
use crate::core_crypto::commons::crypto::glwe::{
    GlweCiphertext as ImplGlweCiphertext,
    LwePrivateFunctionalPackingKeyswitchKeyList as ImplLweCircuitBoostrapPrivateFunctionalPackingKeyswitchKeys,
};
use crate::core_crypto::commons::crypto::lwe::{
    LweCiphertext as ImplLweCiphertext, LweKeyswitchKey as ImplLweKeyswitchKey,
    LweList as ImplLweList,
};
use crate::core_crypto::commons::crypto::secret::{
    GlweSecretKey as ImplGlweSecretKey, LweSecretKey as ImplLweSecretKey,
};
use crate::core_crypto::prelude::{
    BinaryKeyKind, Cleartext32, Cleartext32Version, Cleartext64, Cleartext64Version, CleartextF64,
    CleartextF64Version, DefaultSerializationEngine, DefaultSerializationError,
    EntityDeserializationEngine, EntityDeserializationError, GlweCiphertext32,
    GlweCiphertext32Version, GlweCiphertext64, GlweCiphertext64Version, GlweSecretKey32,
    GlweSecretKey32Version, GlweSecretKey64, GlweSecretKey64Version, LweBootstrapKey32,
    LweBootstrapKey32Version, LweBootstrapKey64, LweBootstrapKey64Version, LweCiphertext32,
    LweCiphertext32Version, LweCiphertext64, LweCiphertext64Version, LweCiphertextVector32,
    LweCiphertextVector32Version, LweCiphertextVector64, LweCiphertextVector64Version,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32Version,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64Version, LweKeyswitchKey32,
    LweKeyswitchKey32Version, LweKeyswitchKey64, LweKeyswitchKey64Version, LwePublicKey32,
    LwePublicKey32Version, LwePublicKey64, LwePublicKey64Version, LweSecretKey32,
    LweSecretKey32Version, LweSecretKey64, LweSecretKey64Version, Plaintext32, Plaintext32Version,
    Plaintext64, Plaintext64Version, PlaintextVector32, PlaintextVector32Version,
    PlaintextVector64, PlaintextVector64Version,
};
use serde::Deserialize;

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a cleartext entity.
impl EntityDeserializationEngine<&[u8], Cleartext32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u32 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext32 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Cleartext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartext32 {
            version: Cleartext32Version,
            inner: ImplCleartext<u32>,
        }
        let deserialized: DeserializableCleartext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartext32 {
                version: Cleartext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartext32 {
                version: Cleartext32Version::V0,
                inner,
            } => Ok(Cleartext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Cleartext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a cleartext entity.
impl EntityDeserializationEngine<&[u8], Cleartext64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u64 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Cleartext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartext64 {
            version: Cleartext64Version,
            inner: ImplCleartext<u64>,
        }
        let deserialized: DeserializableCleartext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartext64 {
                version: Cleartext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartext64 {
                version: Cleartext64Version::V0,
                inner,
            } => Ok(Cleartext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Cleartext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a floating point cleartext entity.
impl EntityDeserializationEngine<&[u8], CleartextF64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: f64 = 3.;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: CleartextF64 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextF64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartextF64 {
            version: CleartextF64Version,
            inner: ImplCleartext<f64>,
        }
        let deserialized: DeserializableCleartextF64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartextF64 {
                version: CleartextF64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartextF64 {
                version: CleartextF64Version::V0,
                inner,
            } => Ok(CleartextF64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> CleartextF64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertext32> for DefaultSerializationEngine {
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
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertext32 {
            version: GlweCiphertext32Version,
            inner: ImplGlweCiphertext<Vec<u32>>,
        }
        let deserialized: DeserializableGlweCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertext32 {
                version: GlweCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertext32 {
                version: GlweCiphertext32Version::V0,
                inner,
            } => Ok(GlweCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertext64> for DefaultSerializationEngine {
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
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertext64 {
            version: GlweCiphertext64Version,
            inner: ImplGlweCiphertext<Vec<u64>>,
        }
        let deserialized: DeserializableGlweCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertext64 {
                version: GlweCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertext64 {
                version: GlweCiphertext64Version::V0,
                inner,
            } => Ok(GlweCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE secret key entity.
impl EntityDeserializationEngine<&[u8], GlweSecretKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_secret_key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&glwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(glwe_secret_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSecretKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSecretKey32 {
            version: GlweSecretKey32Version,
            inner: ImplGlweSecretKey<BinaryKeyKind, Vec<u32>>,
        }
        let deserialized: DeserializableGlweSecretKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSecretKey32 {
                version: GlweSecretKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSecretKey32 {
                version: GlweSecretKey32Version::V0,
                inner,
            } => Ok(GlweSecretKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSecretKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE secret key entity.
impl EntityDeserializationEngine<&[u8], GlweSecretKey64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_secret_key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&glwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(glwe_secret_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSecretKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSecretKey64 {
            version: GlweSecretKey64Version,
            inner: ImplGlweSecretKey<BinaryKeyKind, Vec<u64>>,
        }
        let deserialized: DeserializableGlweSecretKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSecretKey64 {
                version: GlweSecretKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSecretKey64 {
                version: GlweSecretKey64Version::V0,
                inner,
            } => Ok(GlweSecretKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSecretKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE bootstrap key entity.
impl EntityDeserializationEngine<&[u8], LweBootstrapKey32> for DefaultSerializationEngine {
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
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey32 =
    ///     engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweBootstrapKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweBootstrapKey32 {
            version: LweBootstrapKey32Version,
            inner: ImplStandardBootstrapKey<Vec<u32>>,
        }
        let deserialized: DeserializableLweBootstrapKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweBootstrapKey32 {
                version: LweBootstrapKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweBootstrapKey32 {
                version: LweBootstrapKey32Version::V0,
                inner,
            } => Ok(LweBootstrapKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweBootstrapKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE bootstrap key entity.
impl EntityDeserializationEngine<&[u8], LweBootstrapKey64> for DefaultSerializationEngine {
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
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey64 =
    ///     engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweBootstrapKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweBootstrapKey64 {
            version: LweBootstrapKey64Version,
            inner: ImplStandardBootstrapKey<Vec<u64>>,
        }
        let deserialized: DeserializableLweBootstrapKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweBootstrapKey64 {
                version: LweBootstrapKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweBootstrapKey64 {
                version: LweBootstrapKey64Version::V0,
                inner,
            } => Ok(LweBootstrapKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweBootstrapKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], LweCiphertext32> for DefaultSerializationEngine {
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
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertext32 {
            version: LweCiphertext32Version,
            inner: ImplLweCiphertext<Vec<u32>>,
        }
        let deserialized: DeserializableLweCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertext32 {
                version: LweCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertext32 {
                version: LweCiphertext32Version::V0,
                inner,
            } => Ok(LweCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], LweCiphertext64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// use tfhe::core_crypto::prelude::*;
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
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertext64 {
            version: LweCiphertext64Version,
            inner: ImplLweCiphertext<Vec<u64>>,
        }
        let deserialized: DeserializableLweCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertext64 {
                version: LweCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertext64 {
                version: LweCiphertext64Version::V0,
                inner,
            } => Ok(LweCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE ciphertext vector entity.
impl EntityDeserializationEngine<&[u8], LweCiphertextVector32> for DefaultSerializationEngine {
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
    /// let mut ciphertext_vector: LweCiphertextVector32 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_vector, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertextVector32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertextVector32 {
            version: LweCiphertextVector32Version,
            inner: ImplLweList<Vec<u32>>,
        }
        let deserialized: DeserializableLweCiphertextVector32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertextVector32 {
                version: LweCiphertextVector32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertextVector32 {
                version: LweCiphertextVector32Version::V0,
                inner,
            } => Ok(LweCiphertextVector32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertextVector32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE ciphertext vector entity.
impl EntityDeserializationEngine<&[u8], LweCiphertextVector64> for DefaultSerializationEngine {
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
    /// let mut ciphertext_vector: LweCiphertextVector64 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_vector, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertextVector64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertextVector64 {
            version: LweCiphertextVector64Version,
            inner: ImplLweList<Vec<u64>>,
        }
        let deserialized: DeserializableLweCiphertextVector64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertextVector64 {
                version: LweCiphertextVector64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertextVector64 {
                version: LweCiphertextVector64Version::V0,
                inner,
            } => Ok(LweCiphertextVector64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertextVector64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes an LWE circuit bootstrap private functional
/// packing keyswitch vector.
impl EntityDeserializationEngine<&[u8], LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    ///     GlweDimension, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(10);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomposition_base_log = DecompositionBaseLog(3);
    /// let decomposition_level_count = DecompositionLevelCount(5);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    ///
    /// let cbs_private_functional_packing_keyswitch_key:
    ///     LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 =
    ///     engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_base_log,
    ///         decomposition_level_count,
    ///         noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized =
    ///     serialization_engine.serialize(&cbs_private_functional_packing_keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
        EntityDeserializationError<Self::EngineError>,
    > {
        #[derive(Deserialize)]
        struct DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
            version: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32Version,
            inner: ImplLweCircuitBoostrapPrivateFunctionalPackingKeyswitchKeys<Vec<u32>>,
        }
        let deserialized: DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 =
            bincode::deserialize(serialized)
                .map_err(DefaultSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
                version:
                    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
                version: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32Version::V0,
                inner,
            } => Ok(LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
                inner,
            )),
        }
    }

    unsafe fn deserialize_unchecked(
        &mut self,
        serialized: &[u8],
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes an LWE circuit bootstrap private functional
/// packing keyswitch vector.
impl EntityDeserializationEngine<&[u8], LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    ///     GlweDimension, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(10);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomposition_base_log = DecompositionBaseLog(3);
    /// let decomposition_level_count = DecompositionLevelCount(5);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    ///
    /// let cbs_private_functional_packing_keyswitch_key:
    ///     LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 =
    ///     engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_base_log,
    ///         decomposition_level_count,
    ///         noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized =
    ///     serialization_engine.serialize(&cbs_private_functional_packing_keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        EntityDeserializationError<Self::EngineError>,
    > {
        #[derive(Deserialize)]
        struct DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
            version: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64Version,
            inner: ImplLweCircuitBoostrapPrivateFunctionalPackingKeyswitchKeys<Vec<u64>>,
        }
        let deserialized: DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 =
            bincode::deserialize(serialized)
                .map_err(DefaultSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
                version:
                    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
                version: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64Version::V0,
                inner,
            } => Ok(LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
                inner,
            )),
        }
    }

    unsafe fn deserialize_unchecked(
        &mut self,
        serialized: &[u8],
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LweKeyswitchKey32> for DefaultSerializationEngine {
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
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(keyswitch_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweKeyswitchKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweKeyswitchKey32 {
            version: LweKeyswitchKey32Version,
            inner: ImplLweKeyswitchKey<Vec<u32>>,
        }
        let deserialized: DeserializableLweKeyswitchKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweKeyswitchKey32 {
                version: LweKeyswitchKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweKeyswitchKey32 {
                version: LweKeyswitchKey32Version::V0,
                inner,
            } => Ok(LweKeyswitchKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweKeyswitchKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LweKeyswitchKey64> for DefaultSerializationEngine {
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
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(keyswitch_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweKeyswitchKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweKeyswitchKey64 {
            version: LweKeyswitchKey64Version,
            inner: ImplLweKeyswitchKey<Vec<u64>>,
        }
        let deserialized: DeserializableLweKeyswitchKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweKeyswitchKey64 {
                version: LweKeyswitchKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweKeyswitchKey64 {
                version: LweKeyswitchKey64Version::V0,
                inner,
            } => Ok(LweKeyswitchKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweKeyswitchKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE secret key entity.
impl EntityDeserializationEngine<&[u8], LweSecretKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&lwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(lwe_secret_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSecretKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSecretKey32 {
            version: LweSecretKey32Version,
            inner: ImplLweSecretKey<BinaryKeyKind, Vec<u32>>,
        }
        let deserialized: DeserializableLweSecretKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSecretKey32 {
                version: LweSecretKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSecretKey32 {
                version: LweSecretKey32Version::V0,
                inner,
            } => Ok(LweSecretKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSecretKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE secret key entity.
impl EntityDeserializationEngine<&[u8], LweSecretKey64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&lwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(lwe_secret_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSecretKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSecretKey64 {
            version: LweSecretKey64Version,
            inner: ImplLweSecretKey<BinaryKeyKind, Vec<u64>>,
        }
        let deserialized: DeserializableLweSecretKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSecretKey64 {
                version: LweSecretKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSecretKey64 {
                version: LweSecretKey64Version::V0,
                inner,
            } => Ok(LweSecretKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSecretKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes an LWE public key.
impl EntityDeserializationEngine<&[u8], LwePublicKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, LwePublicKeyZeroEncryptionCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let lwe_public_key_zero_encryption_count = LwePublicKeyZeroEncryptionCount(42);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let public_key: LwePublicKey32 = engine.generate_new_lwe_public_key(
    ///     &lwe_secret_key,
    ///     noise,
    ///     lwe_public_key_zero_encryption_count,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&public_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(public_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LwePublicKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLwePublicKey32 {
            version: LwePublicKey32Version,
            inner: ImplLweList<Vec<u32>>,
        }
        let deserialized: DeserializableLwePublicKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLwePublicKey32 {
                version: LwePublicKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLwePublicKey32 {
                version: LwePublicKey32Version::V0,
                inner,
            } => Ok(LwePublicKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LwePublicKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes an LWE public key.
impl EntityDeserializationEngine<&[u8], LwePublicKey64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, LwePublicKeyZeroEncryptionCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let lwe_public_key_zero_encryption_count = LwePublicKeyZeroEncryptionCount(42);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let public_key: LwePublicKey64 = engine.generate_new_lwe_public_key(
    ///     &lwe_secret_key,
    ///     noise,
    ///     lwe_public_key_zero_encryption_count,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&public_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(public_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LwePublicKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLwePublicKey64 {
            version: LwePublicKey64Version,
            inner: ImplLweList<Vec<u64>>,
        }
        let deserialized: DeserializableLwePublicKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLwePublicKey64 {
                version: LwePublicKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLwePublicKey64 {
                version: LwePublicKey64Version::V0,
                inner,
            } => Ok(LwePublicKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LwePublicKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a plaintext entity.
impl EntityDeserializationEngine<&[u8], Plaintext32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext32 = engine.create_plaintext_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Plaintext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintext32 {
            version: Plaintext32Version,
            inner: ImplPlaintext<u32>,
        }
        let deserialized: DeserializablePlaintext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintext32 {
                version: Plaintext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintext32 {
                version: Plaintext32Version::V0,
                inner,
            } => Ok(Plaintext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Plaintext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a plaintext entity.
impl EntityDeserializationEngine<&[u8], Plaintext64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext64 = engine.create_plaintext_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Plaintext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintext64 {
            version: Plaintext64Version,
            inner: ImplPlaintext<u64>,
        }
        let deserialized: DeserializablePlaintext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintext64 {
                version: Plaintext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintext64 {
                version: Plaintext64Version::V0,
                inner,
            } => Ok(Plaintext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Plaintext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a plaintext vector entity.
impl EntityDeserializationEngine<&[u8], PlaintextVector32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext_vector, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PlaintextVector32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintextVector32 {
            version: PlaintextVector32Version,
            inner: ImplPlaintextList<Vec<u32>>,
        }
        let deserialized: DeserializablePlaintextVector32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintextVector32 {
                version: PlaintextVector32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintextVector32 {
                version: PlaintextVector32Version::V0,
                inner,
            } => Ok(PlaintextVector32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PlaintextVector32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a plaintext vector entity.
impl EntityDeserializationEngine<&[u8], PlaintextVector64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext_vector, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PlaintextVector64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintextVector64 {
            version: PlaintextVector64Version,
            inner: ImplPlaintextList<Vec<u64>>,
        }
        let deserialized: DeserializablePlaintextVector64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintextVector64 {
                version: PlaintextVector64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintextVector64 {
                version: PlaintextVector64Version::V0,
                inner,
            } => Ok(PlaintextVector64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PlaintextVector64 {
        self.deserialize(serialized).unwrap()
    }
}
