pub mod ks32;
pub mod standard;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{LweKeyswitchKeyOwned, SeededLweKeyswitchKeyOwned};
use crate::shortint::backward_compatibility::client_key::atomic_pattern::AtomicPatternClientKeyVersions;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, CompressionPrivateKeys,
    DecompressionKey,
};
use crate::shortint::parameters::{
    CompressionParameters, DynamicDistribution, ShortintKeySwitchingParameters,
};
use crate::shortint::{AtomicPatternKind, AtomicPatternParameters, ShortintParameterSet};

use super::secret_encryption_key::SecretEncryptionKeyView;
use super::{LweSecretKeyOwned, LweSecretKeyView};

pub use ks32::*;
pub use standard::*;

/// An atomic pattern used for encryption
///
/// This category of atomic patterns will be used by the [`ClientKey`](super::ClientKey) to encrypt
/// ciphertexts, and to generate a [`ServerKey`](crate::shortint::ServerKey) that can be used for
/// evaluation.
pub trait EncryptionAtomicPattern {
    /// The parameters associated with this client key
    fn parameters(&self) -> ShortintParameterSet;

    /// The secret key used for encryption
    fn encryption_key(&self) -> LweSecretKeyView<'_, u64>;

    /// The noise distribution used for encryption
    fn encryption_noise(&self) -> DynamicDistribution<u64>;

    /// The kind of atomic pattern that will be used by the generated
    /// [`ServerKey`](crate::shortint::ServerKey)
    fn kind(&self) -> AtomicPatternKind;

    fn encryption_key_and_noise(&self) -> (LweSecretKeyView<'_, u64>, DynamicDistribution<u64>) {
        (self.encryption_key(), self.encryption_noise())
    }
}

// This blancket impl is used to allow "views" of client keys, without having to re-implement the
// trait
impl<T: EncryptionAtomicPattern> EncryptionAtomicPattern for &T {
    fn parameters(&self) -> ShortintParameterSet {
        (*self).parameters()
    }

    fn encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        (*self).encryption_key()
    }

    fn encryption_noise(&self) -> DynamicDistribution<u64> {
        (*self).encryption_noise()
    }

    fn kind(&self) -> AtomicPatternKind {
        (*self).kind()
    }
}

/// The client key materials for all the supported Atomic Patterns
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(AtomicPatternClientKeyVersions)]
pub enum AtomicPatternClientKey {
    Standard(StandardAtomicPatternClientKey),
    KeySwitch32(KS32AtomicPatternClientKey),
}

impl AtomicPatternClientKey {
    pub(crate) fn new_with_engine(
        parameters: AtomicPatternParameters,
        engine: &mut ShortintEngine,
    ) -> Self {
        match parameters {
            AtomicPatternParameters::Standard(ap_params) => Self::Standard(
                StandardAtomicPatternClientKey::new_with_engine(ap_params, engine),
            ),
            AtomicPatternParameters::KeySwitch32(ap_params) => Self::KeySwitch32(
                KS32AtomicPatternClientKey::new_with_engine(ap_params, engine),
            ),
        }
    }

    pub fn new(parameters: AtomicPatternParameters) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| Self::new_with_engine(parameters, engine))
    }

    pub fn try_from_lwe_encryption_key(
        encryption_key: LweSecretKeyOwned<u64>,
        parameters: AtomicPatternParameters,
    ) -> crate::Result<Self> {
        match parameters {
            AtomicPatternParameters::Standard(ap_params) => Ok(Self::Standard(
                StandardAtomicPatternClientKey::try_from_lwe_encryption_key(
                    encryption_key,
                    ap_params,
                )?,
            )),
            AtomicPatternParameters::KeySwitch32(ap_params) => Ok(Self::KeySwitch32(
                KS32AtomicPatternClientKey::try_from_lwe_encryption_key(encryption_key, ap_params)?,
            )),
        }
    }

    pub fn new_compression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> CompressionKey {
        match self {
            Self::Standard(std_cks) => std_cks.new_compression_key(private_compression_key),
            Self::KeySwitch32(ks32_cks) => ks32_cks.new_compression_key(private_compression_key),
        }
    }

    pub fn new_compressed_compression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> CompressedCompressionKey {
        match self {
            Self::Standard(std_cks) => {
                std_cks.new_compressed_compression_key(private_compression_key)
            }
            Self::KeySwitch32(ks32_cks) => {
                ks32_cks.new_compressed_compression_key(private_compression_key)
            }
        }
    }

    pub fn new_decompression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> DecompressionKey {
        match self {
            Self::Standard(std_cks) => std_cks.new_decompression_key(private_compression_key),
            Self::KeySwitch32(ks32_cks) => ks32_cks.new_decompression_key(private_compression_key),
        }
    }

    /// Create a decompression key with different parameters than the one in the secret key.
    ///
    /// This allows for example to compress using cpu parameters and decompress with gpu parameters
    pub fn new_decompression_key_with_params(
        &self,
        private_compression_key: &CompressionPrivateKeys,
        compression_params: CompressionParameters,
    ) -> DecompressionKey {
        match self {
            Self::Standard(std_cks) => std_cks
                .new_decompression_key_with_params(private_compression_key, compression_params),
            Self::KeySwitch32(ks32_cks) => ks32_cks
                .new_decompression_key_with_params(private_compression_key, compression_params),
        }
    }

    pub fn new_decompression_key_with_params_and_engine(
        &self,
        private_compression_key: &CompressionPrivateKeys,
        compression_params: CompressionParameters,
        engine: &mut ShortintEngine,
    ) -> DecompressionKey {
        match self {
            Self::Standard(std_cks) => std_cks.new_decompression_key_with_params_and_engine(
                private_compression_key,
                compression_params,
                engine,
            ),
            Self::KeySwitch32(ks32_cks) => ks32_cks.new_decompression_key_with_params_and_engine(
                private_compression_key,
                compression_params,
                engine,
            ),
        }
    }

    pub fn new_compressed_decompression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> CompressedDecompressionKey {
        match self {
            Self::Standard(std_cks) => {
                std_cks.new_compressed_decompression_key(private_compression_key)
            }
            Self::KeySwitch32(ks32_cks) => {
                ks32_cks.new_compressed_decompression_key(private_compression_key)
            }
        }
    }

    pub(crate) fn new_keyswitching_key_with_engine(
        &self,
        input_secret_key: &SecretEncryptionKeyView<'_>,
        params: ShortintKeySwitchingParameters,
        engine: &mut ShortintEngine,
    ) -> LweKeyswitchKeyOwned<u64> {
        match self {
            Self::Standard(ap) => {
                ap.new_keyswitching_key_with_engine(input_secret_key, params, engine)
            }
            Self::KeySwitch32(ap) => {
                ap.new_keyswitching_key_with_engine(input_secret_key, params, engine)
            }
        }
    }

    pub(crate) fn new_seeded_keyswitching_key_with_engine(
        &self,
        input_secret_key: &SecretEncryptionKeyView<'_>,
        params: ShortintKeySwitchingParameters,
        engine: &mut ShortintEngine,
    ) -> SeededLweKeyswitchKeyOwned<u64> {
        match self {
            Self::Standard(ap) => {
                ap.new_seeded_keyswitching_key_with_engine(input_secret_key, params, engine)
            }
            Self::KeySwitch32(ap) => {
                ap.new_seeded_keyswitching_key_with_engine(input_secret_key, params, engine)
            }
        }
    }
}

impl EncryptionAtomicPattern for AtomicPatternClientKey {
    fn parameters(&self) -> ShortintParameterSet {
        match self {
            Self::Standard(ap) => ap.parameters.into(),
            Self::KeySwitch32(ap) => ap.parameters.into(),
        }
    }

    fn encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        match self {
            Self::Standard(ap) => ap.encryption_key(),
            Self::KeySwitch32(ap) => ap.encryption_key(),
        }
    }

    fn encryption_noise(&self) -> DynamicDistribution<u64> {
        match self {
            Self::Standard(ap) => ap.encryption_noise(),
            Self::KeySwitch32(ap) => ap.encryption_noise(),
        }
    }

    fn kind(&self) -> AtomicPatternKind {
        match self {
            Self::Standard(ap_cks) => ap_cks.kind(),
            Self::KeySwitch32(ap_cks) => ap_cks.kind(),
        }
    }
}
