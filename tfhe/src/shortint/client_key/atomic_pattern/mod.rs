pub mod ks32;
pub mod standard;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::shortint::backward_compatibility::client_key::atomic_pattern::AtomicPatternClientKeyVersions;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::DynamicDistribution;
use crate::shortint::{
    AtomicPatternKind, AtomicPatternParameters, EncryptionKeyChoice, ShortintParameterSet,
};

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

    /// The kind of secret key used for encryption
    fn encryption_key_choice(&self) -> EncryptionKeyChoice;

    /// Encryption key used for ciphertexts "in the middle" of the atomic pattern
    ///
    /// For KS-PBS this is the small key, for PBS-KS this is the big key
    fn intermediate_encryption_key(&self) -> LweSecretKeyView<'_, u64>;

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

    fn intermediate_encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        (*self).intermediate_encryption_key()
    }

    fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        (*self).encryption_key_choice()
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
#[allow(clippy::large_enum_variant)] // The difference in size is just because of the wopbs params in std key
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
                StandardAtomicPatternClientKey::new_with_engine(ap_params, None, engine),
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

    fn intermediate_encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        match self {
            Self::Standard(ap) => ap.intermediate_encryption_key(),
            Self::KeySwitch32(ap) => ap.intermediate_encryption_key(),
        }
    }

    fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        match self {
            Self::Standard(ap) => ap.encryption_key_choice(),
            Self::KeySwitch32(ap) => ap.encryption_key_choice(),
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
