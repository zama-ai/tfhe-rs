use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::high_level_api::backward_compatibility::transciphering::StreamCiphertextVersions;
use crate::integer::transciphering::{IntegerStreamCiphertext, IntegerStreamCiphertextKind};
use crate::named::Named;
use crate::transciphering::StreamCipherKind;

/// A symmetric-cipher ciphertext, produced by [`HlStreamCipher::try_encrypt`]
/// and consumed by [`HlTranscipherer::transcipher`].
///
/// Its bytes are stream-cipher output, which is plaintext from the FHE point of
/// view. It therefore holds no FHE ciphertext, does not depend on the choice of parameters, carries
/// no [`Tag`], and is not bound to a device.
///
/// [`HlStreamCipher::try_encrypt`]: super::HlStreamCipher::try_encrypt
/// [`HlTranscipherer::transcipher`]: super::HlTranscipherer::transcipher
/// [`Tag`]: crate::Tag
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(StreamCiphertextVersions)]
pub struct StreamCiphertext {
    inner: IntegerStreamCiphertext,
}

impl StreamCiphertext {
    /// Cipher family that produced this ciphertext. A [`TranscipherSession`]
    /// refuses inputs from another family.
    ///
    /// [`TranscipherSession`]: super::TranscipherSession
    pub fn cipher_kind(&self) -> StreamCipherKind {
        self.inner.inner().kind()
    }

    /// Shape of the value this ciphertext encrypts, which decides the type it
    /// can be transciphered into.
    pub fn kind(&self) -> IntegerStreamCiphertextKind {
        self.inner.kind()
    }

    /// Keystream bit position at which this ciphertext was encrypted.
    pub fn encryption_counter(&self) -> u64 {
        self.inner.inner().encryption_counter()
    }

    pub fn n_bits(&self) -> usize {
        self.inner.n_bits()
    }

    pub fn from_raw_parts(inner: IntegerStreamCiphertext) -> Self {
        Self { inner }
    }

    pub fn into_raw_parts(self) -> IntegerStreamCiphertext {
        self.inner
    }

    pub(super) fn integer(&self) -> &IntegerStreamCiphertext {
        &self.inner
    }
}

impl Named for StreamCiphertext {
    const NAME: &'static str = "high_level_api::StreamCiphertext";
}
