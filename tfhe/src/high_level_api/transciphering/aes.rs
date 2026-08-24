use super::TranscipherSession;
use crate::high_level_api::backward_compatibility::transciphering::{
    AesFheKeyVersionOwned, AesFheKeyVersionedOwned,
};
use crate::high_level_api::errors::UninitializedServerKey;
use crate::high_level_api::global_state::try_with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
#[cfg(feature = "gpu")]
use crate::integer::RadixCiphertext;
use crate::named::Named;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::shortint::oprf::OprfSeed;
use crate::transciphering::{
    AesFheKey as ShortintAesFheKey, AesFheRoundKeys, AesFheState, AesIv, AesPlainKey,
};
use crate::{ClientKey, Tag};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

/// Device-polymorphic FHE-encrypted AES-128 master key.
pub struct AesFheKey {
    inner: InnerAesFheKey,
    tag: Tag,
}

enum InnerAesFheKey {
    Cpu(Box<ShortintAesFheKey>),
    #[cfg(feature = "gpu")]
    #[expect(
        dead_code,
        reason = "GPU transciphering is still stubbed, so the key is built but never consumed"
    )]
    Cuda(CudaUnsignedRadixCiphertext),
}

impl AesFheKey {
    /// The CPU (shortint) key, which is the only form that is serialized.
    ///
    /// GPU-resident keys are not yet serializable (the whole GPU transcipher
    /// path is still stubbed).
    fn to_cpu_key(&self) -> ShortintAesFheKey {
        match &self.inner {
            InnerAesFheKey::Cpu(k) => (**k).clone(),
            #[cfg(feature = "gpu")]
            InnerAesFheKey::Cuda(_) => {
                panic!("serialization of a GPU-resident AES key is not supported yet")
            }
        }
    }

    fn new_cpu(key: ShortintAesFheKey, tag: Tag) -> Self {
        Self {
            inner: InnerAesFheKey::Cpu(Box::new(key)),
            tag,
        }
    }

    pub fn from_raw_parts(key: ShortintAesFheKey, tag: Tag) -> Self {
        Self::new_cpu(key, tag)
    }

    pub fn into_raw_parts(self) -> (ShortintAesFheKey, Tag) {
        (self.to_cpu_key(), self.tag)
    }
}

impl Tagged for AesFheKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl Serialize for AesFheKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.to_cpu_key(), &self.tag).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AesFheKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (key, tag) = <(ShortintAesFheKey, Tag)>::deserialize(deserializer)?;
        Ok(Self::new_cpu(key, tag))
    }
}

impl Versionize for AesFheKey {
    type Versioned<'vers> = AesFheKeyVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        AesFheKeyVersionedOwned::V0(AesFheKeyVersionOwned {
            key: self.to_cpu_key().versionize_owned(),
            tag: self.tag.clone().versionize_owned(),
        })
    }
}

impl VersionizeOwned for AesFheKey {
    type VersionedOwned = AesFheKeyVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        AesFheKeyVersionedOwned::V0(AesFheKeyVersionOwned {
            key: self.to_cpu_key().versionize_owned(),
            tag: self.tag.versionize_owned(),
        })
    }
}

impl Unversionize for AesFheKey {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            AesFheKeyVersionedOwned::V0(v0) => Ok(Self::new_cpu(
                ShortintAesFheKey::unversionize(v0.key)?,
                Tag::unversionize(v0.tag)?,
            )),
        }
    }
}

impl FheTryEncrypt<AesPlainKey, ClientKey> for AesFheKey {
    type Error = crate::Error;

    fn try_encrypt(plain: AesPlainKey, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_key = plain.encrypt(&key.key.key.key);
        let tag = key.tag.clone();
        try_with_internal_keys(|keys| match keys {
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let blocks: Vec<_> = Vec::from(cpu_key.ciphertexts());
                let radix = RadixCiphertext::from(blocks);
                Ok(Self {
                    inner: InnerAesFheKey::Cuda(
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                            &radix,
                            &cuda_key.streams,
                        ),
                    ),
                    tag,
                })
            }
            _ => Ok(Self::new_cpu(cpu_key, tag)),
        })
    }
}

impl FheDecrypt<AesPlainKey> for AesFheKey {
    fn decrypt(&self, cks: &ClientKey) -> AesPlainKey {
        match &self.inner {
            InnerAesFheKey::Cpu(key) => key.decrypt(&cks.key.key.key),
            #[cfg(feature = "gpu")]
            InnerAesFheKey::Cuda(_) => {
                panic!("decryption of a GPU-resident AES key is not supported yet")
            }
        }
    }
}

impl AesFheKey {
    /// Generate a fresh FHE-encrypted AES-128 master key server-side using
    /// OPRF machinery.
    pub fn new_random(seed: impl OprfSeed) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let transciphering_key = cpu_key.transciphering_key()?;
                let shortint_sks = &cpu_key.key.key.key;
                Ok(Self::new_cpu(
                    ShortintAesFheKey::new_random(seed, transciphering_key, shortint_sks),
                    cpu_key.tag.clone(),
                ))
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "AesFheKey::new_random is not yet supported on GPU".to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "AesFheKey::new_random is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

impl TranscipherSession {
    /// Build an AES-128 transcipher session bound to the current thread-local
    /// server key.
    ///
    /// `key` must match the current server key device. The key's [`Tag`] is
    /// carried over to every ciphertext the session transciphers.
    /// Round key expansion happens internally.
    ///
    /// GPU is not yet supported (no `CudaIntegerTranscipherer` impl for AES).
    pub fn aes(key: AesFheKey, iv: impl Into<AesIv>) -> crate::Result<Self> {
        let tag = key.tag;
        try_with_internal_keys(|keys| match (key.inner, keys) {
            (InnerAesFheKey::Cpu(k), Some(InternalServerKey::Cpu(cpu_key))) => {
                let integer_sks = &cpu_key.key.key;
                let round_keys = AesFheRoundKeys::new(&integer_sks.key, &k);
                let state = AesFheState::new(round_keys, iv);
                Ok(Self::new_cpu(
                    crate::transciphering::TranscipherSession::Aes(Box::new(state)),
                    tag,
                ))
            }
            #[cfg(feature = "gpu")]
            (InnerAesFheKey::Cuda(_), Some(InternalServerKey::Cuda(_))) => {
                let _ = iv;
                Err(crate::Error::new(
                    "AES on GPU is not yet available as a Transcipherer".to_owned(),
                ))
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "AesFheKey device does not match the current server key device".to_owned(),
            )),
        })
    }
}

impl Named for AesFheKey {
    const NAME: &'static str = "high_level_api::AesFheKey";
}
