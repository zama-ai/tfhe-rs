use super::TranscipherSession;
use crate::high_level_api::backward_compatibility::transciphering::KreyviumFheKeyVersionedOwned;
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
    KreyviumFheKey as ShortintKreyviumFheKey, KreyviumFheState, KreyviumIV, KreyviumPlainKey,
};
use crate::{ClientKey, Tag};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

/// Device-polymorphic FHE-encrypted Kreyvium master key.
pub struct KreyviumFheKey {
    inner: InnerKreyviumFheKey,
    tag: Tag,
}

enum InnerKreyviumFheKey {
    Cpu(ShortintKreyviumFheKey),
    #[cfg(feature = "gpu")]
    #[expect(
        dead_code,
        reason = "GPU transciphering is still stubbed, so the key is built but never consumed"
    )]
    Cuda(CudaUnsignedRadixCiphertext),
}

impl KreyviumFheKey {
    /// The CPU (shortint) key, which is the only form that is serialized.
    ///
    /// GPU-resident keys are not yet serializable (the whole GPU transcipher
    /// path is still stubbed).
    fn to_cpu_key(&self) -> ShortintKreyviumFheKey {
        match &self.inner {
            InnerKreyviumFheKey::Cpu(k) => k.clone(),
            #[cfg(feature = "gpu")]
            InnerKreyviumFheKey::Cuda(_) => {
                panic!("serialization of a GPU-resident Kreyvium key is not supported yet")
            }
        }
    }

    fn new_cpu(key: ShortintKreyviumFheKey, tag: Tag) -> Self {
        Self {
            inner: InnerKreyviumFheKey::Cpu(key),
            tag,
        }
    }

    pub fn from_raw_parts(key: ShortintKreyviumFheKey, tag: Tag) -> Self {
        Self::new_cpu(key, tag)
    }

    pub fn into_raw_parts(self) -> (ShortintKreyviumFheKey, Tag) {
        (self.to_cpu_key(), self.tag)
    }
}

impl Tagged for KreyviumFheKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl Serialize for KreyviumFheKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.to_cpu_key(), &self.tag).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KreyviumFheKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (key, tag) = <(ShortintKreyviumFheKey, Tag)>::deserialize(deserializer)?;
        Ok(Self::new_cpu(key, tag))
    }
}

// Only CPU data are serialized so we only versionize the CPU type.
#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct KreyviumFheKeyVersionOwned {
    key: <ShortintKreyviumFheKey as VersionizeOwned>::VersionedOwned,
    tag: <Tag as VersionizeOwned>::VersionedOwned,
}

impl Versionize for KreyviumFheKey {
    type Versioned<'vers> = KreyviumFheKeyVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        KreyviumFheKeyVersionedOwned::V0(KreyviumFheKeyVersionOwned {
            key: self.to_cpu_key().versionize_owned(),
            tag: self.tag.clone().versionize_owned(),
        })
    }
}

impl VersionizeOwned for KreyviumFheKey {
    type VersionedOwned = KreyviumFheKeyVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        KreyviumFheKeyVersionedOwned::V0(KreyviumFheKeyVersionOwned {
            key: self.to_cpu_key().versionize_owned(),
            tag: self.tag.versionize_owned(),
        })
    }
}

impl Unversionize for KreyviumFheKey {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            KreyviumFheKeyVersionedOwned::V0(v0) => Ok(Self::new_cpu(
                ShortintKreyviumFheKey::unversionize(v0.key)?,
                Tag::unversionize(v0.tag)?,
            )),
        }
    }
}

impl FheTryEncrypt<KreyviumPlainKey, ClientKey> for KreyviumFheKey {
    type Error = crate::Error;

    fn try_encrypt(plain: KreyviumPlainKey, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_key = plain.encrypt(&key.key.key.key);
        let tag = key.tag.clone();
        try_with_internal_keys(|keys| match keys {
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let blocks: Vec<_> = Vec::from(cpu_key.ciphertexts());
                let radix = RadixCiphertext::from(blocks);
                Ok(Self {
                    inner: InnerKreyviumFheKey::Cuda(
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

impl FheDecrypt<KreyviumPlainKey> for KreyviumFheKey {
    fn decrypt(&self, cks: &ClientKey) -> KreyviumPlainKey {
        match &self.inner {
            InnerKreyviumFheKey::Cpu(key) => key.decrypt(&cks.key.key.key),
            #[cfg(feature = "gpu")]
            InnerKreyviumFheKey::Cuda(_) => {
                panic!("decryption of a GPU-resident Kreyvium key is not supported yet");
            }
        }
    }
}

impl KreyviumFheKey {
    /// Generate a fresh FHE-encrypted Kreyvium master key server-side using
    /// OPRF machinery.
    pub fn new_random(seed: impl OprfSeed) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let transciphering_key = cpu_key.transciphering_key()?;
                let shortint_sks = &cpu_key.key.key.key;
                Ok(Self::new_cpu(
                    ShortintKreyviumFheKey::new_random(seed, transciphering_key, shortint_sks),
                    cpu_key.tag.clone(),
                ))
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "KreyviumFheKey::new_random is not yet supported on GPU".to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "KreyviumFheKey::new_random is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

impl TranscipherSession {
    /// Build a Kreyvium transcipher session bound to the current thread-local
    /// server key.
    ///
    /// `key` must match the current server key device.
    pub fn kreyvium(key: KreyviumFheKey, iv: impl Into<KreyviumIV>) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match (key.inner, keys) {
            (InnerKreyviumFheKey::Cpu(k), Some(InternalServerKey::Cpu(cpu_key))) => {
                let integer_sks = &cpu_key.key.key;
                let state = KreyviumFheState::new(k, iv, &integer_sks.key);
                Ok(Self::new_cpu(
                    crate::transciphering::TranscipherSession::Kreyvium(state),
                ))
            }
            #[cfg(feature = "gpu")]
            (InnerKreyviumFheKey::Cuda(_), Some(InternalServerKey::Cuda(_))) => {
                let _ = iv; // suppress unused-parameter warning
                Err(crate::Error::new(
                    "Kreyvium on GPU is not yet fully wired".to_owned(),
                ))
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "KreyviumFheKey device does not match the current server key device".to_owned(),
            )),
        })
    }
}

impl Named for KreyviumFheKey {
    const NAME: &'static str = "high_level_api::KreyviumFheKey";
}
