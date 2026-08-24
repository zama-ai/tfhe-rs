use super::TranscipherSession;
use crate::high_level_api::backward_compatibility::transciphering::OneTimePadFheSecretMaskVersionedOwned;
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
    OneTimePadFheSecretMask as ShortintOneTimePadFheSecretMask, OneTimePadFheState,
    OneTimePadPlainSecretMask,
};
use crate::{ClientKey, Tag};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

/// Device-polymorphic FHE-encrypted Pad
pub struct OneTimePadFheSecretMask {
    inner: InnerOneTimePadFheSecretMask,
    tag: Tag,
}

enum InnerOneTimePadFheSecretMask {
    Cpu(ShortintOneTimePadFheSecretMask),
    #[cfg(feature = "gpu")]
    #[expect(
        dead_code,
        reason = "GPU transciphering is still stubbed, so the pad is built but never consumed"
    )]
    Cuda(CudaUnsignedRadixCiphertext),
}

impl OneTimePadFheSecretMask {
    /// The CPU (shortint) pad, which is the only form that is serialized.
    ///
    /// GPU-resident keys are not yet serializable (the whole GPU transcipher
    /// path is still stubbed).
    fn to_cpu_key(&self) -> ShortintOneTimePadFheSecretMask {
        match &self.inner {
            InnerOneTimePadFheSecretMask::Cpu(k) => k.clone(),
            #[cfg(feature = "gpu")]
            InnerOneTimePadFheSecretMask::Cuda(_) => {
                panic!("serialization of a GPU-resident OTP mask is not supported yet")
            }
        }
    }

    fn new_cpu(mask: ShortintOneTimePadFheSecretMask, tag: Tag) -> Self {
        Self {
            inner: InnerOneTimePadFheSecretMask::Cpu(mask),
            tag,
        }
    }

    pub fn from_raw_parts(mask: ShortintOneTimePadFheSecretMask, tag: Tag) -> Self {
        Self::new_cpu(mask, tag)
    }

    pub fn into_raw_parts(self) -> (ShortintOneTimePadFheSecretMask, Tag) {
        (self.to_cpu_key(), self.tag)
    }

    /// Generate a fresh FHE-encrypted pad of `n_bits` bits server-side using
    /// OPRF machinery.
    pub fn new_random(seed: impl OprfSeed, n_bits: u64) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let transciphering_key = cpu_key.transciphering_key()?;
                let shortint_sks = &cpu_key.key.key.key;
                Ok(Self::new_cpu(
                    ShortintOneTimePadFheSecretMask::new_random(
                        seed,
                        transciphering_key,
                        shortint_sks,
                        n_bits,
                    ),
                    cpu_key.tag.clone(),
                ))
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "OneTimePadFheSecretMask::new_random is not yet supported on GPU".to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "OneTimePadFheSecretMask::new_random is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

impl Tagged for OneTimePadFheSecretMask {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl Serialize for OneTimePadFheSecretMask {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.to_cpu_key(), &self.tag).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OneTimePadFheSecretMask {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (mask, tag) = <(ShortintOneTimePadFheSecretMask, Tag)>::deserialize(deserializer)?;
        Ok(Self::new_cpu(mask, tag))
    }
}

// Only CPU data are serialized so we only versionize the CPU type.
#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct OneTimePadFheSecretMaskVersionOwned {
    key: <ShortintOneTimePadFheSecretMask as VersionizeOwned>::VersionedOwned,
    tag: <Tag as VersionizeOwned>::VersionedOwned,
}

impl Versionize for OneTimePadFheSecretMask {
    type Versioned<'vers> = OneTimePadFheSecretMaskVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        OneTimePadFheSecretMaskVersionedOwned::V0(OneTimePadFheSecretMaskVersionOwned {
            key: self.to_cpu_key().versionize_owned(),
            tag: self.tag.clone().versionize_owned(),
        })
    }
}

impl VersionizeOwned for OneTimePadFheSecretMask {
    type VersionedOwned = OneTimePadFheSecretMaskVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        OneTimePadFheSecretMaskVersionedOwned::V0(OneTimePadFheSecretMaskVersionOwned {
            key: self.to_cpu_key().versionize_owned(),
            tag: self.tag.versionize_owned(),
        })
    }
}

impl Unversionize for OneTimePadFheSecretMask {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            OneTimePadFheSecretMaskVersionedOwned::V0(v0) => Ok(Self::new_cpu(
                ShortintOneTimePadFheSecretMask::unversionize(v0.key)?,
                Tag::unversionize(v0.tag)?,
            )),
        }
    }
}

impl FheTryEncrypt<OneTimePadPlainSecretMask, ClientKey> for OneTimePadFheSecretMask {
    type Error = crate::Error;

    fn try_encrypt(plain: OneTimePadPlainSecretMask, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_mask = plain.encrypt(&key.key.key.key);
        let tag = key.tag.clone();
        try_with_internal_keys(|keys| match keys {
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let blocks: Vec<_> = cpu_mask.ciphertexts().to_vec();
                let radix = RadixCiphertext::from(blocks);
                Ok(Self {
                    inner: InnerOneTimePadFheSecretMask::Cuda(
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                            &radix,
                            &cuda_key.streams,
                        ),
                    ),
                    tag,
                })
            }
            _ => Ok(Self::new_cpu(cpu_mask, tag)),
        })
    }
}

impl FheDecrypt<OneTimePadPlainSecretMask> for OneTimePadFheSecretMask {
    fn decrypt(&self, cks: &ClientKey) -> OneTimePadPlainSecretMask {
        match &self.inner {
            InnerOneTimePadFheSecretMask::Cpu(mask) => mask.decrypt(&cks.key.key.key),
            #[cfg(feature = "gpu")]
            InnerOneTimePadFheSecretMask::Cuda(_) => {
                panic!("decryption of a GPU-resident OTP mask is not supported yet")
            }
        }
    }
}

impl TranscipherSession {
    /// Build a one-time-pad transcipher session bound to the current
    /// thread-local server key.
    ///
    /// `mask` must match the current server key device. There is no IV: the pad
    /// itself is the keystream, consumed from bit 0 onwards.
    ///
    /// GPU is not yet supported (no `CudaIntegerTranscipherer` impl for the
    /// one-time pad).
    pub fn one_time_pad(mask: OneTimePadFheSecretMask) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match (mask.inner, keys) {
            (InnerOneTimePadFheSecretMask::Cpu(m), Some(InternalServerKey::Cpu(_))) => {
                let state = OneTimePadFheState::new(m);
                Ok(Self::new_cpu(
                    crate::transciphering::TranscipherSession::OneTimePad(state),
                ))
            }
            #[cfg(feature = "gpu")]
            (InnerOneTimePadFheSecretMask::Cuda(_), Some(InternalServerKey::Cuda(_))) => {
                Err(crate::Error::new(
                    "One-time pad on GPU is not yet available as a Transcipherer".to_owned(),
                ))
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "OneTimePadFheSecretMask device does not match the current server key device"
                    .to_owned(),
            )),
        })
    }
}

impl Named for OneTimePadFheSecretMask {
    const NAME: &'static str = "high_level_api::OneTimePadFheSecretMask";
}
