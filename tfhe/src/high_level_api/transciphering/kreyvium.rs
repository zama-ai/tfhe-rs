use super::TranscipherSession;
use crate::high_level_api::backward_compatibility::transciphering::KreyviumFheKeyVersions;
use crate::high_level_api::errors::UninitializedServerKey;
use crate::high_level_api::global_state::try_with_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams_for_gpu_indexes;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
#[cfg(feature = "gpu")]
use crate::integer::RadixCiphertext;
use crate::named::Named;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::shortint::oprf::OprfSeed;
use crate::transciphering::{
    KreyviumFheKey as ShortintKreyviumFheKey, KreyviumFheState, KreyviumIV, KreyviumPlainKey,
};
use crate::{ClientKey, Tag};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Device-polymorphic FHE-encrypted Kreyvium master key.
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(KreyviumFheKeyVersions)]
pub struct KreyviumFheKey {
    inner: InnerKreyviumFheKey,
    tag: Tag,
}

#[derive(Serialize, Deserialize, Versionize)]
#[serde(from = "ShortintKreyviumFheKey", into = "ShortintKreyviumFheKey")]
#[versionize(convert = "ShortintKreyviumFheKey")]
enum InnerKreyviumFheKey {
    Cpu(ShortintKreyviumFheKey),
    #[cfg(feature = "gpu")]
    Cuda(CudaUnsignedRadixCiphertext),
}

impl Clone for InnerKreyviumFheKey {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(k) => Self::Cpu(k.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(k) => {
                with_thread_local_cuda_streams_for_gpu_indexes(k.gpu_indexes(), |streams| {
                    Self::Cuda(k.duplicate(streams))
                })
            }
        }
    }
}

#[allow(clippy::fallible_impl_from)]
impl From<InnerKreyviumFheKey> for ShortintKreyviumFheKey {
    fn from(value: InnerKreyviumFheKey) -> Self {
        match value {
            InnerKreyviumFheKey::Cpu(k) => k,
            #[cfg(feature = "gpu")]
            InnerKreyviumFheKey::Cuda(_) => {
                panic!("serialization of a GPU-resident Kreyvium key is not supported yet")
            }
        }
    }
}

impl From<ShortintKreyviumFheKey> for InnerKreyviumFheKey {
    fn from(value: ShortintKreyviumFheKey) -> Self {
        Self::Cpu(value)
    }
}

impl KreyviumFheKey {
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
        (self.inner.into(), self.tag)
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
