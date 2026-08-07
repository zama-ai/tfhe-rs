use super::TranscipherSession;
use crate::high_level_api::backward_compatibility::transciphering::{
    OneTimePadFheSecretMaskVersionOwned, OneTimePadFheSecretMaskVersionedOwned,
};
use crate::high_level_api::errors::UninitializedServerKey;
use crate::high_level_api::global_state::try_with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
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
use crate::ClientKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

/// Device-polymorphic FHE-encrypted Pad
pub enum OneTimePadFheSecretMask {
    Cpu(ShortintOneTimePadFheSecretMask),
    #[cfg(feature = "gpu")]
    Cuda(CudaUnsignedRadixCiphertext),
}

impl OneTimePadFheSecretMask {
    /// The CPU (shortint) pad, which is the only form that is serialized.
    ///
    /// GPU-resident keys are not yet serializable (the whole GPU transcipher
    /// path is still stubbed).
    fn to_cpu_key(&self) -> ShortintOneTimePadFheSecretMask {
        match self {
            Self::Cpu(k) => k.clone(),
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => {
                panic!("serialization of a GPU-resident OTP mask is not supported yet")
            }
        }
    }

    /// Generate a fresh FHE-encrypted pad of `n_bits` bits server-side using
    /// OPRF machinery.
    pub fn random(seed: impl OprfSeed, n_bits: u64) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let transciphering_key = cpu_key.transciphering_key()?;
                let shortint_sks = &cpu_key.key.key.key;
                Ok(Self::Cpu(ShortintOneTimePadFheSecretMask::random(
                    seed,
                    transciphering_key,
                    shortint_sks,
                    n_bits,
                )))
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "OneTimePadFheSecretMask::random is not yet supported on GPU".to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "OneTimePadFheSecretMask::random is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

impl Serialize for OneTimePadFheSecretMask {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_cpu_key().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OneTimePadFheSecretMask {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::Cpu(ShortintOneTimePadFheSecretMask::deserialize(
            deserializer,
        )?))
    }
}

impl Versionize for OneTimePadFheSecretMask {
    type Versioned<'vers> = OneTimePadFheSecretMaskVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        OneTimePadFheSecretMaskVersionedOwned::V0(OneTimePadFheSecretMaskVersionOwned(
            self.to_cpu_key().versionize_owned(),
        ))
    }
}

impl VersionizeOwned for OneTimePadFheSecretMask {
    type VersionedOwned = OneTimePadFheSecretMaskVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        OneTimePadFheSecretMaskVersionedOwned::V0(OneTimePadFheSecretMaskVersionOwned(
            self.to_cpu_key().versionize_owned(),
        ))
    }
}

impl Unversionize for OneTimePadFheSecretMask {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            OneTimePadFheSecretMaskVersionedOwned::V0(v0) => Ok(Self::Cpu(
                ShortintOneTimePadFheSecretMask::unversionize(v0.0)?,
            )),
        }
    }
}

impl FheTryEncrypt<OneTimePadPlainSecretMask, ClientKey> for OneTimePadFheSecretMask {
    type Error = crate::Error;

    fn try_encrypt(plain: OneTimePadPlainSecretMask, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_mask = plain.encrypt(&key.key.key.key);
        try_with_internal_keys(|keys| match keys {
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let blocks: Vec<_> = cpu_mask.ciphertexts().to_vec();
                let radix = RadixCiphertext::from(blocks);
                Ok(Self::Cuda(
                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix, &cuda_key.streams),
                ))
            }
            _ => Ok(Self::Cpu(cpu_mask)),
        })
    }
}

impl FheDecrypt<OneTimePadPlainSecretMask> for OneTimePadFheSecretMask {
    fn decrypt(&self, cks: &ClientKey) -> OneTimePadPlainSecretMask {
        match self {
            Self::Cpu(mask) => mask.decrypt(&cks.key.key.key),
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => {
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
        try_with_internal_keys(|keys| match (mask, keys) {
            (OneTimePadFheSecretMask::Cpu(m), Some(InternalServerKey::Cpu(_))) => {
                let state = OneTimePadFheState::new(m);
                Ok(Self::Cpu(
                    crate::transciphering::TranscipherSession::OneTimePad(state),
                ))
            }
            #[cfg(feature = "gpu")]
            (OneTimePadFheSecretMask::Cuda(_), Some(InternalServerKey::Cuda(_))) => {
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
