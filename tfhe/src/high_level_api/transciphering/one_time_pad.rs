use super::TranscipherSession;
use crate::conformance::ParameterSetConformant;
use crate::high_level_api::backward_compatibility::transciphering::{
    CompressedSquashedNoiseOneTimePadFheSecretMaskVersions, OneTimePadFheSecretMaskVersions,
};
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::errors::{UninitializedNoiseSquashing, UninitializedServerKey};
use crate::high_level_api::global_state::try_with_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::{
    cuda_clone, with_thread_local_cuda_streams_for_gpu_indexes,
};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::{SquashNoise, Tagged};
use crate::high_level_api::{
    CompressedSquashedNoiseCiphertextListConformanceParams, SquashedNoiseCiphertextState,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::transciphering::ciphers::one_time_pad::{
    CudaOneTimePadFheSecretMask, CudaOneTimePadState,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::transciphering::CudaTranscipherSession;
use crate::named::Named;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::shortint::oprf::OprfSeed;
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::AtomicPatternParameters;
use crate::transciphering::{
    CompressedSquashedNoiseOneTimePadFheSecretMask as TranscipheringCompressedSquashedNoiseOneTimePadFheSecretMask,
    CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams as TranscipheringCompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams,
    KeyStreamLayout, OneTimePadFheSecretMask as TranscipheringOneTimePadFheSecretMask,
    OneTimePadFheState, OneTimePadPlainSecretMask,
    SquashedNoiseOneTimePadFheSecretMask as TranscipheringSquashedNoiseOneTimePadFheSecretMask,
};
use crate::{ClientKey, ServerKey, Tag};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Device-polymorphic FHE-encrypted Pad
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(OneTimePadFheSecretMaskVersions)]
pub struct OneTimePadFheSecretMask {
    inner: InnerOneTimePadFheSecretMask,
    tag: Tag,
}

#[derive(Serialize, Deserialize, Versionize)]
#[serde(
    from = "TranscipheringOneTimePadFheSecretMask",
    into = "TranscipheringOneTimePadFheSecretMask"
)]
#[versionize(convert = "TranscipheringOneTimePadFheSecretMask")]
enum InnerOneTimePadFheSecretMask {
    Cpu(TranscipheringOneTimePadFheSecretMask),
    #[cfg(feature = "gpu")]
    Cuda(CudaOneTimePadFheSecretMask),
}

impl Clone for InnerOneTimePadFheSecretMask {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(k) => Self::Cpu(k.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(k) => Self::Cuda(cuda_clone(k)),
        }
    }
}

impl InnerOneTimePadFheSecretMask {
    /// Returns a ref to the inner cpu mask if self is on the CPU, otherwise, returns a copy that
    /// is on the CPU
    fn on_cpu(&self) -> MaybeCloned<'_, TranscipheringOneTimePadFheSecretMask> {
        match self {
            Self::Cpu(mask) => MaybeCloned::Borrowed(mask),
            // No server key at hand when decrypting or serializing, so the streams are those of
            // the GPUs holding the mask
            #[cfg(feature = "gpu")]
            Self::Cuda(mask) => {
                with_thread_local_cuda_streams_for_gpu_indexes(mask.gpu_indexes(), |streams| {
                    MaybeCloned::Cloned(mask.to_cpu(streams))
                })
            }
        }
    }
}

/// Serialization only knows the CPU mask
impl From<InnerOneTimePadFheSecretMask> for TranscipheringOneTimePadFheSecretMask {
    fn from(value: InnerOneTimePadFheSecretMask) -> Self {
        match value {
            InnerOneTimePadFheSecretMask::Cpu(k) => k,
            #[cfg(feature = "gpu")]
            InnerOneTimePadFheSecretMask::Cuda(mask) => {
                with_thread_local_cuda_streams_for_gpu_indexes(mask.gpu_indexes(), |streams| {
                    mask.to_cpu(streams)
                })
            }
        }
    }
}

impl From<TranscipheringOneTimePadFheSecretMask> for InnerOneTimePadFheSecretMask {
    fn from(value: TranscipheringOneTimePadFheSecretMask) -> Self {
        Self::Cpu(value)
    }
}

impl OneTimePadFheSecretMask {
    fn new_cpu(mask: TranscipheringOneTimePadFheSecretMask, tag: Tag) -> Self {
        Self {
            inner: InnerOneTimePadFheSecretMask::Cpu(mask),
            tag,
        }
    }

    pub fn from_raw_parts(mask: TranscipheringOneTimePadFheSecretMask, tag: Tag) -> Self {
        Self::new_cpu(mask, tag)
    }

    pub fn into_raw_parts(self) -> (TranscipheringOneTimePadFheSecretMask, Tag) {
        (self.inner.into(), self.tag)
    }

    /// Generate a fresh FHE-encrypted pad of `n_bits` bits server-side using
    /// OPRF machinery.
    ///
    /// Pads are generated in counter mode, so the pad generated for a seed is a prefix of all
    /// the pads generated with the same seed and more bits. See
    /// [`TranscipheringOneTimePadFheSecretMask::new_random`] for details.
    ///
    /// The same seed should never be used to encrypt different data, since the generated masks
    /// would share their bits.
    pub fn new_random(seed: impl OprfSeed, n_bits: u64) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let transciphering_key = cpu_key.transciphering_key()?;
                let shortint_sks = &cpu_key.key.key.key;
                Ok(Self::new_cpu(
                    TranscipheringOneTimePadFheSecretMask::new_random(
                        seed,
                        transciphering_key,
                        shortint_sks,
                        n_bits,
                    )
                    .map_err(|e| format!("{e}"))?,
                    cpu_key.tag.clone(),
                ))
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let mask = CudaOneTimePadFheSecretMask::new_random(
                    seed,
                    cuda_key.transciphering_key()?,
                    cuda_key.pbs_key(),
                    n_bits,
                    &cuda_key.streams,
                )
                .map_err(|e| format!("{e}"))?;
                Ok(Self {
                    inner: InnerOneTimePadFheSecretMask::Cuda(mask),
                    tag: cuda_key.tag.clone(),
                })
            }
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

impl FheTryEncrypt<OneTimePadPlainSecretMask, ClientKey> for OneTimePadFheSecretMask {
    type Error = crate::Error;

    fn try_encrypt(plain: OneTimePadPlainSecretMask, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_mask = plain
            .encrypt(&key.key.key.key)
            .map_err(|e| format!("{e}"))?;
        let tag = key.tag.clone();
        try_with_internal_keys(|keys| match keys {
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => Ok(Self {
                inner: InnerOneTimePadFheSecretMask::Cuda(CudaOneTimePadFheSecretMask::from_cpu(
                    &cpu_mask,
                    &cuda_key.streams,
                )),
                tag,
            }),
            _ => Ok(Self::new_cpu(cpu_mask, tag)),
        })
    }
}

impl FheDecrypt<OneTimePadPlainSecretMask> for OneTimePadFheSecretMask {
    fn decrypt(&self, cks: &ClientKey) -> OneTimePadPlainSecretMask {
        self.inner.on_cpu().decrypt(&cks.key.key.key)
    }
}

impl TranscipherSession {
    /// Build a one-time-pad transcipher session bound to the current
    /// thread-local server key.
    ///
    /// `mask` must match the current server key device. There is no IV: the pad
    /// itself is the keystream, consumed from bit 0 onwards.
    pub fn one_time_pad(mask: OneTimePadFheSecretMask) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match (mask.inner, keys) {
            (InnerOneTimePadFheSecretMask::Cpu(m), Some(InternalServerKey::Cpu(_))) => {
                let state = OneTimePadFheState::new(m);
                Ok(Self::new_cpu(
                    crate::transciphering::TranscipherSession::OneTimePad(state),
                ))
            }
            #[cfg(feature = "gpu")]
            (InnerOneTimePadFheSecretMask::Cuda(m), Some(InternalServerKey::Cuda(_))) => {
                let state = CudaOneTimePadState::new(m);
                Ok(Self::new_gpu(CudaTranscipherSession::OneTimePad(state)))
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

#[derive(Copy, Clone)]
pub struct OneTimePadFheSecretMaskConformanceParams(pub(crate) CiphertextConformanceParams);

impl<P> From<P> for OneTimePadFheSecretMaskConformanceParams
where
    P: Into<AtomicPatternParameters>,
{
    fn from(params: P) -> Self {
        Self(params.into().to_shortint_conformance_param())
    }
}

impl From<&ServerKey> for OneTimePadFheSecretMaskConformanceParams {
    fn from(sk: &ServerKey) -> Self {
        Self(sk.key.pbs_key().key.conformance_params())
    }
}

impl ParameterSetConformant for OneTimePadFheSecretMask {
    type ParameterSet = OneTimePadFheSecretMaskConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        let Self { inner, tag: _ } = self;

        inner.on_cpu().is_conformant(&params.0)
    }
}

impl Named for OneTimePadFheSecretMask {
    const NAME: &'static str = "high_level_api::OneTimePadFheSecretMask";
}

/// FHE-encrypted pad whose noise has been squashed, so that it can be decrypted with the noise
/// squashing key.
///
/// It is obtained with [`SquashNoise::squash_noise`] on a [`OneTimePadFheSecretMask`].
/// Use [`Self::compress`] to get a [`CompressedSquashedNoiseOneTimePadFheSecretMask`] that
/// can be serialized.
pub struct SquashedNoiseOneTimePadFheSecretMask {
    inner: TranscipheringSquashedNoiseOneTimePadFheSecretMask,
    state: SquashedNoiseCiphertextState,
    tag: Tag,
}

impl SquashedNoiseOneTimePadFheSecretMask {
    pub fn into_raw_parts(self) -> (TranscipheringSquashedNoiseOneTimePadFheSecretMask, Tag) {
        (self.inner, self.tag)
    }

    /// Compress the squashed mask using the noise squashing compression key of the current
    /// server key.
    ///
    /// Returns an error if the mask comes from a decompression.
    pub fn compress(&self) -> crate::Result<CompressedSquashedNoiseOneTimePadFheSecretMask> {
        if !matches!(self.state, SquashedNoiseCiphertextState::Normal) {
            return Err(crate::Error::new(
                "A decompressed SquashedNoiseOneTimePadFheSecretMask cannot be compressed again"
                    .to_owned(),
            ));
        }

        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let compression_key = cpu_key
                    .key
                    .noise_squashing_compression_key
                    .as_ref()
                    .ok_or_else(|| {
                        crate::Error::new(
                            "Compression key for squashed noise data not set in server key"
                                .to_owned(),
                        )
                    })?;

                Ok(CompressedSquashedNoiseOneTimePadFheSecretMask {
                    inner: self.inner.compress(&compression_key.key),
                    tag: cpu_key.tag.clone(),
                })
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "SquashedNoiseOneTimePadFheSecretMask::compress is not yet supported on GPU"
                    .to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "SquashedNoiseOneTimePadFheSecretMask::compress is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

impl SquashNoise for OneTimePadFheSecretMask {
    type Output = SquashedNoiseOneTimePadFheSecretMask;

    fn squash_noise(&self) -> crate::Result<Self::Output> {
        try_with_internal_keys(|keys| match (&self.inner, keys) {
            (InnerOneTimePadFheSecretMask::Cpu(mask), Some(InternalServerKey::Cpu(cpu_key))) => {
                let noise_squashing_key = cpu_key
                    .key
                    .noise_squashing_key
                    .as_ref()
                    .ok_or(UninitializedNoiseSquashing)?;

                Ok(SquashedNoiseOneTimePadFheSecretMask {
                    inner: mask.squash_noise(&noise_squashing_key.key, &cpu_key.key.key.key)?,
                    state: SquashedNoiseCiphertextState::Normal,
                    tag: cpu_key.tag.clone(),
                })
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "OneTimePadFheSecretMask::squash_noise is only supported on CPU".to_owned(),
            )),
        })
    }
}

impl FheDecrypt<OneTimePadPlainSecretMask> for SquashedNoiseOneTimePadFheSecretMask {
    fn decrypt(&self, key: &ClientKey) -> OneTimePadPlainSecretMask {
        let decryption_key = key.private_noise_squashing_decryption_key(self.state);
        let values: Vec<u128> = self
            .inner
            .ciphertexts()
            .iter()
            .map(|ct| decryption_key.key.decrypt_squashed_noise_ciphertext(ct))
            .collect();

        OneTimePadPlainSecretMask::from_squashed_noise_decrypted_values(
            &values,
            self.inner.layout(),
        )
        .expect("The mask ciphertexts do not match the mask layout")
    }
}

impl Tagged for SquashedNoiseOneTimePadFheSecretMask {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

#[derive(Serialize, Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseOneTimePadFheSecretMaskVersions)]
pub struct CompressedSquashedNoiseOneTimePadFheSecretMask {
    inner: TranscipheringCompressedSquashedNoiseOneTimePadFheSecretMask,
    tag: Tag,
}

impl CompressedSquashedNoiseOneTimePadFheSecretMask {
    pub fn from_raw_parts(
        mask: TranscipheringCompressedSquashedNoiseOneTimePadFheSecretMask,
        tag: Tag,
    ) -> Self {
        Self { inner: mask, tag }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        TranscipheringCompressedSquashedNoiseOneTimePadFheSecretMask,
        Tag,
    ) {
        (self.inner, self.tag)
    }

    /// Extracts the squashed mask from the compressed one. This does not require any key.
    pub fn decompress(&self) -> crate::Result<SquashedNoiseOneTimePadFheSecretMask> {
        Ok(SquashedNoiseOneTimePadFheSecretMask {
            inner: self.inner.decompress()?,
            state: SquashedNoiseCiphertextState::PostDecompression,
            tag: self.tag.clone(),
        })
    }
}

impl FheDecrypt<OneTimePadPlainSecretMask> for CompressedSquashedNoiseOneTimePadFheSecretMask {
    fn decrypt(&self, key: &ClientKey) -> OneTimePadPlainSecretMask {
        self.decompress()
            .expect("Invalid CompressedSquashedNoiseOneTimePadFheSecretMask")
            .decrypt(key)
    }
}

impl Tagged for CompressedSquashedNoiseOneTimePadFheSecretMask {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams(
    pub(crate) TranscipheringCompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams,
);

impl CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams {
    pub fn new(
        list_params: CompressedSquashedNoiseCiphertextListConformanceParams,
        layout: KeyStreamLayout,
    ) -> Self {
        Self(
            TranscipheringCompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams {
                list_params: list_params.params,
                layout,
            },
        )
    }
}

/// Conformance params for a mask generated with the full plaintext space of the server key
/// parameters, which is the layout used by [`OneTimePadFheSecretMask::new_random`].
impl TryFrom<&ServerKey> for CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams {
    type Error = crate::Error;

    fn try_from(sks: &ServerKey) -> Result<Self, Self::Error> {
        let list_params = CompressedSquashedNoiseCiphertextListConformanceParams::try_from(sks)?;
        let layout = KeyStreamLayout::full_space(
            list_params.params.message_modulus,
            list_params.params.carry_modulus,
        )
        .ok_or_else(|| {
            crate::Error::new(
                "The server key parameters are not compatible with otp mask generation".to_owned(),
            )
        })?;

        Ok(Self::new(list_params, layout))
    }
}

impl ParameterSetConformant for CompressedSquashedNoiseOneTimePadFheSecretMask {
    type ParameterSet = CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        let Self { inner, tag: _ } = self;

        inner.is_conformant(&params.0)
    }
}

impl Named for CompressedSquashedNoiseOneTimePadFheSecretMask {
    const NAME: &'static str = "high_level_api::CompressedSquashedNoiseOneTimePadFheSecretMask";
}
