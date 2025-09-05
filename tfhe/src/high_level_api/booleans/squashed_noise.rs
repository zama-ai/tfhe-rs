use super::base::FheBool;
use crate::backward_compatibility::booleans::{
    InnerSquashedNoiseBooleanVersionedOwned, SquashedNoiseFheBoolVersions,
};
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::errors::UninitializedNoiseSquashing;
use crate::high_level_api::global_state::{self, with_internal_keys};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::{FheDecrypt, SquashNoise, Tagged};
use crate::high_level_api::SquashedNoiseCiphertextState;
use crate::integer::ciphertext::SquashedNoiseBooleanBlock;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::named::Named;
use crate::{ClientKey, Device, Tag};
use serde::{Deserializer, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

/// Enum that manages the current inner representation of a boolean.
pub(in crate::high_level_api) enum InnerSquashedNoiseBoolean {
    Cpu(SquashedNoiseBooleanBlock),
}

impl Clone for InnerSquashedNoiseBoolean {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
        }
    }
}
impl serde::Serialize for InnerSquashedNoiseBoolean {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.on_cpu().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for InnerSquashedNoiseBoolean {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut deserialized = Self::Cpu(
            crate::integer::ciphertext::SquashedNoiseBooleanBlock::deserialize(deserializer)?,
        );
        deserialized.move_to_device_of_server_key_if_set();
        Ok(deserialized)
    }
}

// Only CPU data are serialized so we only versionize the CPU type.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub(crate) struct InnerSquashedNoiseBooleanVersionOwned(
    <crate::integer::ciphertext::SquashedNoiseBooleanBlock as VersionizeOwned>::VersionedOwned,
);

impl Versionize for InnerSquashedNoiseBoolean {
    type Versioned<'vers> = InnerSquashedNoiseBooleanVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.into_owned().versionize_owned();
        InnerSquashedNoiseBooleanVersionedOwned::V0(InnerSquashedNoiseBooleanVersionOwned(
            versioned,
        ))
    }
}
impl VersionizeOwned for InnerSquashedNoiseBoolean {
    type VersionedOwned = InnerSquashedNoiseBooleanVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        InnerSquashedNoiseBooleanVersionedOwned::V0(InnerSquashedNoiseBooleanVersionOwned(
            cpu_data.into_owned().versionize_owned(),
        ))
    }
}

impl Unversionize for InnerSquashedNoiseBoolean {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            InnerSquashedNoiseBooleanVersionedOwned::V0(v0) => {
                let mut unversioned = Self::Cpu(
                    crate::integer::ciphertext::SquashedNoiseBooleanBlock::unversionize(v0.0)?,
                );
                unversioned.move_to_device_of_server_key_if_set();
                Ok(unversioned)
            }
        }
    }
}

impl InnerSquashedNoiseBoolean {
    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    pub(crate) fn on_cpu(&self) -> MaybeCloned<'_, SquashedNoiseBooleanBlock> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn move_to_device(&mut self, device: Device) {
        match (&self, device) {
            (Self::Cpu(_), Device::Cpu) => {
                // Nothing to do, we already are on the correct device
            }
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => panic!("Cuda/Hpu devices do not support noise squashing yet"),
        }
    }

    #[inline]
    pub(crate) fn move_to_device_of_server_key_if_set(&mut self) {
        if let Some(device) = global_state::device_of_internal_keys() {
            self.move_to_device(device);
        }
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize, Versionize)]
#[versionize(SquashedNoiseFheBoolVersions)]
pub struct SquashedNoiseFheBool {
    pub(in crate::high_level_api) inner: InnerSquashedNoiseBoolean,
    pub(in crate::high_level_api) state: SquashedNoiseCiphertextState,
    tag: Tag,
}

impl SquashedNoiseFheBool {
    pub(in crate::high_level_api) fn new(
        inner: InnerSquashedNoiseBoolean,
        state: SquashedNoiseCiphertextState,
        tag: Tag,
    ) -> Self {
        Self { inner, state, tag }
    }
}

impl Named for SquashedNoiseFheBool {
    const NAME: &'static str = "high_level_api::SquashedNoiseFheBool";
}

impl SquashedNoiseFheBool {
    pub fn underlying_squashed_noise_ciphertext(
        &self,
    ) -> MaybeCloned<'_, SquashedNoiseBooleanBlock> {
        self.inner.on_cpu()
    }
}

impl FheDecrypt<bool> for SquashedNoiseFheBool {
    fn decrypt(&self, key: &ClientKey) -> bool {
        let noise_squashing_private_key = key.private_noise_squashing_decryption_key(self.state);
        noise_squashing_private_key
            .decrypt_bool(&self.inner.on_cpu())
            .unwrap()
    }
}

impl Tagged for SquashedNoiseFheBool {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl SquashNoise for FheBool {
    type Output = SquashedNoiseFheBool;

    fn squash_noise(&self) -> crate::Result<Self::Output> {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(server_key) => {
                let noise_squashing_key = server_key
                    .key
                    .noise_squashing_key
                    .as_ref()
                    .ok_or(UninitializedNoiseSquashing)?;

                Ok(SquashedNoiseFheBool {
                    inner: InnerSquashedNoiseBoolean::Cpu(
                        noise_squashing_key.squash_boolean_block_noise(
                            server_key.key.pbs_key(),
                            &self.ciphertext.on_cpu(),
                        )?,
                    ),
                    state: SquashedNoiseCiphertextState::Normal,
                    tag: server_key.tag.clone(),
                })
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;

                let noise_squashing_key = cuda_key
                    .key
                    .noise_squashing_key
                    .as_ref()
                    .ok_or(UninitializedNoiseSquashing)?;

                let cuda_block = CudaBooleanBlock(match self.ciphertext.on_gpu(streams) {
                    MaybeCloned::Borrowed(gpu_ct) => {
                        unsafe {
                            // SAFETY
                            // The gpu_ct is a ref, meaning it belongs to the thing
                            // that is being iterated on, so it will stay alive for the
                            // whole function
                            gpu_ct.duplicate_async(streams)
                        }
                    }
                    MaybeCloned::Cloned(gpu_ct) => gpu_ct,
                });
                let cuda_squashed_block = noise_squashing_key.squash_boolean_block_noise(
                    cuda_key.pbs_key(),
                    &cuda_block,
                    streams,
                )?;
                let cpu_squashed_block =
                    cuda_squashed_block.to_squashed_noise_boolean_block(streams);

                Ok(SquashedNoiseFheBool {
                    inner: InnerSquashedNoiseBoolean::Cpu(cpu_squashed_block),
                    state: SquashedNoiseCiphertextState::Normal,
                    tag: cuda_key.tag.clone(),
                })
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                Err(crate::error!("Hpu devices do not support noise squashing"))
            }
        })
    }
}
