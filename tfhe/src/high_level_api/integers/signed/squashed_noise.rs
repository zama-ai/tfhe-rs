use super::base::{FheInt, FheIntId};
use crate::backward_compatibility::integers::{
    InnerSquashedNoiseSignedRadixCiphertextVersionedOwned, SquashedNoiseFheIntVersions,
};
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::errors::UninitializedNoiseSquashing;
use crate::high_level_api::global_state::{self, with_internal_keys};
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::{
    with_cuda_internal_keys, with_thread_local_cuda_streams_for_gpu_indexes,
};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::{FheDecrypt, SquashNoise};
use crate::high_level_api::SquashedNoiseCiphertextState;
use crate::integer::block_decomposition::{RecomposableFrom, SignExtendable};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseSignedRadixCiphertext;
use crate::named::Named;
use crate::prelude::Tagged;
use crate::{ClientKey, Device, Tag};
use serde::{Deserializer, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

/// Enum that manages the current inner representation of a squashed noise FheInt .
pub(in crate::high_level_api) enum InnerSquashedNoiseSignedRadixCiphertext {
    Cpu(crate::integer::ciphertext::SquashedNoiseSignedRadixCiphertext),
    #[cfg(feature = "gpu")]
    Cuda(CudaSquashedNoiseSignedRadixCiphertext),
}

impl Clone for InnerSquashedNoiseSignedRadixCiphertext {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                with_thread_local_cuda_streams_for_gpu_indexes(inner.gpu_indexes(), |streams| {
                    Self::Cuda(inner.duplicate(streams))
                })
            }
        }
    }
}
impl serde::Serialize for InnerSquashedNoiseSignedRadixCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.on_cpu().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for InnerSquashedNoiseSignedRadixCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut deserialized = Self::Cpu(
            crate::integer::ciphertext::SquashedNoiseSignedRadixCiphertext::deserialize(
                deserializer,
            )?,
        );
        deserialized.move_to_device_of_server_key_if_set();
        Ok(deserialized)
    }
}

// Only CPU data are serialized so we only versionize the CPU type.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub(crate) struct InnerSquashedNoiseSignedRadixCiphertextVersionOwned(
    <crate::integer::ciphertext::SquashedNoiseSignedRadixCiphertext as VersionizeOwned>::VersionedOwned,
);

impl Versionize for InnerSquashedNoiseSignedRadixCiphertext {
    type Versioned<'vers> = InnerSquashedNoiseSignedRadixCiphertextVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.into_owned().versionize_owned();
        InnerSquashedNoiseSignedRadixCiphertextVersionedOwned::V0(
            InnerSquashedNoiseSignedRadixCiphertextVersionOwned(versioned),
        )
    }
}
impl VersionizeOwned for InnerSquashedNoiseSignedRadixCiphertext {
    type VersionedOwned = InnerSquashedNoiseSignedRadixCiphertextVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        InnerSquashedNoiseSignedRadixCiphertextVersionedOwned::V0(
            InnerSquashedNoiseSignedRadixCiphertextVersionOwned(
                cpu_data.into_owned().versionize_owned(),
            ),
        )
    }
}

impl Unversionize for InnerSquashedNoiseSignedRadixCiphertext {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            InnerSquashedNoiseSignedRadixCiphertextVersionedOwned::V0(v0) => {
                let mut unversioned = Self::Cpu(
                    crate::integer::ciphertext::SquashedNoiseSignedRadixCiphertext::unversionize(
                        v0.0,
                    )?,
                );
                unversioned.move_to_device_of_server_key_if_set();
                Ok(unversioned)
            }
        }
    }
}

impl InnerSquashedNoiseSignedRadixCiphertext {
    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    pub(crate) fn on_cpu(
        &self,
    ) -> MaybeCloned<'_, crate::integer::ciphertext::SquashedNoiseSignedRadixCiphertext> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_streams_for_gpu_indexes(ct.gpu_indexes(), |streams| {
                    MaybeCloned::Cloned(ct.to_squashed_noise_signed_radix_ciphertext(streams))
                })
            }
        }
    }
    fn current_device(&self) -> crate::Device {
        match self {
            Self::Cpu(_) => crate::Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => crate::Device::CudaGpu,
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    fn move_to_device(&mut self, target_device: Device) {
        let current_device = self.current_device();

        if current_device == target_device {
            #[cfg(feature = "gpu")]
            // We may not be on the correct Cuda device
            if let Self::Cuda(cuda_ct) = self {
                with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    if cuda_ct.gpu_indexes() != streams.gpu_indexes() {
                        *cuda_ct = cuda_ct.duplicate(streams);
                    }
                })
            }
            return;
        }

        // The logic is that the common device is the CPU, all other devices
        // know how to transfer from and to CPU.

        // So we first transfer to CPU
        let cpu_ct = self.on_cpu();

        // Then we can transfer the desired device
        match target_device {
            Device::Cpu => {
                let _ = cpu_ct;
            }
            #[cfg(feature = "gpu")]
            Device::CudaGpu => {
                let new_inner = with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    CudaSquashedNoiseSignedRadixCiphertext::from_squashed_noise_signed_radix_ciphertext(&cpu_ct, streams)
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "hpu")]
            Device::Hpu => {
                panic!("HPU does not support noise squashing compression");
            }
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
#[versionize(SquashedNoiseFheIntVersions)]
pub struct SquashedNoiseFheInt {
    pub(in crate::high_level_api) inner: InnerSquashedNoiseSignedRadixCiphertext,
    pub(in crate::high_level_api) state: SquashedNoiseCiphertextState,
    tag: Tag,
}

impl Named for SquashedNoiseFheInt {
    const NAME: &'static str = "high_level_api::SquashedNoiseFheInt";
}

impl SquashedNoiseFheInt {
    pub(in crate::high_level_api) fn new(
        inner: InnerSquashedNoiseSignedRadixCiphertext,
        state: SquashedNoiseCiphertextState,
        tag: Tag,
    ) -> Self {
        Self { inner, state, tag }
    }

    pub fn underlying_squashed_noise_ciphertext(
        &self,
    ) -> MaybeCloned<'_, crate::integer::ciphertext::SquashedNoiseSignedRadixCiphertext> {
        self.inner.on_cpu()
    }

    pub fn num_bits(&self) -> usize {
        match &self.inner {
            InnerSquashedNoiseSignedRadixCiphertext::Cpu(on_cpu) => {
                on_cpu.original_block_count
                    * on_cpu.packed_blocks[0].message_modulus().0.ilog2() as usize
            }
            #[cfg(feature = "gpu")]
            InnerSquashedNoiseSignedRadixCiphertext::Cuda(gpu_ct) => {
                gpu_ct.ciphertext.original_block_count
                    * gpu_ct
                        .ciphertext
                        .info
                        .blocks
                        .first()
                        .unwrap()
                        .message_modulus
                        .0
                        .ilog2() as usize
            }
        }
    }
}

impl<Clear> FheDecrypt<Clear> for SquashedNoiseFheInt
where
    Clear: RecomposableFrom<u128> + SignExtendable,
{
    fn decrypt(&self, key: &ClientKey) -> Clear {
        let noise_squashing_private_key = key.private_noise_squashing_decryption_key(self.state);

        noise_squashing_private_key
            .decrypt_signed_radix(&self.inner.on_cpu())
            .unwrap()
    }
}

impl Tagged for SquashedNoiseFheInt {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl<Id: FheIntId> SquashNoise for FheInt<Id> {
    type Output = SquashedNoiseFheInt;

    fn squash_noise(&self) -> crate::Result<Self::Output> {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(server_key) => {
                let noise_squashing_key = server_key
                    .key
                    .noise_squashing_key
                    .as_ref()
                    .ok_or(UninitializedNoiseSquashing)?;

                Ok(SquashedNoiseFheInt {
                    inner: InnerSquashedNoiseSignedRadixCiphertext::Cpu(
                        noise_squashing_key.squash_signed_radix_ciphertext_noise(
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

                let cuda_squashed_ct = noise_squashing_key.squash_signed_radix_ciphertext_noise(
                    cuda_key.pbs_key(),
                    &self.ciphertext.on_gpu(streams),
                    streams,
                )?;

                let cpu_squashed_ct =
                    cuda_squashed_ct.to_squashed_noise_signed_radix_ciphertext(streams);
                Ok(SquashedNoiseFheInt {
                    inner: InnerSquashedNoiseSignedRadixCiphertext::Cpu(cpu_squashed_ct),
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
