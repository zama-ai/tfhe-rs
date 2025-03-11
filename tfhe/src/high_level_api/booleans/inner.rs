use crate::backward_compatibility::booleans::InnerBooleanVersionedOwned;
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::{
    with_thread_local_cuda_streams, with_thread_local_cuda_streams_for_gpu_indexes,
};
use crate::integer::BooleanBlock;
use crate::Device;
use serde::{Deserializer, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

/// Enum that manages the current inner representation of a boolean.
pub(in crate::high_level_api) enum InnerBoolean {
    Cpu(BooleanBlock),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock),
    #[cfg(feature = "hpu")]
    Hpu(crate::integer::hpu::ciphertext::HpuRadixCiphertext),
}

impl Clone for InnerBoolean {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                with_thread_local_cuda_streams(|streams| Self::Cuda(inner.duplicate(streams)))
            }
            #[cfg(feature = "hpu")]
            Self::Hpu(inner) => Self::Hpu(inner.clone()),
        }
    }
}
impl serde::Serialize for InnerBoolean {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct.serialize(serializer),
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => self.on_cpu().serialize(serializer),
            #[cfg(feature = "hpu")]
            Self::Hpu(_) => self.on_cpu().serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for InnerBoolean {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut deserialized = Self::Cpu(crate::integer::BooleanBlock::deserialize(deserializer)?);
        deserialized.move_to_device_of_server_key_if_set();
        Ok(deserialized)
    }
}

// Only CPU data are serialized so we only versionize the CPU type.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub(crate) struct InnerBooleanVersionOwned(
    <crate::integer::BooleanBlock as VersionizeOwned>::VersionedOwned,
);

impl Versionize for InnerBoolean {
    type Versioned<'vers> = InnerBooleanVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.into_owned().versionize_owned();
        InnerBooleanVersionedOwned::V0(InnerBooleanVersionOwned(versioned))
    }
}
impl VersionizeOwned for InnerBoolean {
    type VersionedOwned = InnerBooleanVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        InnerBooleanVersionedOwned::V0(InnerBooleanVersionOwned(
            cpu_data.into_owned().versionize_owned(),
        ))
    }
}

impl Unversionize for InnerBoolean {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            InnerBooleanVersionedOwned::V0(v0) => {
                let mut unversioned = Self::Cpu(crate::integer::BooleanBlock::unversionize(v0.0)?);
                unversioned.move_to_device_of_server_key_if_set();
                Ok(unversioned)
            }
        }
    }
}

impl From<BooleanBlock> for InnerBoolean {
    fn from(value: BooleanBlock) -> Self {
        Self::Cpu(value)
    }
}

#[cfg(feature = "gpu")]
impl From<crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock> for InnerBoolean {
    fn from(value: crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock) -> Self {
        Self::Cuda(value)
    }
}

#[cfg(feature = "hpu")]
impl From<crate::integer::hpu::ciphertext::HpuRadixCiphertext> for InnerBoolean {
    fn from(value: crate::integer::hpu::ciphertext::HpuRadixCiphertext) -> Self {
        Self::Hpu(value)
    }
}

impl InnerBoolean {
    pub(crate) fn current_device(&self) -> Device {
        match self {
            Self::Cpu(_) => Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => Device::CudaGpu,
            #[cfg(feature = "hpu")]
            Self::Hpu(_) => Device::Hpu,
        }
    }

    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    pub(crate) fn on_cpu(&self) -> MaybeCloned<'_, BooleanBlock> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_streams_for_gpu_indexes(ct.gpu_indexes(), |streams| {
                    MaybeCloned::Cloned(ct.to_boolean_block(streams))
                })
            }
            #[cfg(feature = "hpu")]
            Self::Hpu(ct) => MaybeCloned::Cloned(ct.to_boolean_block()),
        }
    }

    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    #[cfg(feature = "gpu")]
    pub(crate) fn on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> MaybeCloned<'_, crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext> {
        match self {
            Self::Cpu(ct) => with_thread_local_cuda_streams(|streams| {
                let ct_as_radix = crate::integer::RadixCiphertext::from(vec![ct.0.clone()]);
                let cuda_ct =
                    crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                        &ct_as_radix,
                        streams,
                    );
                MaybeCloned::Cloned(cuda_ct)
            }),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                if ct.gpu_indexes() == streams.gpu_indexes() {
                    MaybeCloned::Borrowed(ct.as_ref())
                } else {
                    MaybeCloned::Cloned(ct.duplicate(streams).0)
                }
            }
        }
    }

    pub(crate) fn as_cpu_mut(&mut self) -> &mut BooleanBlock {
        match self {
            Self::Cpu(block) => block,
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => {
                self.move_to_device(Device::Cpu);
                self.as_cpu_mut()
            }
        }
    }

    #[cfg(feature = "gpu")]
    #[track_caller]
    pub(crate) fn as_gpu_mut(
        &mut self,
        streams: &CudaStreams,
    ) -> &mut crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext {
        use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;

        match self {
            Self::Cpu(cpu_ct) => {
                let ct_as_radix = crate::integer::RadixCiphertext::from(vec![cpu_ct.0.clone()]);
                let cuda_ct = crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_as_radix, streams);
                let cuda_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(cuda_ct.ciphertext);
                *self = Self::Cuda(cuda_ct);
                let Self::Cuda(cuda_ct) = self else {
                    unreachable!()
                };
                &mut cuda_ct.0
            }
            Self::Cuda(cuda_ct) => {
                if cuda_ct.gpu_indexes() != streams.gpu_indexes() {
                    *cuda_ct = cuda_ct.duplicate(streams);
                }
                &mut cuda_ct.0
            }
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn into_gpu(
        self,
        streams: &CudaStreams,
    ) -> crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock {
        match self {
            Self::Cpu(cpu_ct) => with_thread_local_cuda_streams(|streams| {
                crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock::from_boolean_block(
                    &cpu_ct, streams,
                )
            }),
            Self::Cuda(ct) => ct.move_to_stream(streams),
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn move_to_device(&mut self, device: Device) {
        match (&self, device) {
            (Self::Cpu(_), Device::Cpu) => {
                // Nothing to do, we already are on the correct device
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(cuda_ct), Device::CudaGpu) => {
                // We are on a GPU, but it may not be the correct one
                let new = with_thread_local_cuda_streams(|streams| {
                    if cuda_ct.gpu_indexes() == streams.gpu_indexes() {
                        None
                    } else {
                        Some(cuda_ct.duplicate(streams))
                    }
                });
                if let Some(ct) = new {
                    *self = Self::Cuda(ct);
                }
            }
            #[cfg(feature = "gpu")]
            (Self::Cpu(ct), Device::CudaGpu) => {
                let new_inner = with_thread_local_cuda_streams(|streams| {
                    crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock::from_boolean_block(
                        ct,
                        streams,
                    )
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(ct), Device::Cpu) => {
                let new_inner =
                    with_thread_local_cuda_streams_for_gpu_indexes(ct.gpu_indexes(), |streams| {
                        ct.to_boolean_block(streams)
                    });
                *self = Self::Cpu(new_inner);
            }
            #[cfg(feature = "hpu")]
            _ => todo!(),
        }
    }

    #[inline]
    pub(crate) fn move_to_device_of_server_key_if_set(&mut self) {
        if let Some(device) = global_state::device_of_internal_keys() {
            self.move_to_device(device);
        }
    }
}
