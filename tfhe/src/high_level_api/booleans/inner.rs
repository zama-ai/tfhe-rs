use crate::backward_compatibility::booleans::InnerBooleanVersionedOwned;
use crate::high_level_api::details::MaybeCloned;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::{self, with_thread_local_cuda_stream};
use crate::integer::BooleanBlock;
use crate::Device;
use serde::{Deserializer, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize};

/// Enum that manages the current inner representation of a boolean.
pub(in crate::high_level_api) enum InnerBoolean {
    Cpu(BooleanBlock),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock),
}

impl Clone for InnerBoolean {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                with_thread_local_cuda_stream(|stream| Self::Cuda(inner.duplicate(stream)))
            }
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
pub(crate) struct InnerBooleanVersionOwned(
    <crate::integer::BooleanBlock as Versionize>::VersionedOwned,
);

impl Versionize for InnerBoolean {
    type Versioned<'vers> = InnerBooleanVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.versionize_owned();
        InnerBooleanVersionedOwned::V0(InnerBooleanVersionOwned(versioned))
    }

    type VersionedOwned = InnerBooleanVersionedOwned;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        InnerBooleanVersionedOwned::V0(InnerBooleanVersionOwned(cpu_data.versionize_owned()))
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

impl InnerBoolean {
    pub(crate) fn current_device(&self) -> Device {
        match self {
            Self::Cpu(_) => Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => Device::CudaGpu,
        }
    }

    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    pub(crate) fn on_cpu(&self) -> MaybeCloned<'_, BooleanBlock> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => with_thread_local_cuda_stream(|stream| {
                MaybeCloned::Cloned(ct.to_boolean_block(stream))
            }),
        }
    }

    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    #[cfg(feature = "gpu")]
    pub(crate) fn on_gpu(
        &self,
    ) -> MaybeCloned<'_, crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext> {
        match self {
            Self::Cpu(ct) => with_thread_local_cuda_stream(|stream| {
                let ct_as_radix = crate::integer::RadixCiphertext::from(vec![ct.0.clone()]);
                let cuda_ct =
                    crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                        &ct_as_radix,
                        stream,
                    );
                MaybeCloned::Cloned(cuda_ct)
            }),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => MaybeCloned::Borrowed(ct.as_ref()),
        }
    }

    pub(crate) fn as_cpu_mut(&mut self) -> &mut BooleanBlock {
        match self {
            Self::Cpu(block) => block,
            #[cfg(feature = "gpu")]
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
    ) -> &mut crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext {
        if let Self::Cuda(radix_ct) = self {
            radix_ct.as_mut()
        } else {
            self.move_to_device(Device::CudaGpu);
            self.as_gpu_mut()
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn into_gpu(
        self,
    ) -> crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock {
        match self {
            Self::Cpu(cpu_ct) => with_thread_local_cuda_stream(|stream| {
                crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock::from_boolean_block(
                    &cpu_ct, stream,
                )
            }),
            Self::Cuda(ct) => ct,
        }
    }

    pub(crate) fn move_to_device(&mut self, device: Device) {
        match (&self, device) {
            (Self::Cpu(_), Device::Cpu) => {
                // Nothing to do, we already are on the correct device
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(_), Device::CudaGpu) => {
                // Nothing to do, we already are on the correct device
            }
            #[cfg(feature = "gpu")]
            (Self::Cpu(ct), Device::CudaGpu) => {
                let new_inner = with_thread_local_cuda_stream(|stream| {
                    crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock::from_boolean_block(
                        ct,
                        stream,
                    )
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(ct), Device::Cpu) => {
                let new_inner = with_thread_local_cuda_stream(|stream| ct.to_boolean_block(stream));
                *self = Self::Cpu(new_inner);
            }
        }
    }

    #[inline]
    #[allow(clippy::unused_self)]
    pub(crate) fn move_to_device_of_server_key_if_set(&mut self) {
        #[cfg(feature = "gpu")]
        if let Some(device) = global_state::device_of_internal_keys() {
            self.move_to_device(device);
        }
    }
}
