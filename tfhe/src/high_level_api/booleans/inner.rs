use crate::high_level_api::details::MaybeCloned;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::{self, with_thread_local_cuda_stream};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::BooleanBlock;
use crate::Device;
use serde::{Deserializer, Serializer};

/// Enum that manages the current inner representation of a boolean.
pub(in crate::high_level_api) enum InnerBoolean {
    Cpu(BooleanBlock),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext),
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

impl From<BooleanBlock> for InnerBoolean {
    fn from(value: BooleanBlock) -> Self {
        Self::Cpu(value)
    }
}

#[cfg(feature = "gpu")]
impl From<crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext> for InnerBoolean {
    fn from(value: crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext) -> Self {
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
                let cpu_ct = ct.to_radix_ciphertext(stream);
                MaybeCloned::Cloned(BooleanBlock::new_unchecked(cpu_ct.blocks[0].clone()))
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
            Self::Cuda(ct) => MaybeCloned::Borrowed(ct),
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
            radix_ct
        } else {
            self.move_to_device(Device::CudaGpu);
            self.as_gpu_mut()
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
                let ct_as_radix = crate::integer::RadixCiphertext::from(vec![ct.0.clone()]);
                let new_inner = with_thread_local_cuda_stream(|stream| {
                    crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                        &ct_as_radix,
                        stream,
                    )
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(ct), Device::Cpu) => {
                let new_inner =
                    with_thread_local_cuda_stream(|stream| ct.to_radix_ciphertext(stream));
                *self = Self::Cpu(BooleanBlock::new_unchecked(new_inner.blocks[0].clone()));
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
