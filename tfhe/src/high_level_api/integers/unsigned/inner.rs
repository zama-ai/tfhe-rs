use crate::backward_compatibility::integers::UnsignedRadixCiphertextVersionedOwned;
use crate::high_level_api::details::MaybeCloned;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::{self, with_thread_local_cuda_stream};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::Device;
use serde::{Deserializer, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize};

pub(crate) enum RadixCiphertext {
    Cpu(crate::integer::RadixCiphertext),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext),
}

impl From<crate::integer::RadixCiphertext> for RadixCiphertext {
    fn from(value: crate::integer::RadixCiphertext) -> Self {
        Self::Cpu(value)
    }
}

#[cfg(feature = "gpu")]
impl From<crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext> for RadixCiphertext {
    fn from(value: crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext) -> Self {
        Self::Cuda(value)
    }
}

impl Clone for RadixCiphertext {
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

impl serde::Serialize for RadixCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.on_cpu().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RadixCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut deserialized =
            Self::Cpu(crate::integer::RadixCiphertext::deserialize(deserializer)?);
        deserialized.move_to_device_of_server_key_if_set();
        Ok(deserialized)
    }
}

// Only CPU data are serialized so we only version the CPU type.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct RadixCiphertextVersionOwned(
    <crate::integer::RadixCiphertext as Versionize>::VersionedOwned,
);

impl Versionize for RadixCiphertext {
    type Versioned<'vers> = UnsignedRadixCiphertextVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.versionize_owned();
        UnsignedRadixCiphertextVersionedOwned::V0(RadixCiphertextVersionOwned(versioned))
    }

    type VersionedOwned = UnsignedRadixCiphertextVersionedOwned;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        UnsignedRadixCiphertextVersionedOwned::V0(RadixCiphertextVersionOwned(
            cpu_data.versionize_owned(),
        ))
    }
}

impl Unversionize for RadixCiphertext {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            UnsignedRadixCiphertextVersionedOwned::V0(v0) => {
                let mut unversioned =
                    Self::Cpu(crate::integer::RadixCiphertext::unversionize(v0.0)?);
                unversioned.move_to_device_of_server_key_if_set();
                Ok(unversioned)
            }
        }
    }
}

impl RadixCiphertext {
    pub(crate) fn current_device(&self) -> Device {
        match self {
            Self::Cpu(_) => Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => Device::CudaGpu,
        }
    }

    /// Returns the a ref to the inner cpu ciphertext if self is on the CPU, otherwise, returns a
    /// copy that is on the CPU
    pub(crate) fn on_cpu(&self) -> MaybeCloned<'_, crate::integer::RadixCiphertext> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => with_thread_local_cuda_stream(|stream| {
                let cpu_ct = ct.to_radix_ciphertext(stream);
                MaybeCloned::Cloned(cpu_ct)
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
                let ct =
                    crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                        ct, stream,
                    );
                MaybeCloned::Cloned(ct)
            }),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => MaybeCloned::Borrowed(ct),
        }
    }

    pub(crate) fn as_cpu_mut(&mut self) -> &mut crate::integer::RadixCiphertext {
        match self {
            Self::Cpu(radix_ct) => radix_ct,
            #[cfg(feature = "gpu")]
            _ => {
                self.move_to_device(Device::Cpu);
                self.as_cpu_mut()
            }
        }
    }

    #[cfg(feature = "gpu")]
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

    pub(crate) fn into_cpu(self) -> crate::integer::RadixCiphertext {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct,
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_stream(|stream| ct.to_radix_ciphertext(stream))
            }
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn into_gpu(self) -> crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext {
        match self {
            Self::Cpu(cpu_ct) => with_thread_local_cuda_stream(|stream| {
                crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(
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
                    crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                        ct, stream,
                    )
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(ct), Device::Cpu) => {
                let new_inner =
                    with_thread_local_cuda_stream(|stream| ct.to_radix_ciphertext(stream));
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
