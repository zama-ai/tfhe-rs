use crate::backward_compatibility::integers::SignedRadixCiphertextVersionedOwned;
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_cuda_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams_for_gpu_indexes;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
use crate::Device;
use serde::{Deserializer, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};
pub(crate) enum SignedRadixCiphertext {
    Cpu(crate::integer::SignedRadixCiphertext),
    #[cfg(feature = "gpu")]
    Cuda(CudaSignedRadixCiphertext),
}

impl From<crate::integer::SignedRadixCiphertext> for SignedRadixCiphertext {
    fn from(value: crate::integer::SignedRadixCiphertext) -> Self {
        Self::Cpu(value)
    }
}

#[cfg(feature = "gpu")]
impl From<CudaSignedRadixCiphertext> for SignedRadixCiphertext {
    fn from(value: CudaSignedRadixCiphertext) -> Self {
        Self::Cuda(value)
    }
}

impl Clone for SignedRadixCiphertext {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                with_thread_local_cuda_streams_for_gpu_indexes(inner.gpu_indexes(), |streams| {
                    let inner = inner.duplicate(streams);
                    Self::Cuda(inner)
                })
            }
        }
    }
}

impl serde::Serialize for SignedRadixCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.on_cpu().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SignedRadixCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut deserialized = Self::Cpu(crate::integer::SignedRadixCiphertext::deserialize(
            deserializer,
        )?);
        deserialized.move_to_device_of_server_key_if_set();
        Ok(deserialized)
    }
}

// Only CPU data are serialized so we only versionize the CPU type.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub(crate) struct SignedRadixCiphertextVersionOwned(
    <crate::integer::SignedRadixCiphertext as VersionizeOwned>::VersionedOwned,
);

impl Versionize for SignedRadixCiphertext {
    type Versioned<'vers> = SignedRadixCiphertextVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.into_owned().versionize_owned();
        SignedRadixCiphertextVersionedOwned::V0(SignedRadixCiphertextVersionOwned(versioned))
    }
}

impl VersionizeOwned for SignedRadixCiphertext {
    type VersionedOwned = SignedRadixCiphertextVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        SignedRadixCiphertextVersionedOwned::V0(SignedRadixCiphertextVersionOwned(
            cpu_data.into_owned().versionize_owned(),
        ))
    }
}

impl Unversionize for SignedRadixCiphertext {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            SignedRadixCiphertextVersionedOwned::V0(v0) => {
                let mut unversioned =
                    Self::Cpu(crate::integer::SignedRadixCiphertext::unversionize(v0.0)?);
                unversioned.move_to_device_of_server_key_if_set();
                Ok(unversioned)
            }
        }
    }
}

impl SignedRadixCiphertext {
    pub(crate) fn current_device(&self) -> Device {
        match self {
            Self::Cpu(_) => Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => Device::CudaGpu,
        }
    }

    /// Returns the a ref to the inner cpu ciphertext if self is on the CPU, otherwise, returns a
    /// copy that is on the CPU
    pub(crate) fn on_cpu(&self) -> MaybeCloned<'_, crate::integer::SignedRadixCiphertext> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_streams_for_gpu_indexes(ct.gpu_indexes(), |streams| {
                    let cpu_ct = ct.to_signed_radix_ciphertext(streams);
                    MaybeCloned::Cloned(cpu_ct)
                })
            }
        }
    }

    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    #[cfg(feature = "gpu")]
    pub(crate) fn on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> MaybeCloned<'_, CudaSignedRadixCiphertext> {
        match self {
            Self::Cpu(ct) => {
                let ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(ct, streams);
                MaybeCloned::Cloned(ct)
            }
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                if ct.gpu_indexes() == streams.gpu_indexes() {
                    MaybeCloned::Borrowed(ct)
                } else {
                    MaybeCloned::Cloned(ct.duplicate(streams))
                }
            }
        }
    }

    pub(crate) fn as_cpu_mut(&mut self) -> &mut crate::integer::SignedRadixCiphertext {
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
    pub(crate) fn as_gpu_mut(&mut self, streams: &CudaStreams) -> &mut CudaSignedRadixCiphertext {
        match self {
            Self::Cpu(cpu_ct) => {
                let cuda_ct =
                    CudaSignedRadixCiphertext::from_signed_radix_ciphertext(cpu_ct, streams);
                *self = Self::Cuda(cuda_ct);
                let Self::Cuda(cuda_ct) = self else {
                    unreachable!()
                };
                cuda_ct
            }
            Self::Cuda(cuda_ct) => {
                if cuda_ct.gpu_indexes() != streams.gpu_indexes() {
                    *cuda_ct = cuda_ct.duplicate(streams);
                }
                cuda_ct
            }
        }
    }

    pub(crate) fn into_cpu(self) -> crate::integer::SignedRadixCiphertext {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct,
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_streams_for_gpu_indexes(ct.gpu_indexes(), |streams| {
                    ct.to_signed_radix_ciphertext(streams)
                })
            }
        }
    }

    #[allow(unused)]
    #[cfg(feature = "gpu")]
    pub(crate) fn into_gpu(self, streams: &CudaStreams) -> CudaSignedRadixCiphertext {
        match self {
            Self::Cpu(cpu_ct) => {
                CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&cpu_ct, streams)
            }
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
                let new = with_cuda_internal_keys(|key| {
                    let streams = &key.streams;
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
                let new_inner = with_cuda_internal_keys(|key| {
                    let streams = &key.streams;
                    CudaSignedRadixCiphertext::from_signed_radix_ciphertext(ct, streams)
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(ct), Device::Cpu) => {
                let new_inner = with_cuda_internal_keys(|key| {
                    let streams = &key.streams;
                    ct.to_signed_radix_ciphertext(streams)
                });
                *self = Self::Cpu(new_inner);
            }
            #[cfg(feature = "hpu")]
            (_, Device::Hpu) => {
                panic!("Hpu device do not support signed integer yet",)
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
