use crate::backward_compatibility::integers::UnsignedRadixCiphertextVersionedOwned;
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_cuda_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams_for_gpu_indexes;
#[cfg(feature = "hpu")]
use crate::high_level_api::keys::HpuTaggedDevice;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
#[cfg(feature = "hpu")]
use crate::integer::hpu::ciphertext::HpuRadixCiphertext;
use crate::Device;
use serde::{Deserializer, Serializer};
#[cfg(feature = "hpu")]
use tfhe_hpu_backend::prelude::*;
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

pub(crate) enum RadixCiphertext {
    Cpu(crate::integer::RadixCiphertext),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext),
    #[cfg(feature = "hpu")]
    Hpu(HpuRadixCiphertext),
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

#[cfg(feature = "hpu")]
impl From<HpuRadixCiphertext> for RadixCiphertext {
    fn from(value: HpuRadixCiphertext) -> Self {
        Self::Hpu(value)
    }
}

impl Clone for RadixCiphertext {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => with_cuda_internal_keys(|key| {
                let streams = &key.streams;
                Self::Cuda(inner.duplicate(streams))
            }),
            #[cfg(feature = "hpu")]
            Self::Hpu(inner) => {
                // NB: Hpu backends flavor behavs differently regarding memory.
                //  Some of them has duplicated memory on Host with sync mechanism.
                //  But it's not the case for all.
                // To prevent special cases, all the "deep" clone are made on HPU side
                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_MEMCPY;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let deep_clone =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(inner), &[])
                        .pop()
                        .expect("IOP_MEMCPY must return 1 operand");
                Self::Hpu(deep_clone)
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
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub(crate) struct RadixCiphertextVersionOwned(
    <crate::integer::RadixCiphertext as VersionizeOwned>::VersionedOwned,
);

impl Versionize for RadixCiphertext {
    type Versioned<'vers> = UnsignedRadixCiphertextVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.into_owned().versionize_owned();
        UnsignedRadixCiphertextVersionedOwned::V0(RadixCiphertextVersionOwned(versioned))
    }
}

impl VersionizeOwned for RadixCiphertext {
    type VersionedOwned = UnsignedRadixCiphertextVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        UnsignedRadixCiphertextVersionedOwned::V0(RadixCiphertextVersionOwned(
            cpu_data.into_owned().versionize_owned(),
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
    pub(crate) fn wait(&self) {
        match self {
            Self::Cpu(_) => {}
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => {}
            #[cfg(feature = "hpu")]
            Self::Hpu(hpu_ct) => hpu_ct.0.wait(),
        }
    }

    pub(crate) fn current_device(&self) -> Device {
        match self {
            Self::Cpu(_) => Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => Device::CudaGpu,
            #[cfg(feature = "hpu")]
            Self::Hpu(_) => Device::Hpu,
        }
    }

    /// Returns the a ref to the inner cpu ciphertext if self is on the CPU, otherwise, returns a
    /// copy that is on the CPU
    pub(crate) fn on_cpu(&self) -> MaybeCloned<'_, crate::integer::RadixCiphertext> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => with_thread_local_cuda_streams_for_gpu_indexes(
                ct.ciphertext.d_blocks.0.d_vec.gpu_indexes.as_slice(),
                |streams| {
                    let cpu_ct = ct.to_radix_ciphertext(streams);
                    MaybeCloned::Cloned(cpu_ct)
                },
            ),
            #[cfg(feature = "hpu")]
            Self::Hpu(hpu_ct) => {
                let cpu_inner = hpu_ct.to_radix_ciphertext();
                MaybeCloned::Cloned(cpu_inner)
            }
        }
    }

    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    #[cfg(feature = "gpu")]
    pub(crate) fn on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> MaybeCloned<'_, CudaUnsignedRadixCiphertext> {
        let cpu_radix = if let Self::Cuda(gpu_radix) = self {
            if gpu_radix.gpu_indexes() == streams.gpu_indexes() {
                return MaybeCloned::Borrowed(gpu_radix);
            }
            return MaybeCloned::Cloned(gpu_radix.duplicate(streams));
        } else {
            self.on_cpu()
        };

        let gpu_radix = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&cpu_radix, streams);
        MaybeCloned::Cloned(gpu_radix)
    }

    #[cfg(feature = "hpu")]
    pub(crate) fn on_hpu(&self, device: &HpuTaggedDevice) -> MaybeCloned<'_, HpuRadixCiphertext> {
        let cpu_radix = if let Self::Hpu(hpu_radix) = self {
            return MaybeCloned::Borrowed(hpu_radix);
        } else {
            self.on_cpu()
        };

        let hpu_ct = HpuRadixCiphertext::from_radix_ciphertext(&cpu_radix, &device.device);
        MaybeCloned::Cloned(hpu_ct)
    }

    pub(crate) fn as_cpu_mut(&mut self) -> &mut crate::integer::RadixCiphertext {
        match self {
            Self::Cpu(radix_ct) => radix_ct,
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => {
                self.move_to_device(Device::Cpu);
                self.as_cpu_mut()
            }
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn as_gpu_mut(&mut self, streams: &CudaStreams) -> &mut CudaUnsignedRadixCiphertext {
        let cpu_radix = if let Self::Cuda(cuda_ct) = self {
            if cuda_ct.gpu_indexes() != streams.gpu_indexes() {
                *cuda_ct = cuda_ct.duplicate(streams);
            }
            return cuda_ct;
        } else {
            self.on_cpu()
        };

        let cuda_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&cpu_radix, streams);
        *self = Self::Cuda(cuda_ct);
        let Self::Cuda(cuda_ct) = self else {
            unreachable!()
        };
        cuda_ct
    }

    #[cfg(feature = "hpu")]
    pub(crate) fn as_hpu_mut(&mut self, device: &HpuTaggedDevice) -> &mut HpuRadixCiphertext {
        if let Self::Hpu(radix_ct) = self {
            radix_ct
        } else {
            let cpu_ct = self.on_cpu();
            let hpu_ct = HpuRadixCiphertext::from_radix_ciphertext(&cpu_ct, &device.device);
            *self = Self::Hpu(hpu_ct);
            let Self::Hpu(hpu_ct) = self else {
                unreachable!()
            };
            hpu_ct
        }
    }

    pub(crate) fn into_cpu(self) -> crate::integer::RadixCiphertext {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct,
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_streams_for_gpu_indexes(ct.gpu_indexes(), |streams| {
                    ct.to_radix_ciphertext(streams)
                })
            }
            #[cfg(feature = "hpu")]
            Self::Hpu(hpu_ct) => hpu_ct.to_radix_ciphertext(),
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn into_gpu(self, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext {
        let cpu_radix = if let Self::Cuda(gpu_radix) = self {
            return gpu_radix.move_to_stream(streams);
        } else {
            self.into_cpu()
        };
        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&cpu_radix, streams)
    }

    #[cfg(feature = "hpu")]
    pub(crate) fn into_hpu(self, device: &HpuTaggedDevice) -> HpuRadixCiphertext {
        if let Self::Hpu(radix_ct) = self {
            radix_ct
        } else {
            let cpu_ct = self.on_cpu();
            HpuRadixCiphertext::from_radix_ciphertext(&cpu_ct, &device.device)
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn move_to_device(&mut self, target_device: Device) {
        let current_device = self.current_device();

        if current_device == target_device {
            #[cfg(feature = "gpu")]
            // We may not be on the correct Cuda device
            if let Self::Cuda(cuda_ct) = self {
                with_cuda_internal_keys(|key| {
                    let streams = &key.streams;
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
                let new_inner = with_cuda_internal_keys(|key| {
                    let streams = &key.streams;
                    crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                        &cpu_ct, streams,
                    )
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "hpu")]
            Device::Hpu => {
                let hpu_ct = global_state::with_thread_local_hpu_device(|device| {
                    HpuRadixCiphertext::from_radix_ciphertext(&cpu_ct, &device.device)
                });
                *self = Self::Hpu(hpu_ct);
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
