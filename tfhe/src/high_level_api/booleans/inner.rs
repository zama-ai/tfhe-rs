#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::backward_compatibility::booleans::SerializableInnerBooleanVersions;
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_cuda_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams_for_gpu_indexes;
use crate::integer::BooleanBlock;
use crate::Device;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[cfg(feature = "hpu")]
use crate::high_level_api::keys::HpuTaggedDevice;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
#[cfg(feature = "hpu")]
use crate::integer::hpu::ciphertext::HpuRadixCiphertext;

/// Enum that manages the current inner representation of a boolean.
#[derive(Serialize, Deserialize, Versionize)]
#[serde(from = "SerializableInnerBoolean", into = "SerializableInnerBoolean")]
#[versionize(convert = "SerializableInnerBoolean")]
pub(in crate::high_level_api) enum InnerBoolean {
    Cpu(BooleanBlock),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock),
    #[cfg(feature = "hpu")]
    Hpu(HpuRadixCiphertext),
}

impl Clone for InnerBoolean {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                with_thread_local_cuda_streams_for_gpu_indexes(inner.gpu_indexes(), |streams| {
                    Self::Cuda(inner.duplicate(streams))
                })
            }
            #[cfg(feature = "hpu")]
            Self::Hpu(inner) => Self::Hpu(inner.clone()),
        }
    }
}
/// Serialized form of [`InnerBoolean`], with the data always moved to the CPU
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableInnerBooleanVersions)]
pub(crate) struct SerializableInnerBoolean(BooleanBlock);

impl From<SerializableInnerBoolean> for InnerBoolean {
    fn from(value: SerializableInnerBoolean) -> Self {
        Self::Cpu(value.0)
    }
}

impl From<InnerBoolean> for SerializableInnerBoolean {
    fn from(value: InnerBoolean) -> Self {
        Self(value.into_cpu())
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
impl From<HpuRadixCiphertext> for InnerBoolean {
    fn from(value: HpuRadixCiphertext) -> Self {
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

    pub(crate) fn wait(&self) {
        match self {
            Self::Cpu(_) => {}
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => {}
            #[cfg(feature = "hpu")]
            Self::Hpu(ct) => ct.wait(),
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
    ) -> MaybeCloned<'_, CudaUnsignedRadixCiphertext> {
        let cpu_radix = if let Self::Cuda(gpu_radix) = self {
            if gpu_radix.gpu_indexes() == streams.gpu_indexes() {
                return MaybeCloned::Borrowed(&gpu_radix.0);
            }
            return MaybeCloned::Cloned(gpu_radix.duplicate(streams).0);
        } else {
            self.on_cpu()
        };

        let gpu_radix = CudaBooleanBlock::from_boolean_block(&cpu_radix, streams);
        MaybeCloned::Cloned(gpu_radix.0)
    }

    #[cfg(feature = "hpu")]
    pub(crate) fn on_hpu(&self, device: &HpuTaggedDevice) -> MaybeCloned<'_, HpuRadixCiphertext> {
        let cpu_radix = if let Self::Hpu(hpu_radix) = self {
            return MaybeCloned::Borrowed(hpu_radix);
        } else {
            self.on_cpu()
        };

        let hpu_ct = HpuRadixCiphertext::from_boolean_ciphertext(&cpu_radix, &device.device, None);
        MaybeCloned::Cloned(hpu_ct)
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
    pub(crate) fn as_gpu_mut(&mut self, streams: &CudaStreams) -> &mut CudaUnsignedRadixCiphertext {
        use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;

        let cpu_radix = if let Self::Cuda(cuda_ct) = self {
            if cuda_ct.gpu_indexes() != streams.gpu_indexes() {
                *cuda_ct = cuda_ct.duplicate(streams);
            }
            return &mut cuda_ct.0;
        } else {
            self.on_cpu()
        };

        let cuda_ct = CudaBooleanBlock::from_boolean_block(&cpu_radix, streams);
        *self = Self::Cuda(cuda_ct);
        let Self::Cuda(cuda_ct) = self else {
            unreachable!()
        };
        &mut cuda_ct.0
    }

    pub(crate) fn into_cpu(self) -> BooleanBlock {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct,
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_streams_for_gpu_indexes(ct.gpu_indexes(), |streams| {
                    ct.to_boolean_block(streams)
                })
            }
            #[cfg(feature = "hpu")]
            Self::Hpu(hpu_ct) => hpu_ct.to_boolean_block(),
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn into_gpu(self, streams: &CudaStreams) -> CudaBooleanBlock {
        let cpu_bool = if let Self::Cuda(gpu_bool) = self {
            return gpu_bool.move_to_stream(streams);
        } else {
            self.into_cpu()
        };
        CudaBooleanBlock::from_boolean_block(&cpu_bool, streams)
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
                    crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock::from_boolean_block(
                        &cpu_ct, streams,
                    )
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "hpu")]
            Device::Hpu => {
                let hpu_ct = global_state::with_thread_local_hpu_device(|device| {
                    HpuRadixCiphertext::from_boolean_ciphertext(&cpu_ct, &device.device, None)
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
