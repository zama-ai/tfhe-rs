use crate::core_crypto::gpu::{CudaDevice, CudaStream};
use crate::integer::gpu::CudaServerKey;
use crate::integer::{RadixClientKey, ServerKey};
use std::sync::Arc;

pub(crate) struct GpuContext {
    pub(crate) _device: CudaDevice,
    pub(crate) stream: CudaStream,
    pub(crate) sks: CudaServerKey,
}
pub(crate) struct GpuFunctionExecutor<F> {
    pub(crate) context: Option<GpuContext>,
    pub(crate) func: F,
}

impl<F> GpuFunctionExecutor<F> {
    pub(crate) fn new(func: F) -> Self {
        Self {
            context: None,
            func,
        }
    }
}

impl<F> GpuFunctionExecutor<F> {
    pub(crate) fn setup_from_keys(&mut self, cks: &RadixClientKey, _sks: &Arc<ServerKey>) {
        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        let sks = CudaServerKey::new(cks.as_ref(), &stream);
        stream.synchronize();
        let context = GpuContext {
            _device: device,
            stream,
            sks,
        };
        self.context = Some(context);
    }
}
