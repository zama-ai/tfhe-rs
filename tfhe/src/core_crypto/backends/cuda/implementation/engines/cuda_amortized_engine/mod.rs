use crate::core_crypto::backends::cuda::engines::CudaError;
use crate::core_crypto::backends::cuda::private::device::{CudaStream, GpuIndex, NumberOfGpus};
use crate::core_crypto::prelude::sealed::AbstractEngineSeal;
use crate::core_crypto::prelude::{AbstractEngine, SharedMemoryAmount};
use concrete_cuda::cuda_bind::cuda_get_number_of_gpus;

/// A variant of CudaEngine exposed by the cuda backend.
///
/// This engine implements an amortized version of bootstrap on the GPU.
/// It is dedicated to the execution of bootstraps over larger amounts of
/// input ciphertexts than the CudaEngine's bootstrap implementation.
#[derive(Debug, Clone)]
pub struct AmortizedCudaEngine {
    streams: Vec<CudaStream>,
    max_shared_memory: usize,
}

impl AbstractEngineSeal for AmortizedCudaEngine {}

impl AbstractEngine for AmortizedCudaEngine {
    type EngineError = CudaError;

    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let number_of_gpus = unsafe { cuda_get_number_of_gpus() as usize };
        if number_of_gpus == 0 {
            Err(CudaError::DeviceNotFound)
        } else {
            let mut streams: Vec<CudaStream> = Vec::new();
            for gpu_index in 0..number_of_gpus {
                streams.push(CudaStream::new(GpuIndex(gpu_index))?);
            }
            let max_shared_memory = streams[0].get_max_shared_memory()?;

            Ok(AmortizedCudaEngine {
                streams,
                max_shared_memory: max_shared_memory as usize,
            })
        }
    }
}

impl AmortizedCudaEngine {
    /// Get the number of available GPUs from the engine
    pub fn get_number_of_gpus(&self) -> NumberOfGpus {
        NumberOfGpus(self.streams.len())
    }
    /// Get the Cuda streams from the engine
    pub fn get_cuda_streams(&self) -> &Vec<CudaStream> {
        &self.streams
    }
    /// Get the size of the shared memory (on device 0)
    pub fn get_cuda_shared_memory(&self) -> SharedMemoryAmount {
        SharedMemoryAmount(self.max_shared_memory)
    }
}

macro_rules! check_poly_size {
    ($poly_size: ident) => {
        if $poly_size != 512
            && $poly_size != 1024
            && $poly_size != 2048
            && $poly_size != 4096
            && $poly_size != 8192
        {
            return Err(CudaError::PolynomialSizeNotSupported.into());
        }
    };
}

// mod lwe_ciphertext_vector_discarding_bootstrap;
