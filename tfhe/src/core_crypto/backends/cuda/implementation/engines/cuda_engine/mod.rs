use crate::core_crypto::backends::cuda::private::device::{CudaStream, GpuIndex, NumberOfGpus};
use crate::core_crypto::prelude::sealed::AbstractEngineSeal;
use crate::core_crypto::prelude::{AbstractEngine, CudaError, SharedMemoryAmount};
use concrete_cuda::cuda_bind::cuda_get_number_of_gpus;
/// The main engine exposed by the cuda backend.
///
/// This engine handles single-GPU and multi-GPU computations for the user. It always associates
/// one Cuda stream to each available Nvidia GPU, and splits the input ciphertexts evenly over
/// the GPUs (the last GPU may be a bit more loaded if the number of GPUs does not divide the
/// number of input ciphertexts). This engine does not give control over the streams, nor the GPU
/// load balancing. In this way, we can overlap computations done on different GPUs, but not
/// computations done on a given GPU, which are executed in a sequence.
// A finer access to streams could allow for more overlapping of computations
// on a given device. We'll probably want to support it in the future, in an AdvancedCudaEngine
// for example.
#[derive(Debug, Clone)]
pub struct CudaEngine {
    streams: Vec<CudaStream>,
    max_shared_memory: usize,
}

impl AbstractEngineSeal for CudaEngine {}

impl AbstractEngine for CudaEngine {
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

            Ok(CudaEngine {
                streams,
                max_shared_memory: max_shared_memory as usize,
            })
        }
    }
}

impl CudaEngine {
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
        if $poly_size.0 != 512 && $poly_size.0 != 1024 && $poly_size.0 != 2048 {
            return Err(CudaError::PolynomialSizeNotSupported.into());
        }
    };
}

mod glwe_ciphertext_conversion;
mod lwe_bootstrap_key_conversion;
mod lwe_ciphertext_conversion;
mod lwe_ciphertext_discarding_bootstrap;
mod lwe_ciphertext_discarding_conversion;
mod lwe_ciphertext_discarding_keyswitch;
mod lwe_keyswitch_key_conversion;

// mod ggsw_ciphertext_conversion;
// mod glwe_ciphertext_discarding_conversion;
// mod glwe_ciphertext_vector_conversion;
// mod glwe_ciphertext_vector_discarding_conversion;
// mod lwe_ciphertext_vector_conversion;
// mod lwe_ciphertext_vector_discarding_bootstrap;
// mod lwe_ciphertext_vector_discarding_conversion;
// mod lwe_ciphertext_vector_discarding_keyswitch;
