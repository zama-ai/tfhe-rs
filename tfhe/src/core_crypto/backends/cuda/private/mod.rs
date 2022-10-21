use crate::core_crypto::backends::cuda::private::device::{
    GpuIndex, NumberOfGpus, NumberOfSamples,
};
use crate::core_crypto::prelude::CiphertextCount;
use std::cmp::min;

pub mod crypto;
pub mod device;
pub mod pointers;
pub mod vec;
pub mod wopbs;

pub(crate) fn number_of_active_gpus(
    total_number_of_gpus: NumberOfGpus,
    lwe_ciphertext_count: CiphertextCount,
) -> NumberOfGpus {
    let mut n = total_number_of_gpus.0;
    // In case there are more GPUs than inputs, use only as many GPUs as there are inputs
    if lwe_ciphertext_count.0 < n {
        n = min(lwe_ciphertext_count.0, total_number_of_gpus.0)
    }
    NumberOfGpus(n)
}

pub(crate) fn compute_number_of_samples_on_gpu(
    number_of_gpus: NumberOfGpus,
    lwe_ciphertext_count: CiphertextCount,
    gpu_index: GpuIndex,
) -> NumberOfSamples {
    let samples_per_gpu = lwe_ciphertext_count.0 / number_of_gpus.0;
    let mut samples = samples_per_gpu;
    // We add the remainder of the integer division lwe_count/num_gpus to the load of the last GPU
    if gpu_index.0 == number_of_gpus.0 - 1 {
        samples += lwe_ciphertext_count.0 % number_of_gpus.0;
    }
    NumberOfSamples(samples)
}
