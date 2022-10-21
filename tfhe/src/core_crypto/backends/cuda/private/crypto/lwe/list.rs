use crate::core_crypto::backends::cuda::private::device::{CudaStream, GpuIndex, NumberOfGpus};
use crate::core_crypto::backends::cuda::private::vec::CudaVec;
use crate::core_crypto::backends::cuda::private::{
    compute_number_of_samples_on_gpu, number_of_active_gpus,
};
use crate::core_crypto::commons::crypto::lwe::LweList;
use crate::core_crypto::commons::math::tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::prelude::{CiphertextCount, LweCiphertextCount, LweDimension};

/// An array of LWE ciphertexts in the GPU.
///
/// In the Cuda Engine, the logic is that vectors of LWE ciphertexts get
/// chunked and each chunk is sent to a given GPU.
/// The amount of ciphertexts per GPU is hard set to the total amount of
/// ciphertexts divided by the number of GPUs.
/// The aim is to make it easy for end users to handle multi-GPU calculations.
/// It is planned to expose an advanced CudaEngine that will make it possible
/// for end users to actually handle GPUs, streams and partitioning on their
/// own.
/// FIXME: the last GPU is less charged because it only takes the
///   remainder of the division of the total amount of input ciphertexts
///   by the number of GPUs. Originally, we were thinking of giving the
///   last GPU the same amount of ciphertexts as the others + the ciphertexts
///   that don't fit in case the remainder is not zero.

#[derive(Debug)]
pub(crate) struct CudaLweList<T: UnsignedInteger> {
    // Pointers to GPU data: one cuda vec per GPU
    pub(crate) d_vecs: Vec<CudaVec<T>>,
    // Number of ciphertexts in the array
    pub(crate) lwe_ciphertext_count: LweCiphertextCount,
    // Lwe dimension
    pub(crate) lwe_dimension: LweDimension,
}

pub(crate) unsafe fn copy_lwe_ciphertext_vector_from_cpu_to_gpu<T: UnsignedInteger, Cont>(
    streams: &[CudaStream],
    input: &LweList<Cont>,
    number_of_available_gpus: NumberOfGpus,
) -> Vec<CudaVec<T>>
where
    Cont: AsRefSlice<Element = T>,
{
    let input_slice = input.as_tensor().as_slice();
    // In case there are less inputs than GPUs, we use just one GPU per input
    let number_of_gpus = number_of_active_gpus(number_of_available_gpus, input.count());
    let mut vecs = Vec::with_capacity(number_of_gpus.0);
    let samples_on_gpu_0 =
        compute_number_of_samples_on_gpu(number_of_gpus, input.count(), GpuIndex(0));
    let data_per_gpu = samples_on_gpu_0.0 * input.lwe_size().0;
    for (gpu_index, chunk) in input_slice.chunks_exact(data_per_gpu).enumerate() {
        let stream = &streams[gpu_index];
        let samples =
            compute_number_of_samples_on_gpu(number_of_gpus, input.count(), GpuIndex(gpu_index));
        let alloc_size = samples.0 * input.lwe_size().0;
        if gpu_index == number_of_gpus.0 - 1 {
            let mut d_vec = stream.malloc::<T>(alloc_size as u32);
            let chunk_and_remainder =
                [chunk, input_slice.chunks_exact(data_per_gpu).remainder()].concat();
            stream.copy_to_gpu::<T>(&mut d_vec, chunk_and_remainder.as_slice());
            vecs.push(d_vec);
        } else {
            let mut d_vec = stream.malloc::<T>(alloc_size as u32);
            stream.copy_to_gpu::<T>(&mut d_vec, chunk);
            vecs.push(d_vec);
        }
    }
    vecs
}

pub(crate) unsafe fn copy_lwe_ciphertext_vector_from_gpu_to_cpu<T: UnsignedInteger>(
    streams: &[CudaStream],
    input: &CudaLweList<T>,
    number_of_available_gpus: NumberOfGpus,
) -> Vec<T> {
    let samples_per_gpu = compute_number_of_samples_on_gpu(
        number_of_available_gpus,
        CiphertextCount(input.lwe_ciphertext_count.0),
        GpuIndex(0),
    );
    let data_per_gpu = samples_per_gpu.0 * input.lwe_dimension.to_lwe_size().0;

    let mut output =
        vec![T::ZERO; input.lwe_dimension.to_lwe_size().0 * input.lwe_ciphertext_count.0];
    for (gpu_index, chunks) in output.chunks_exact_mut(data_per_gpu).enumerate() {
        let stream = &streams[gpu_index];
        stream.copy_to_cpu::<T>(chunks, input.d_vecs.get(gpu_index).unwrap());
    }
    if samples_per_gpu.0 * number_of_available_gpus.0 < input.lwe_ciphertext_count.0 {
        let last_chunk = output.chunks_exact_mut(data_per_gpu).into_remainder();
        let last_stream = streams.last().unwrap();
        last_stream.copy_to_cpu::<T>(last_chunk, input.d_vecs.last().unwrap());
    }
    output
}

pub(crate) unsafe fn discard_copy_lwe_ciphertext_vector_from_gpu_to_cpu<T: UnsignedInteger>(
    output: &mut LweList<&mut [T]>,
    streams: &[CudaStream],
    input: &CudaLweList<T>,
    number_of_available_gpus: NumberOfGpus,
) {
    let samples_per_gpu = compute_number_of_samples_on_gpu(
        number_of_available_gpus,
        CiphertextCount(input.lwe_ciphertext_count.0),
        GpuIndex(0),
    );
    let data_per_gpu = samples_per_gpu.0 * input.lwe_dimension.to_lwe_size().0;

    for (gpu_index, chunks) in output
        .as_mut_tensor()
        .as_mut_slice()
        .chunks_exact_mut(data_per_gpu)
        .enumerate()
    {
        let stream = &streams[gpu_index];
        stream.copy_to_cpu::<T>(chunks, input.d_vecs.get(gpu_index).unwrap());
    }
    if samples_per_gpu.0 * number_of_available_gpus.0 < input.lwe_ciphertext_count.0 {
        let last_chunk = output
            .as_mut_tensor()
            .as_mut_slice()
            .chunks_exact_mut(data_per_gpu)
            .into_remainder();
        let last_stream = streams.last().unwrap();
        last_stream.copy_to_cpu::<T>(last_chunk, input.d_vecs.last().unwrap());
    }
}
