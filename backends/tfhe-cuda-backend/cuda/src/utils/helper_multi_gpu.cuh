#ifndef HELPER_MULTI_GPU_CUH
#define HELPER_MULTI_GPU_CUH

#include "helper_multi_gpu.h"

/// Initialize same-size arrays on all active gpus
template <typename Torus>
void multi_gpu_alloc_array(cudaStream_t *streams, uint32_t *gpu_indexes,
                           uint32_t gpu_count, std::vector<Torus *> &dest,
                           uint32_t elements_per_gpu,
                           bool sync_threads = true) {

  dest.resize(gpu_count);
#pragma omp parallel for num_threads(gpu_count)
  for (uint i = 0; i < gpu_count; i++) {
    Torus *d_array = (Torus *)cuda_malloc_async(
        elements_per_gpu * sizeof(Torus), streams[i], gpu_indexes[i]);
    dest[i] = d_array;
  }

  if (sync_threads)
    for (uint i = 0; i < gpu_count; i++)
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
}
/// Copy an array residing on one GPU to all active gpus
template <typename Torus>
void multi_gpu_copy_array(cudaStream_t *streams, uint32_t *gpu_indexes,
                          uint32_t active_gpu_count, std::vector<Torus *> &dest,
                          Torus *src, uint32_t elements_per_gpu,
                          bool sync_threads = true) {

  if (sync_threads)
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

  dest.resize(active_gpu_count);
#pragma omp parallel for num_threads(active_gpu_count)
  for (uint i = 0; i < active_gpu_count; i++) {
    cuda_memcpy_async_gpu_to_gpu(dest[i], src, elements_per_gpu * sizeof(Torus),
                                 streams[i], gpu_indexes[i]);
  }

  if (sync_threads)
    for (uint i = 0; i < active_gpu_count; i++)
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
}
/// Allocates the input/output vector for all devices
/// Initializes also the related indexing and initializes it to the trivial
/// index
template <typename Torus>
void multi_gpu_alloc_lwe(cudaStream_t *streams, uint32_t *gpu_indexes,
                         uint32_t gpu_count, std::vector<Torus *> &dest,
                         uint32_t num_inputs, uint32_t elements_per_input,
                         bool sync_threads = true) {
  auto active_gpu_count = get_active_gpu_count(num_inputs, gpu_count);

  dest.resize(active_gpu_count);
#pragma omp parallel for num_threads(active_gpu_count)
  for (uint i = 0; i < active_gpu_count; i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, active_gpu_count);
    Torus *d_array = (Torus *)cuda_malloc_async(
        inputs_on_gpu * elements_per_input * sizeof(Torus), streams[i],
        gpu_indexes[i]);
    dest[i] = d_array;
  }

  if (sync_threads)
    for (uint i = 0; i < active_gpu_count; i++)
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
}
/// Load an array residing on one GPU to all active gpus
/// and split the array among them.
/// The input indexing logic is given by an index array.
/// The output indexing is always the trivial one
template <typename Torus>
void multi_gpu_scatter_lwe(cudaStream_t *streams, uint32_t *gpu_indexes,
                           uint32_t gpu_count, std::vector<Torus *> &dest,
                           Torus *src, Torus *h_src_indexes,
                           bool is_trivial_index, uint32_t num_inputs,
                           uint32_t elements_per_input,
                           bool sync_threads = true) {

  auto active_gpu_count = get_active_gpu_count(num_inputs, gpu_count);

  if (sync_threads)
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

  dest.resize(active_gpu_count);
#pragma omp parallel for num_threads(active_gpu_count)
  for (uint i = 0; i < active_gpu_count; i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, active_gpu_count);
    auto gpu_offset = 0;
    for (uint j = 0; j < i; j++) {
      gpu_offset += get_num_inputs_on_gpu(num_inputs, j, active_gpu_count);
    }

    if (is_trivial_index) {
      auto d_dest = dest[i];
      auto d_src = src + gpu_offset * elements_per_input;
      cuda_memcpy_async_gpu_to_gpu(
          d_dest, d_src, inputs_on_gpu * elements_per_input * sizeof(Torus),
          streams[i], gpu_indexes[i]);

    } else {
      auto src_indexes = h_src_indexes + gpu_offset;

      // TODO Check if we can increase parallelization by adding another omp
      // clause here
      for (uint j = 0; j < inputs_on_gpu; j++) {
        auto d_dest = dest[i] + j * elements_per_input;
        auto d_src = src + src_indexes[j] * elements_per_input;

        cuda_memcpy_async_gpu_to_gpu(d_dest, d_src,
                                     elements_per_input * sizeof(Torus),
                                     streams[i], gpu_indexes[i]);
      }
    }
  }

  if (sync_threads)
    for (uint i = 0; i < active_gpu_count; i++)
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
}

/// Copy data from multiple GPUs back to GPU 0 following the indexing given in
/// dest_indexes
/// The input indexing should be the trivial one
template <typename Torus>
void multi_gpu_gather_lwe(cudaStream_t *streams, uint32_t *gpu_indexes,
                          uint32_t gpu_count, Torus *dest,
                          const std::vector<Torus *> &src,
                          Torus *h_dest_indexes, bool is_trivial_index,
                          uint32_t num_inputs, uint32_t elements_per_input,
                          bool sync_threads = true) {

  auto active_gpu_count = get_active_gpu_count(num_inputs, gpu_count);

  if (sync_threads)
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

#pragma omp parallel for num_threads(active_gpu_count)
  for (uint i = 0; i < active_gpu_count; i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, active_gpu_count);
    auto gpu_offset = 0;
    for (uint j = 0; j < i; j++) {
      gpu_offset += get_num_inputs_on_gpu(num_inputs, j, active_gpu_count);
    }

    if (is_trivial_index) {
      auto d_dest = dest + gpu_offset * elements_per_input;
      auto d_src = src[i];

      cuda_memcpy_async_gpu_to_gpu(
          d_dest, d_src, inputs_on_gpu * elements_per_input * sizeof(Torus),
          streams[i], gpu_indexes[i]);
    } else {
      auto dest_indexes = h_dest_indexes + gpu_offset;

      // TODO Check if we can increase parallelization by adding another omp
      // clause here
      for (uint j = 0; j < inputs_on_gpu; j++) {
        auto d_dest = dest + dest_indexes[j] * elements_per_input;
        auto d_src = src[i] + j * elements_per_input;

        cuda_memcpy_async_gpu_to_gpu(d_dest, d_src,
                                     elements_per_input * sizeof(Torus),
                                     streams[i], gpu_indexes[i]);
      }
    }
  }

  if (sync_threads)
    for (uint i = 0; i < active_gpu_count; i++)
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
}
template <typename Torus>
void multi_gpu_release_lwe(cudaStream_t *streams, uint32_t *gpu_indexes,
                           std::vector<Torus *> &vec,
                           bool sync_threads = true) {

#pragma omp parallel for num_threads(vec.size())
  for (uint i = 0; i < vec.size(); i++) {
    cuda_drop_async(vec[i], streams[i], gpu_indexes[i]);
    if (sync_threads)
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
  }
  vec.clear();
}

#endif
