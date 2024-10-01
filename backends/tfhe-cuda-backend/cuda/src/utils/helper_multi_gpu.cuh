#ifndef HELPER_MULTI_GPU_CUH
#define HELPER_MULTI_GPU_CUH

#include "helper_multi_gpu.h"

/// Initialize same-size arrays on all active gpus
template <typename Torus>
void multi_gpu_alloc_array_async(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count, std::vector<Torus *> &dest,
                                 uint32_t elements_per_gpu) {

  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    Torus *d_array = (Torus *)cuda_malloc_async(
        elements_per_gpu * sizeof(Torus), streams[i], gpu_indexes[i]);
    dest[i] = d_array;
  }
}
/// Copy an array residing on one GPU to all active gpus
template <typename Torus>
void multi_gpu_copy_array_async(cudaStream_t const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                std::vector<Torus *> &dest, Torus const *src,
                                uint32_t elements_per_gpu) {
  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    cuda_memcpy_async_gpu_to_gpu(dest[i], src, elements_per_gpu * sizeof(Torus),
                                 streams[i], gpu_indexes[i]);
  }
}
/// Allocates the input/output vector for all devices
/// Initializes also the related indexing and initializes it to the trivial
/// index
template <typename Torus>
void multi_gpu_alloc_lwe_async(cudaStream_t const *streams,
                               uint32_t const *gpu_indexes, uint32_t gpu_count,
                               std::vector<Torus *> &dest, uint32_t num_inputs,
                               uint32_t lwe_size) {
  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, gpu_count);
    Torus *d_array = (Torus *)cuda_malloc_async(
        inputs_on_gpu * lwe_size * sizeof(Torus), streams[i], gpu_indexes[i]);
    dest[i] = d_array;
  }
}

/// Allocates the input/output vector for all devices
/// Initializes also the related indexing and initializes it to the trivial
/// index
template <typename Torus>
void multi_gpu_alloc_lwe_many_lut_output_async(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, std::vector<Torus *> &dest, uint32_t num_inputs,
    uint32_t num_many_lut, uint32_t lwe_size) {
  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, gpu_count);
    Torus *d_array = (Torus *)cuda_malloc_async(num_many_lut * inputs_on_gpu *
                                                    lwe_size * sizeof(Torus),
                                                streams[i], gpu_indexes[i]);
    dest[i] = d_array;
  }
}

/// Load an array residing on one GPU to all active gpus
/// and split the array among them.
/// The input indexing logic is given by an index array.
/// The output indexing is always the trivial one
template <typename Torus>
void multi_gpu_scatter_lwe_async(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count, std::vector<Torus *> &dest,
                                 Torus const *src, Torus const *h_src_indexes,
                                 bool is_trivial_index, uint32_t num_inputs,
                                 uint32_t lwe_size) {

  cuda_synchronize_stream(streams[0], gpu_indexes[0]);
  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, gpu_count);
    auto gpu_offset = 0;
    for (uint j = 0; j < i; j++) {
      gpu_offset += get_num_inputs_on_gpu(num_inputs, j, gpu_count);
    }

    if (is_trivial_index) {
      auto d_dest = dest[i];
      auto d_src = src + gpu_offset * lwe_size;
      cuda_memcpy_async_gpu_to_gpu(d_dest, d_src,
                                   inputs_on_gpu * lwe_size * sizeof(Torus),
                                   streams[i], gpu_indexes[i]);

    } else {
      auto src_indexes = h_src_indexes + gpu_offset;

      for (uint j = 0; j < inputs_on_gpu; j++) {
        auto d_dest = dest[i] + j * lwe_size;
        auto d_src = src + src_indexes[j] * lwe_size;

        cuda_memcpy_async_gpu_to_gpu(d_dest, d_src, lwe_size * sizeof(Torus),
                                     streams[i], gpu_indexes[i]);
      }
    }
  }
}

/// Copy data from multiple GPUs back to GPU 0 following the indexing given in
/// dest_indexes
/// The input indexing should be the trivial one
template <typename Torus>
void multi_gpu_gather_lwe_async(cudaStream_t const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                Torus *dest, const std::vector<Torus *> &src,
                                Torus *h_dest_indexes, bool is_trivial_index,
                                uint32_t num_inputs, uint32_t lwe_size) {

  for (uint i = 0; i < gpu_count; i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, gpu_count);
    auto gpu_offset = 0;
    for (uint j = 0; j < i; j++) {
      gpu_offset += get_num_inputs_on_gpu(num_inputs, j, gpu_count);
    }

    if (is_trivial_index) {
      auto d_dest = dest + gpu_offset * lwe_size;
      auto d_src = src[i];

      cuda_memcpy_async_gpu_to_gpu(d_dest, d_src,
                                   inputs_on_gpu * lwe_size * sizeof(Torus),
                                   streams[i], gpu_indexes[i]);
    } else {
      auto dest_indexes = h_dest_indexes + gpu_offset;

      for (uint j = 0; j < inputs_on_gpu; j++) {
        auto d_dest = dest + dest_indexes[j] * lwe_size;
        auto d_src = src[i] + j * lwe_size;

        cuda_memcpy_async_gpu_to_gpu(d_dest, d_src, lwe_size * sizeof(Torus),
                                     streams[i], gpu_indexes[i]);
      }
    }
  }
}

/// Copy data from multiple GPUs back to GPU 0 following the indexing given in
/// dest_indexes
/// The input indexing should be the trivial one
template <typename Torus>
void multi_gpu_gather_many_lut_lwe_async(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *dest, const std::vector<Torus *> &src,
    Torus *h_dest_indexes, bool is_trivial_index, uint32_t num_inputs,
    uint32_t lwe_size, uint32_t num_many_lut) {

  for (uint lut_id = 0; lut_id < num_many_lut; lut_id++) {
    for (uint i = 0; i < gpu_count; i++) {
      auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, gpu_count);
      auto gpu_offset = 0;
      for (uint j = 0; j < i; j++) {
        gpu_offset += get_num_inputs_on_gpu(num_inputs, j, gpu_count);
      }

      if (is_trivial_index) {
        auto d_dest =
            dest + gpu_offset * lwe_size + lut_id * num_inputs * lwe_size;
        auto d_src = src[i] + lut_id * inputs_on_gpu * lwe_size;

        cuda_memcpy_async_gpu_to_gpu(d_dest, d_src,
                                     inputs_on_gpu * lwe_size * sizeof(Torus),
                                     streams[i], gpu_indexes[i]);
      } else {
        auto dest_indexes = h_dest_indexes + gpu_offset;

        for (uint j = 0; j < inputs_on_gpu; j++) {
          auto d_dest = dest + dest_indexes[j] * lwe_size +
                        lut_id * num_inputs * lwe_size;
          auto d_src =
              src[i] + j * lwe_size + lut_id * inputs_on_gpu * lwe_size;

          cuda_memcpy_async_gpu_to_gpu(d_dest, d_src, lwe_size * sizeof(Torus),
                                       streams[i], gpu_indexes[i]);
        }
      }
    }
  }
}

template <typename Torus>
void multi_gpu_release_async(cudaStream_t const *streams,
                             uint32_t const *gpu_indexes,
                             std::vector<Torus *> &vec) {

  for (uint i = 0; i < vec.size(); i++)
    cuda_drop_async(vec[i], streams[i], gpu_indexes[i]);
}

#endif
