#ifndef HELPER_MULTI_GPU_CUH
#define HELPER_MULTI_GPU_CUH

#include "helper_multi_gpu.h"

/// Initialize same-size arrays on all active gpus
template <typename Torus>
void multi_gpu_alloc_array_async(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count, std::vector<Torus *> &dest,
                                 uint32_t elements_per_gpu,
                                 uint64_t &size_tracker_on_gpu_0,
                                 bool allocate_gpu_memory) {

  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    uint64_t size_tracker_on_gpu_i = 0;
    Torus *d_array = (Torus *)cuda_malloc_with_size_tracking_async(
        elements_per_gpu * sizeof(Torus), streams[i], gpu_indexes[i],
        size_tracker_on_gpu_i, allocate_gpu_memory);
    dest[i] = d_array;
    if (i == 0) {
      size_tracker_on_gpu_0 += size_tracker_on_gpu_i;
    }
  }
}
/// Copy an array residing on one GPU to all active gpus
template <typename Torus>
void multi_gpu_copy_array_async(cudaStream_t const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                std::vector<Torus *> &dest, Torus const *src,
                                uint32_t elements_per_gpu,
                                bool gpu_memory_allocated) {
  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        dest[i], src, elements_per_gpu * sizeof(Torus), streams[i],
        gpu_indexes[i], gpu_memory_allocated);
  }
}
/// Allocates the input/output vector for all devices
/// Initializes also the related indexing and initializes it to the trivial
/// index
template <typename Torus>
void multi_gpu_alloc_lwe_async(cudaStream_t const *streams,
                               uint32_t const *gpu_indexes, uint32_t gpu_count,
                               std::vector<Torus *> &dest, uint32_t num_inputs,
                               uint32_t lwe_size,
                               uint64_t &size_tracker_on_gpu_0,
                               bool allocate_gpu_memory) {
  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    uint64_t size_tracker_on_gpu_i = 0;
    auto inputs_on_gpu = std::max(
        THRESHOLD_MULTI_GPU, get_num_inputs_on_gpu(num_inputs, i, gpu_count));
    Torus *d_array = (Torus *)cuda_malloc_with_size_tracking_async(
        inputs_on_gpu * lwe_size * sizeof(Torus), streams[i], gpu_indexes[i],
        size_tracker_on_gpu_i, allocate_gpu_memory);
    dest[i] = d_array;
    if (i == 0) {
      size_tracker_on_gpu_0 += size_tracker_on_gpu_i;
    }
  }
}

template void multi_gpu_alloc_lwe_async<__uint128_t>(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, std::vector<__uint128_t *> &dest, uint32_t num_inputs,
    uint32_t lwe_size, uint64_t &size_tracker_on_gpu_0,
    bool allocate_gpu_memory);

/// Allocates the input/output vector for all devices
/// Initializes also the related indexing and initializes it to the trivial
/// index
template <typename Torus>
void multi_gpu_alloc_lwe_many_lut_output_async(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, std::vector<Torus *> &dest, uint32_t num_inputs,
    uint32_t num_many_lut, uint32_t lwe_size, uint64_t &size_tracker_on_gpu_0,
    bool allocate_gpu_memory) {
  dest.resize(gpu_count);
  for (uint i = 0; i < gpu_count; i++) {
    uint64_t size_tracker = 0;
    auto inputs_on_gpu = std::max(
        THRESHOLD_MULTI_GPU, get_num_inputs_on_gpu(num_inputs, i, gpu_count));
    Torus *d_array = (Torus *)cuda_malloc_with_size_tracking_async(
        num_many_lut * inputs_on_gpu * lwe_size * sizeof(Torus), streams[i],
        gpu_indexes[i], size_tracker, allocate_gpu_memory);
    dest[i] = d_array;
    if (i == 0) {
      size_tracker_on_gpu_0 += size_tracker;
    }
  }
}

// Each block handles one lwe
template <typename Torus>
__global__ void pack_data(Torus *d_packed_vector, Torus const *d_vector,
                          Torus const *d_indexes, int lwe_size) {

  int output_offset = blockIdx.x * lwe_size;
  int input_offset = d_indexes[blockIdx.x] * lwe_size;
  for (int ind = threadIdx.x; ind < lwe_size; ind += blockDim.x) {
    d_packed_vector[ind + output_offset] = d_vector[ind + input_offset];
  }
}

// Each block handles one lwe
template <typename Torus>
__global__ void unpack_data(Torus *d_vector, Torus const *d_packed_vector,
                            Torus const *d_indexes, int lwe_size) {

  int input_offset = blockIdx.x * lwe_size;
  int output_offset = d_indexes[blockIdx.x] * lwe_size;
  for (int ind = threadIdx.x; ind < lwe_size; ind += blockDim.x) {
    d_vector[ind + output_offset] = d_packed_vector[ind + input_offset];
  }
}

/// Load an array residing on one GPU to all active gpus
/// and split the array among them.
/// The input indexing logic is given by an index array.
/// The output indexing is always the trivial one
/// num_inputs: total num of lwe in src
template <typename Torus>
void multi_gpu_scatter_lwe_async(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count, std::vector<Torus *> &dest,
                                 Torus const *src, Torus const *d_src_indexes,
                                 bool is_trivial_index,
                                 uint32_t max_active_gpu_count,
                                 uint32_t num_inputs, uint32_t lwe_size) {

  if (max_active_gpu_count < gpu_count)
    PANIC("Cuda error: number of gpus in scatter should be <= number of gpus "
          "used to create the lut")
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
      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          d_dest, d_src, inputs_on_gpu * lwe_size * sizeof(Torus), streams[i],
          gpu_indexes[i], true);

    } else {
      if (d_src_indexes == nullptr)
        PANIC("Cuda error: source indexes should be initialized!");
      Torus *d_packed_vector = (Torus *)cuda_malloc_async(
          inputs_on_gpu * lwe_size * sizeof(Torus), streams[0], gpu_indexes[0]);

      cudaEvent_t temp_event2 = cuda_create_event(gpu_indexes[0]);

      pack_data<Torus><<<inputs_on_gpu, 1024, 0, streams[0]>>>(
          d_packed_vector, (Torus *)src, (Torus *)d_src_indexes + gpu_offset,
          lwe_size);
      check_cuda_error(cudaGetLastError());
      cuda_event_record(temp_event2, streams[0], gpu_indexes[0]);
      cuda_stream_wait_event(streams[i], temp_event2, gpu_indexes[i]);

      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          dest[i], d_packed_vector, inputs_on_gpu * lwe_size * sizeof(Torus),
          streams[i], gpu_indexes[i], true);

      cudaEvent_t temp_event = cuda_create_event(gpu_indexes[i]);
      cuda_event_record(temp_event, streams[i], gpu_indexes[i]);
      cuda_stream_wait_event(streams[0], temp_event, gpu_indexes[0]);
      cuda_drop_async(d_packed_vector, streams[0], gpu_indexes[0]);
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
                                Torus *d_dest_indexes, bool is_trivial_index,
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

      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          d_dest, d_src, inputs_on_gpu * lwe_size * sizeof(Torus), streams[i],
          gpu_indexes[i], true);
    } else {
      if (d_dest_indexes == nullptr)
        PANIC("Cuda error: destination indexes should be initialized!");

      Torus *d_packed_vector = (Torus *)cuda_malloc_async(
          inputs_on_gpu * lwe_size * sizeof(Torus), streams[0], gpu_indexes[0]);
      cudaEvent_t temp_event2 = cuda_create_event(gpu_indexes[0]);

      cuda_event_record(temp_event2, streams[0], gpu_indexes[0]);
      cuda_stream_wait_event(streams[i], temp_event2, gpu_indexes[i]);

      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          d_packed_vector, src[i], inputs_on_gpu * lwe_size * sizeof(Torus),
          streams[i], gpu_indexes[i], true);
      cudaEvent_t temp_event3 = cuda_create_event(gpu_indexes[i]);

      cuda_event_record(temp_event3, streams[i], gpu_indexes[i]);
      cuda_stream_wait_event(streams[0], temp_event3, gpu_indexes[0]);

      unpack_data<Torus><<<inputs_on_gpu, 1024, 0, streams[0]>>>(
          dest, d_packed_vector, (Torus *)d_dest_indexes + gpu_offset,
          lwe_size);
      check_cuda_error(cudaGetLastError());

      cuda_drop_async(d_packed_vector, streams[0], gpu_indexes[0]);
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

        cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
            d_dest, d_src, inputs_on_gpu * lwe_size * sizeof(Torus), streams[i],
            gpu_indexes[i], true);
      } else {
        auto dest_indexes = h_dest_indexes + gpu_offset;

        for (uint j = 0; j < inputs_on_gpu; j++) {
          auto d_dest = dest + dest_indexes[j] * lwe_size +
                        lut_id * num_inputs * lwe_size;
          auto d_src =
              src[i] + j * lwe_size + lut_id * inputs_on_gpu * lwe_size;

          cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
              d_dest, d_src, lwe_size * sizeof(Torus), streams[i],
              gpu_indexes[i], true);
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
template void
multi_gpu_release_async<__uint128_t>(cudaStream_t const *streams,
                                     uint32_t const *gpu_indexes,
                                     std::vector<__uint128_t *> &vec);

#endif
