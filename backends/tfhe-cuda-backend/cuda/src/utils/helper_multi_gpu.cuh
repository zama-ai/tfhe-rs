#ifndef HELPER_MULTI_GPU_CUH
#define HELPER_MULTI_GPU_CUH

#include "checked_arithmetic.h"
#include "helper_multi_gpu.h"

/// Initialize same-size arrays on all active gpus
template <typename Torus>
void multi_gpu_alloc_array_async(CudaStreams streams,
                                 std::vector<Torus *> &dest,
                                 uint32_t elements_per_gpu,
                                 uint64_t &size_tracker_on_gpu_0,
                                 bool allocate_gpu_memory) {
  PANIC_IF_FALSE(dest.empty(),
                 "Cuda error: Requested multi-GPU vector is already allocated");
  dest.resize(streams.count());
  for (uint i = 0; i < streams.count(); i++) {
    uint64_t size_tracker_on_gpu_i = 0;
    Torus *d_array = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(elements_per_gpu), streams.stream(i),
        streams.gpu_index(i), size_tracker_on_gpu_i, allocate_gpu_memory);
    dest[i] = d_array;
    if (i == 0) {
      size_tracker_on_gpu_0 += size_tracker_on_gpu_i;
    }
  }
}
/// Copy an array residing on one GPU to all active gpus
template <typename Torus>
void multi_gpu_copy_array_async(CudaStreams streams,
                                const std::vector<Torus *> &dest,
                                Torus const *src, uint32_t elements_per_gpu,
                                bool gpu_memory_allocated) {
  PANIC_IF_FALSE(
      dest.size() >= streams.count(),
      "Cuda error: destination vector was not allocated for enough GPUs");
  for (uint i = 0; i < streams.count(); i++) {
    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        dest[i], src, safe_mul_sizeof<Torus>(elements_per_gpu),
        streams.stream(i), streams.gpu_index(i), gpu_memory_allocated);
  }
}
/// Copy an array residing on one CPU to all active gpus
template <typename Torus>
void multi_gpu_copy_array_from_cpu_async(CudaStreams streams,
                                         const std::vector<Torus *> &dest,
                                         Torus const *h_src,
                                         uint32_t elements_per_gpu,
                                         bool gpu_memory_allocated) {
  PANIC_IF_FALSE(dest.size() >= streams.count(),
                 "Cuda error: requested multi-gpu copy from CPU with "
                 "insufficient destination buffers");
  for (uint i = 0; i < streams.count(); i++) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        dest[i], h_src, safe_mul_sizeof<Torus>(elements_per_gpu),
        streams.stream(i), streams.gpu_index(i), gpu_memory_allocated);
  }
}
/// Allocates the input/output vector for all devices
/// Initializes also the related indexing and initializes it to the trivial
/// index
template <typename Torus>
void multi_gpu_alloc_lwe_async(CudaStreams streams, std::vector<Torus *> &dest,
                               uint32_t num_inputs, uint32_t lwe_size,
                               uint64_t &size_tracker_on_gpu_0,
                               PBS_TYPE pbs_type, bool allocate_gpu_memory) {
  PANIC_IF_FALSE(dest.empty(),
                 "Cuda error: Requested multi-GPU vector is already allocated");
  int classical_threshold = sizeof(Torus) == 16
                                ? THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128
                                : get_threshold_multi_gpu_classical();
  int threshold = (pbs_type == MULTI_BIT)
                      ? THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS
                      : classical_threshold;

  dest.resize(streams.count());
  for (uint i = 0; i < streams.count(); i++) {
    uint64_t size_tracker_on_gpu_i = 0;
    auto inputs_on_gpu = std::min(
        (int)num_inputs,
        std::max((int)threshold,
                 get_num_inputs_on_gpu(num_inputs, i, streams.count())));
    Torus *d_array = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>((size_t)inputs_on_gpu, (size_t)lwe_size),
        streams.stream(i), streams.gpu_index(i), size_tracker_on_gpu_i,
        allocate_gpu_memory);
    dest[i] = d_array;
    if (i == 0) {
      size_tracker_on_gpu_0 += size_tracker_on_gpu_i;
    }
  }
}

template void multi_gpu_alloc_lwe_async<__uint128_t>(
    CudaStreams streams, std::vector<__uint128_t *> &dest, uint32_t num_inputs,
    uint32_t lwe_size, uint64_t &size_tracker_on_gpu_0, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

/// Allocates the input/output vector for all devices
/// Initializes also the related indexing and initializes it to the trivial
/// index
template <typename Torus>
void multi_gpu_alloc_lwe_many_lut_output_async(
    CudaStreams streams, std::vector<Torus *> &dest, uint32_t num_inputs,
    uint32_t num_many_lut, uint32_t lwe_size, uint64_t &size_tracker_on_gpu_0,
    PBS_TYPE pbs_type, bool allocate_gpu_memory) {

  PANIC_IF_FALSE(dest.empty(),
                 "Cuda error: Requested multi-GPU vector is already allocated");
  int classical_threshold = sizeof(Torus) == 16
                                ? THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128
                                : get_threshold_multi_gpu_classical();
  int threshold = (pbs_type == MULTI_BIT)
                      ? THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS
                      : classical_threshold;

  dest.resize(streams.count());
  for (uint i = 0; i < streams.count(); i++) {
    uint64_t size_tracker = 0;
    auto inputs_on_gpu = std::min(
        (int)num_inputs,
        std::max((int)threshold,
                 get_num_inputs_on_gpu(num_inputs, i, streams.count())));
    Torus *d_array = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>((size_t)num_many_lut, (size_t)inputs_on_gpu,
                               (size_t)lwe_size),
        streams.stream(i), streams.gpu_index(i), size_tracker,
        allocate_gpu_memory);
    dest[i] = d_array;
    if (i == 0) {
      size_tracker_on_gpu_0 += size_tracker;
    }
  }
}

// This function reads lwes using the indexes and place them in a single aligned
// array. This function is needed before communication to perform a single
// contiguous data movement. Each block handles one lwe.
template <typename Torus>
__global__ void align_with_indexes(Torus *d_packed_vector,
                                   Torus const *d_vector,
                                   Torus const *d_indexes, int lwe_size) {

  int output_offset = blockIdx.x * lwe_size;
  int input_offset = d_indexes[blockIdx.x] * lwe_size;
  for (int ind = threadIdx.x; ind < lwe_size; ind += blockDim.x) {
    d_packed_vector[ind + output_offset] = d_vector[ind + input_offset];
  }
}

// This function takes the aligned array after communication and places it in
// the corresponding indexes. Each block handles one lwe.
template <typename Torus>
__global__ void realign_with_indexes(Torus *d_vector,
                                     Torus const *d_packed_vector,
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
void multi_gpu_scatter_lwe_async(
    CudaStreams streams, const std::vector<Torus *> &dest, Torus const *src,
    Torus const *d_src_indexes, bool is_trivial_index,
    std::vector<Torus *> &aligned_vec, CudaEventPool &event_pool,
    uint32_t max_active_gpu_count, uint32_t num_inputs, uint32_t lwe_size) {

  PANIC_IF_FALSE(
      max_active_gpu_count >= streams.count(),
      "Cuda error: number of gpus in scatter should be <= number of gpus "
      "used to create the lut");
  PANIC_IF_FALSE(dest.size() >= streams.count(),
                 "Cuda error: dest vector was not allocated for enough GPUs");
  for (uint i = 0; i < streams.count(); i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, streams.count());
    auto gpu_offset = 0;
    for (uint j = 0; j < i; j++) {
      gpu_offset += get_num_inputs_on_gpu(num_inputs, j, streams.count());
    }

    if (is_trivial_index) {
      auto d_dest = dest[i];
      auto d_src = src + gpu_offset * lwe_size;
      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          d_dest, d_src,
          safe_mul_sizeof<Torus>((size_t)inputs_on_gpu, (size_t)lwe_size),
          streams.stream(i), streams.gpu_index(i), true);

    } else {
      PANIC_IF_FALSE(aligned_vec.size() > 0,
                     "Cuda error: auxiliary arrays should be setup!");
      PANIC_IF_FALSE(
          aligned_vec.size() >= streams.count(),
          "Cuda error: aligned vec was not allocated for enough GPUs");

      if (d_src_indexes == nullptr)
        PANIC("Cuda error: source indexes should be initialized!");

      cudaEvent_t temp_event2 = event_pool.request_event(streams.gpu_index(0));
      cuda_set_device(streams.gpu_index(0));
      align_with_indexes<Torus><<<inputs_on_gpu, 1024, 0, streams.stream(0)>>>(
          aligned_vec[i], (Torus *)src, (Torus *)d_src_indexes + gpu_offset,
          lwe_size);
      check_cuda_error(cudaGetLastError());
      cuda_event_record(temp_event2, streams.stream(0), streams.gpu_index(0));
      cuda_stream_wait_event(streams.stream(i), temp_event2,
                             streams.gpu_index(i));

      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          dest[i], aligned_vec[i],
          safe_mul_sizeof<Torus>((size_t)inputs_on_gpu, (size_t)lwe_size),
          streams.stream(i), streams.gpu_index(i), true);

      cudaEvent_t temp_event = event_pool.request_event(streams.gpu_index(i));
      cuda_event_record(temp_event, streams.stream(i), streams.gpu_index(i));
      cuda_stream_wait_event(streams.stream(0), temp_event,
                             streams.gpu_index(0));
    }
  }
}

/// Copy data from multiple GPUs back to GPU 0 following the indexing given in
/// dest_indexes
/// The input indexing should be the trivial one
template <typename Torus>
void multi_gpu_gather_lwe_async(CudaStreams streams, Torus *dest,
                                const std::vector<Torus *> &src,
                                Torus *d_dest_indexes, bool is_trivial_index,
                                std::vector<Torus *> &aligned_vec,
                                CudaEventPool &event_pool, uint32_t num_inputs,
                                uint32_t lwe_size) {

  PANIC_IF_FALSE(src.size() >= streams.count(),
                 "Cuda error: src vector was not allocated for enough GPUs");
  for (uint i = 0; i < streams.count(); i++) {
    auto inputs_on_gpu = get_num_inputs_on_gpu(num_inputs, i, streams.count());
    auto gpu_offset = 0;
    for (uint j = 0; j < i; j++) {
      gpu_offset += get_num_inputs_on_gpu(num_inputs, j, streams.count());
    }

    if (is_trivial_index) {
      auto d_dest = dest + gpu_offset * lwe_size;
      auto d_src = src[i];

      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          d_dest, d_src,
          safe_mul_sizeof<Torus>((size_t)inputs_on_gpu, (size_t)lwe_size),
          streams.stream(i), streams.gpu_index(i), true);
    } else {
      PANIC_IF_FALSE(aligned_vec.size() > 0,
                     "Cuda error: auxiliary arrays should be setup!");
      PANIC_IF_FALSE(
          aligned_vec.size() >= streams.count(),
          "Cuda error: aligned vec was not allocated for enough GPUs");
      if (d_dest_indexes == nullptr)
        PANIC("Cuda error: destination indexes should be initialized!");

      cudaEvent_t temp_event2 = event_pool.request_event(streams.gpu_index(0));

      cuda_event_record(temp_event2, streams.stream(0), streams.gpu_index(0));
      cuda_stream_wait_event(streams.stream(i), temp_event2,
                             streams.gpu_index(i));

      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          aligned_vec[i], src[i],
          safe_mul_sizeof<Torus>((size_t)inputs_on_gpu, (size_t)lwe_size),
          streams.stream(i), streams.gpu_index(i), true);

      cudaEvent_t temp_event3 = event_pool.request_event(streams.gpu_index(i));
      cuda_event_record(temp_event3, streams.stream(i), streams.gpu_index(i));
      cuda_stream_wait_event(streams.stream(0), temp_event3,
                             streams.gpu_index(0));
      cuda_set_device(streams.gpu_index(0));
      realign_with_indexes<Torus>
          <<<inputs_on_gpu, 1024, 0, streams.stream(0)>>>(
              dest, aligned_vec[i], (Torus *)d_dest_indexes + gpu_offset,
              lwe_size);
      check_cuda_error(cudaGetLastError());
    }
  }
}

/// Copy data from multiple GPUs back to GPU 0 following the indexing given in
/// dest_indexes
/// The input indexing should be the trivial one
template <typename Torus>
void multi_gpu_gather_many_lut_lwe_async(CudaStreams streams, Torus *dest,
                                         const std::vector<Torus *> &src,
                                         Torus *h_dest_indexes,
                                         bool is_trivial_index,
                                         uint32_t num_inputs, uint32_t lwe_size,
                                         uint32_t num_many_lut) {

  PANIC_IF_FALSE(src.size() >= streams.count(),
                 "Cuda error: src vector was not allocated for enough GPUs");
  for (uint lut_id = 0; lut_id < num_many_lut; lut_id++) {
    for (uint i = 0; i < streams.count(); i++) {
      auto inputs_on_gpu =
          get_num_inputs_on_gpu(num_inputs, i, streams.count());
      auto gpu_offset = 0;
      for (uint j = 0; j < i; j++) {
        gpu_offset += get_num_inputs_on_gpu(num_inputs, j, streams.count());
      }

      if (is_trivial_index) {
        auto d_dest =
            dest + gpu_offset * lwe_size + lut_id * num_inputs * lwe_size;
        auto d_src = src[i] + lut_id * inputs_on_gpu * lwe_size;

        cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
            d_dest, d_src,
            safe_mul_sizeof<Torus>((size_t)inputs_on_gpu, (size_t)lwe_size),
            streams.stream(i), streams.gpu_index(i), true);
      } else {
        if (h_dest_indexes == nullptr)
          PANIC("Cuda error: destination indexes should be initialized!");
        auto dest_indexes = h_dest_indexes + gpu_offset;

        for (uint j = 0; j < inputs_on_gpu; j++) {
          auto d_dest = dest + dest_indexes[j] * lwe_size +
                        lut_id * num_inputs * lwe_size;
          auto d_src =
              src[i] + j * lwe_size + lut_id * inputs_on_gpu * lwe_size;

          cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
              d_dest, d_src, safe_mul_sizeof<Torus>((size_t)lwe_size),
              streams.stream(i), streams.gpu_index(i), true);
        }
      }
    }
  }
}

template <typename Torus>
void multi_gpu_release_async(CudaStreams streams, std::vector<Torus *> &vec) {

  PANIC_IF_FALSE(vec.size() >= streams.count(),
                 "Cuda error: vec was not allocated for enough GPUs");
  for (uint i = 0; i < vec.size(); i++)
    cuda_drop_async(vec[i], streams.stream(i), streams.gpu_index(i));
}
template void
multi_gpu_release_async<__uint128_t>(CudaStreams streams,
                                     std::vector<__uint128_t *> &vec);

#endif
