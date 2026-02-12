#pragma once

#include "checked_arithmetic.h"
#include "integer_utilities.h"
#include "keyswitch/ks_enums.h"
#include "zk/expand.cuh"
#include "zk/zk_utilities.h"

template <typename Torus> struct int_rerand_mem {
  int_radix_params params;

  Torus *tmp_zero_lwes;
  Torus *tmp_ksed_zero_lwes;
  Torus *lwe_trivial_indexes;
  uint32_t num_lwes;

  bool gpu_memory_allocated;

  std::vector<ks_mem<Torus> *>
      ks_tmp_buf_vec; // not allocated, ReRand not using GEMM KS for now
  // kept empty to pass to the KS function indicating GEMM KS disabled

  expand_job<Torus> *d_expand_jobs;
  expand_job<Torus> *h_expand_jobs;

  int_rerand_mem(CudaStreams streams, int_radix_params params,
                 const uint32_t num_lwes, const bool allocate_gpu_memory,
                 uint64_t &size_tracker)
      : params(params), num_lwes(num_lwes),
        gpu_memory_allocated(allocate_gpu_memory) {

    tmp_zero_lwes = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_lwes, params.big_lwe_dimension + 1),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);

    tmp_ksed_zero_lwes = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_lwes, params.small_lwe_dimension + 1),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);

    d_expand_jobs =
        static_cast<expand_job<Torus> *>(cuda_malloc_with_size_tracking_async(
            safe_mul_sizeof<expand_job<Torus>>(num_lwes), streams.stream(0),
            streams.gpu_index(0), size_tracker, allocate_gpu_memory));

    h_expand_jobs = static_cast<expand_job<Torus> *>(
        malloc(safe_mul_sizeof<expand_job<Torus>>(num_lwes)));

    auto h_lwe_trivial_indexes =
        static_cast<Torus *>(malloc(safe_mul_sizeof<Torus>(num_lwes)));
    for (auto i = 0; i < num_lwes; ++i) {
      h_lwe_trivial_indexes[i] = i;
    }
    lwe_trivial_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_lwes), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    cuda_memcpy_async_to_gpu(lwe_trivial_indexes, h_lwe_trivial_indexes,
                             safe_mul_sizeof<Torus>(num_lwes),
                             streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    free(h_lwe_trivial_indexes);
  }

  void release(CudaStreams streams) {
    cuda_drop_with_size_tracking_async(tmp_zero_lwes, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    tmp_zero_lwes = nullptr;
    cuda_drop_with_size_tracking_async(tmp_ksed_zero_lwes, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    tmp_ksed_zero_lwes = nullptr;
    cuda_drop_with_size_tracking_async(lwe_trivial_indexes, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    lwe_trivial_indexes = nullptr;
    cuda_drop_with_size_tracking_async(d_expand_jobs, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    d_expand_jobs = nullptr;

    for (auto i = 0; i < ks_tmp_buf_vec.size(); i++) {
      cleanup_cuda_keyswitch(streams.stream(i), streams.gpu_index(i),
                             ks_tmp_buf_vec[i], gpu_memory_allocated);
    }
    ks_tmp_buf_vec.clear();

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(h_expand_jobs);
    h_expand_jobs = nullptr;
  }
};
