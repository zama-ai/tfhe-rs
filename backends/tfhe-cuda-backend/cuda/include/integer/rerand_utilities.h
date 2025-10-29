#pragma once

#include "integer_utilities.h"
#include "keyswitch/ks_enums.h"
#include "zk/expand.cuh"
#include "zk/zk_utilities.h"

template <typename Torus> struct int_rerand_mem {
  int_radix_params params;
  Torus *lwe_trivial_indexes;

  Torus *tmp_zero_lwes;
  Torus *tmp_ksed_zero_lwes;
  uint32_t num_lwes;

  bool gpu_memory_allocated;

  expand_job<Torus> *d_expand_jobs;
  expand_job<Torus> *h_expand_jobs;

  int_rerand_mem(CudaStreams streams, int_radix_params params,
                 const uint32_t num_lwes, const bool allocate_gpu_memory,
                 uint64_t &size_tracker)
      : params(params), num_lwes(num_lwes),
        gpu_memory_allocated(allocate_gpu_memory) {

    tmp_zero_lwes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_lwes * (params.big_lwe_dimension + 1) * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);

    tmp_ksed_zero_lwes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_lwes * (params.small_lwe_dimension + 1) * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);

    d_expand_jobs =
        static_cast<expand_job<Torus> *>(cuda_malloc_with_size_tracking_async(
            num_lwes * sizeof(expand_job<Torus>), streams.stream(0),
            streams.gpu_index(0), size_tracker, allocate_gpu_memory));

    h_expand_jobs = static_cast<expand_job<Torus> *>(
        malloc(num_lwes * sizeof(expand_job<Torus>)));

    auto h_lwe_trivial_indexes =
        static_cast<Torus *>(malloc(num_lwes * sizeof(Torus)));
    for (auto i = 0; i < num_lwes; ++i) {
      h_lwe_trivial_indexes[i] = i;
    }
    lwe_trivial_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_lwes * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
        size_tracker, allocate_gpu_memory);
    cuda_memcpy_async_to_gpu(lwe_trivial_indexes, h_lwe_trivial_indexes,
                             num_lwes * sizeof(Torus), streams.stream(0),
                             streams.gpu_index(0));

    streams.synchronize();

    free(h_lwe_trivial_indexes);
  }

  void release(CudaStreams streams) {
    cuda_drop_with_size_tracking_async(tmp_zero_lwes, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(tmp_ksed_zero_lwes, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_expand_jobs, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(h_expand_jobs);
  }
};
