#ifndef CUDA_MULTI_BIT_H
#define CUDA_MULTI_BIT_H

#include <cstdint>

extern "C" {
void cuda_convert_lwe_multi_bit_bootstrap_key_64(
    void *dest, void *src, cuda_stream_t *stream, uint32_t input_lwe_dim,
    uint32_t glwe_dim, uint32_t level_count, uint32_t polynomial_size,
    uint32_t grouping_factor);

void cuda_multi_bit_pbs_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx);

void scratch_cuda_multi_bit_pbs_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory);

void cleanup_cuda_multi_bit_pbs(cuda_stream_t *stream, int8_t **pbs_buffer);
}

#ifdef __CUDACC__
__host__ uint64_t get_max_buffer_size_multibit_bootstrap(
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_input_lwe_ciphertext_count);
#endif

template <typename Torus> struct pbs_multibit_buffer {
  double2 *global_accumulator_fft;
  Torus *global_accumulator;

  std::vector<int> enabled_gpus;

  uint32_t lwe_chunk_size = 2;
  int num_producers;
  int max_pool_size = 2;

  pbs_multibit_buffer(cuda_stream_t *stream, uint32_t glwe_dimension,
                      uint32_t polynomial_size, uint32_t level_count,
                      uint32_t input_lwe_ciphertext_count,
                      bool allocate_gpu_memory) {

    enabled_gpus = cuda_get_p2p_enabled_gpus(stream->gpu_index);

    for (int peer_device : enabled_gpus)
      cuda_enable_p2p_access(peer_device, stream->gpu_index);

    // gpuIndex can access gpuIndex's memory, so we insert
    enabled_gpus.push_back(stream->gpu_index);

    num_producers = std::max((size_t)2, enabled_gpus.size());

    if (allocate_gpu_memory) {
      global_accumulator_fft = (double2 *)cuda_malloc_async(
          input_lwe_ciphertext_count * (glwe_dimension + 1) * level_count *
              (polynomial_size / 2) * sizeof(double2),
          stream);
      global_accumulator = (Torus *)cuda_malloc_async(
          input_lwe_ciphertext_count * (glwe_dimension + 1) * polynomial_size *
              sizeof(Torus),
          stream);
    }
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(global_accumulator_fft, stream);
    cuda_drop_async(global_accumulator, stream);
  }
};

#endif // CUDA_MULTI_BIT_H
