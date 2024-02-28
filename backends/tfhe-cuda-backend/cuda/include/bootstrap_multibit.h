#ifndef CUDA_MULTI_BIT_H
#define CUDA_MULTI_BIT_H

#include <cstdint>
#include <string>

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

  uint32_t lwe_chunk_size;
  int num_producers;
  int max_pool_size = 2;

  pbs_multibit_buffer(cuda_stream_t *stream, uint32_t glwe_dimension,
                      uint32_t polynomial_size, uint32_t level_count,
                      uint32_t input_lwe_ciphertext_count,
                      bool allocate_gpu_memory) {

      lwe_chunk_size = std::stoi(std::getenv("LWECHUNKSIZE"));
      num_producers = std::stoi(std::getenv("NUMPRODUCERS"));
      printf("lwe_chunk_size: %d\n", lwe_chunk_size);
      printf("num_producers: %d\n", num_producers);

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
