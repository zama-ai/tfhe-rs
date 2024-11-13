#ifndef CUDA_INTEGER_CMUX_CUH
#define CUDA_INTEGER_CMUX_CUH

#include "integer.cuh"

template <typename Torus>
__host__ void zero_out_if(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes, uint32_t gpu_count,
                          Torus *lwe_array_out, Torus const *lwe_array_input,
                          Torus const *lwe_condition,
                          int_zero_out_if_buffer<Torus> *mem_ptr,
                          int_radix_lut<Torus> *predicate, void *const *bsks,
                          Torus *const *ksks, uint32_t num_radix_blocks) {
  cudaSetDevice(gpu_indexes[0]);
  auto params = mem_ptr->params;

  // We can't use integer_radix_apply_bivariate_lookup_table_kb since the
  // second operand is not an array
  auto tmp_lwe_array_input = mem_ptr->tmp;
  pack_bivariate_blocks_with_single_block<Torus>(
      streams, gpu_indexes, gpu_count, tmp_lwe_array_input,
      predicate->lwe_indexes_in, lwe_array_input, lwe_condition,
      predicate->lwe_indexes_in, params.big_lwe_dimension,
      params.message_modulus, num_radix_blocks);

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, tmp_lwe_array_input, bsks,
      ksks, num_radix_blocks, predicate);
}

template <typename Torus>
__host__ void host_integer_radix_cmux_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_condition,
    Torus const *lwe_array_true, Torus const *lwe_array_false,
    int_cmux_buffer<Torus> *mem_ptr, void *const *bsks, Torus *const *ksks,
    uint32_t num_radix_blocks) {

  auto params = mem_ptr->params;

  // Since our CPU threads will be working on different streams we shall assert
  // the work in the main stream is completed
  auto true_streams = mem_ptr->zero_if_true_buffer->true_streams;
  auto false_streams = mem_ptr->zero_if_false_buffer->false_streams;
  for (uint j = 0; j < gpu_count; j++) {
    cuda_synchronize_stream(streams[j], gpu_indexes[j]);
  }

  auto mem_true = mem_ptr->zero_if_true_buffer;
  zero_out_if<Torus>(true_streams, gpu_indexes, gpu_count, mem_ptr->tmp_true_ct,
                     lwe_array_true, lwe_condition, mem_true,
                     mem_ptr->inverted_predicate_lut, bsks, ksks,
                     num_radix_blocks);
  auto mem_false = mem_ptr->zero_if_false_buffer;
  zero_out_if<Torus>(false_streams, gpu_indexes, gpu_count,
                     mem_ptr->tmp_false_ct, lwe_array_false, lwe_condition,
                     mem_false, mem_ptr->predicate_lut, bsks, ksks,
                     num_radix_blocks);
  for (uint j = 0; j < mem_ptr->zero_if_true_buffer->active_gpu_count; j++) {
    cuda_synchronize_stream(true_streams[j], gpu_indexes[j]);
  }
  for (uint j = 0; j < mem_ptr->zero_if_false_buffer->active_gpu_count; j++) {
    cuda_synchronize_stream(false_streams[j], gpu_indexes[j]);
  }

  // If the condition was true, true_ct will have kept its value and false_ct
  // will be 0 If the condition was false, true_ct will be 0 and false_ct will
  // have kept its value
  auto added_cts = mem_ptr->tmp_true_ct;
  host_addition<Torus>(streams[0], gpu_indexes[0], added_cts,
                       mem_ptr->tmp_true_ct, mem_ptr->tmp_false_ct,
                       params.big_lwe_dimension, num_radix_blocks);

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, added_cts, bsks, ksks,
      num_radix_blocks, mem_ptr->message_extract_lut);
}

template <typename Torus>
__host__ void scratch_cuda_integer_radix_cmux_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_cmux_buffer<Torus> **mem_ptr,
    std::function<Torus(Torus)> predicate_lut_f, uint32_t num_radix_blocks,
    int_radix_params params, bool allocate_gpu_memory) {

  *mem_ptr = new int_cmux_buffer<Torus>(streams, gpu_indexes, gpu_count,
                                        predicate_lut_f, params,
                                        num_radix_blocks, allocate_gpu_memory);
}
#endif
