#ifndef CUDA_INTEGER_CMUX_CUH
#define CUDA_INTEGER_CMUX_CUH

#include "integer.cuh"
#include "radix_ciphertext.cuh"

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
__host__ void legacy_host_integer_radix_cmux_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_condition,
    Torus const *lwe_array_true, Torus const *lwe_array_false,
    int_cmux_buffer<Torus> *mem_ptr, void *const *bsks, Torus *const *ksks,
    uint32_t num_radix_blocks) {

  auto params = mem_ptr->params;
  Torus lwe_size = params.big_lwe_dimension + 1;
  Torus radix_lwe_size = lwe_size * num_radix_blocks;
  cuda_memcpy_async_gpu_to_gpu(mem_ptr->buffer_in->ptr, lwe_array_true,
                               radix_lwe_size * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
  cuda_memcpy_async_gpu_to_gpu(
      (Torus *)(mem_ptr->buffer_in->ptr) + radix_lwe_size, lwe_array_false,
      radix_lwe_size * sizeof(Torus), streams[0], gpu_indexes[0]);
  for (uint i = 0; i < 2 * num_radix_blocks; i++) {
    cuda_memcpy_async_gpu_to_gpu(
        (Torus *)(mem_ptr->condition_array->ptr) + i * lwe_size, lwe_condition,
        lwe_size * sizeof(Torus), streams[0], gpu_indexes[0]);
  }
  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, (Torus *)(mem_ptr->buffer_out->ptr),
      (Torus *)(mem_ptr->buffer_in->ptr),
      (Torus *)(mem_ptr->condition_array->ptr), bsks, ksks,
      2 * num_radix_blocks, mem_ptr->predicate_lut, params.message_modulus);

  // If the condition was true, true_ct will have kept its value and false_ct
  // will be 0 If the condition was false, true_ct will be 0 and false_ct will
  // have kept its value
  auto mem_true = (Torus *)(mem_ptr->buffer_out->ptr);
  auto ptr = (Torus *)mem_ptr->buffer_out->ptr;
  auto mem_false = &ptr[radix_lwe_size];
  auto added_cts = mem_true;
  legacy_host_addition<Torus>(streams[0], gpu_indexes[0], added_cts, mem_true,
                              mem_false, params.big_lwe_dimension,
                              num_radix_blocks);

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, added_cts, bsks, ksks,
      num_radix_blocks, mem_ptr->message_extract_lut);
}

template <typename Torus>
__host__ void host_integer_radix_cmux_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_condition,
    CudaRadixCiphertextFFI const *lwe_array_true,
    CudaRadixCiphertextFFI const *lwe_array_false,
    int_cmux_buffer<Torus> *mem_ptr, void *const *bsks, Torus *const *ksks) {

  if (lwe_array_out->num_radix_blocks != lwe_array_true->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  if (lwe_array_out->num_radix_blocks != lwe_array_false->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")

  auto num_radix_blocks = lwe_array_out->num_radix_blocks;
  auto params = mem_ptr->params;
  Torus lwe_size = params.big_lwe_dimension + 1;
  copy_radix_ciphertext_to_larger_output_slice_async<Torus>(
      streams[0], gpu_indexes[0], mem_ptr->buffer_in, lwe_array_true, 0);
  copy_radix_ciphertext_to_larger_output_slice_async<Torus>(
      streams[0], gpu_indexes[0], mem_ptr->buffer_in, lwe_array_false,
      num_radix_blocks);
  for (uint i = 0; i < 2 * num_radix_blocks; i++) {
    cuda_memcpy_async_gpu_to_gpu(
        (Torus *)(mem_ptr->condition_array->ptr) + i * lwe_size,
        (Torus *)(lwe_condition->ptr), lwe_size * sizeof(Torus), streams[0],
        gpu_indexes[0]);
  }
  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, (Torus *)(mem_ptr->buffer_out->ptr),
      (Torus *)(mem_ptr->buffer_in->ptr),
      (Torus *)(mem_ptr->condition_array->ptr), bsks, ksks,
      2 * num_radix_blocks, mem_ptr->predicate_lut, params.message_modulus);

  // If the condition was true, true_ct will have kept its value and false_ct
  // will be 0 If the condition was false, true_ct will be 0 and false_ct will
  // have kept its value
  CudaRadixCiphertextFFI *mem_true = new CudaRadixCiphertextFFI;
  CudaRadixCiphertextFFI *mem_false = new CudaRadixCiphertextFFI;
  as_radix_ciphertext_slice<Torus>(mem_true, mem_ptr->buffer_out, 0,
                                   num_radix_blocks - 1);
  as_radix_ciphertext_slice<Torus>(mem_false, mem_ptr->buffer_out,
                                   num_radix_blocks, 2 * num_radix_blocks - 1);

  auto added_cts = mem_true;
  host_addition<Torus>(streams[0], gpu_indexes[0], added_cts, mem_true,
                       mem_false);

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, (Torus *)(lwe_array_out->ptr),
      (Torus *)(added_cts->ptr), bsks, ksks, num_radix_blocks,
      mem_ptr->message_extract_lut);
  delete mem_true;
  delete mem_false;
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
