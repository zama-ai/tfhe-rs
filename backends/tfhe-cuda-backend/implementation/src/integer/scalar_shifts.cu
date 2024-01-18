#include "scalar_shifts.cuh"

void scratch_cuda_integer_radix_scalar_shift_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_TYPE shift_type, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_integer_radix_scalar_shift_kb<uint64_t>(
      stream, (int_shift_buffer<uint64_t> **)mem_ptr, num_blocks, params,
      shift_type, allocate_gpu_memory);
}

void cuda_integer_radix_scalar_shift_kb_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint32_t shift, int8_t *mem_ptr,
    void *bsk, void *ksk, uint32_t num_blocks) {

  host_integer_radix_scalar_shift_kb_inplace<uint64_t>(
      stream, static_cast<uint64_t *>(lwe_array), shift,
      (int_shift_buffer<uint64_t> *)mem_ptr, bsk, static_cast<uint64_t *>(ksk),
      num_blocks);
}

void cleanup_cuda_integer_radix_scalar_shift(cuda_stream_t *stream,
                                             int8_t **mem_ptr_void) {

  int_shift_buffer<uint64_t> *mem_ptr =
      (int_shift_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(stream);
}
