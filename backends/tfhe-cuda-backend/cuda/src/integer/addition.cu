#include "integer/addition.cuh"

void scratch_cuda_signed_overflowing_add_or_sub_radix_ciphertext_kb_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, int8_t **mem_ptr,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, int8_t signed_operation,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  SIGNED_OPERATION op = (signed_operation == 1) ? SIGNED_OPERATION::ADDITION
                                                : SIGNED_OPERATION::SUBTRACTION;
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_integer_signed_overflowing_add_or_sub_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_signed_overflowing_add_or_sub_memory<uint64_t> **)mem_ptr,
      num_blocks, op, params, allocate_gpu_memory);
}

void cuda_signed_overflowing_add_or_sub_radix_ciphertext_kb_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, void *lhs,
    void *rhs, void *overflowed, int8_t signed_operation, int8_t *mem_ptr,
    void **bsks, void **ksks, uint32_t num_blocks) {

  auto mem = (int_signed_overflowing_add_or_sub_memory<uint64_t> *)mem_ptr;
  SIGNED_OPERATION op = (signed_operation == 1) ? SIGNED_OPERATION::ADDITION
                                                : SIGNED_OPERATION::SUBTRACTION;

  switch (mem->params.polynomial_size) {
  case 512:
    host_integer_signed_overflowing_add_or_sub_kb<uint64_t, Degree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(lhs), static_cast<uint64_t *>(rhs),
        static_cast<uint64_t *>(overflowed), op, bsks, (uint64_t **)(ksks), mem,
        num_blocks);
    break;
  case 1024:

    host_integer_signed_overflowing_add_or_sub_kb<uint64_t, Degree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(lhs), static_cast<uint64_t *>(rhs),
        static_cast<uint64_t *>(overflowed), op, bsks, (uint64_t **)(ksks), mem,
        num_blocks);
    break;
  case 2048:
    host_integer_signed_overflowing_add_or_sub_kb<uint64_t, Degree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(lhs), static_cast<uint64_t *>(rhs),
        static_cast<uint64_t *>(overflowed), op, bsks, (uint64_t **)(ksks), mem,
        num_blocks);
    break;
  case 4096:
    host_integer_signed_overflowing_add_or_sub_kb<uint64_t, Degree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(lhs), static_cast<uint64_t *>(rhs),
        static_cast<uint64_t *>(overflowed), op, bsks, (uint64_t **)(ksks), mem,
        num_blocks);
    break;
  case 8192:
    host_integer_signed_overflowing_add_or_sub_kb<uint64_t, Degree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(lhs), static_cast<uint64_t *>(rhs),
        static_cast<uint64_t *>(overflowed), op, bsks, (uint64_t **)(ksks), mem,
        num_blocks);
    break;
  case 16384:
    host_integer_signed_overflowing_add_or_sub_kb<uint64_t, Degree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(lhs), static_cast<uint64_t *>(rhs),
        static_cast<uint64_t *>(overflowed), op, bsks, (uint64_t **)(ksks), mem,
        num_blocks);
    break;
  default:
    PANIC("Cuda error (integer signed_overflowing_add_or_sub): unsupported "
          "polynomial size. "
          "Only N = 512, 1024, 2048, 4096, 8192, 16384 is supported")
  }
}

void cleanup_signed_overflowing_add_or_sub(void **streams,
                                           uint32_t *gpu_indexes,
                                           uint32_t gpu_count,
                                           int8_t **mem_ptr_void) {
  int_signed_overflowing_add_or_sub_memory<uint64_t> *mem_ptr =
      (int_signed_overflowing_add_or_sub_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
