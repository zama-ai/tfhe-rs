#include "integer/negation.cuh"

void cuda_negate_integer_radix_ciphertext_64_inplace(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, void *lwe_array,
    uint32_t lwe_dimension, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus) {

  host_integer_radix_negation(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array), static_cast<uint64_t *>(lwe_array),
      lwe_dimension, lwe_ciphertext_count, message_modulus, carry_modulus);
}

void scratch_cuda_integer_radix_overflowing_sub_kb_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, int8_t **mem_ptr,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_integer_overflowing_sub_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_overflowing_sub_memory<uint64_t> **)mem_ptr, num_blocks, params,
      allocate_gpu_memory);
}

void cuda_integer_radix_overflowing_sub_kb_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count,
    void *radix_lwe_out, void *radix_lwe_overflowed, void *radix_lwe_left,
    void *radix_lwe_right, int8_t *mem_ptr, void **bsks, void **ksks,
    uint32_t num_blocks) {

  auto mem = (int_overflowing_sub_memory<uint64_t> *)mem_ptr;

  switch (mem->params.polynomial_size) {
  case 512:
    host_integer_overflowing_sub_kb<uint64_t, AmortizedDegree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_overflowed),
        static_cast<uint64_t *>(radix_lwe_left),
        static_cast<uint64_t *>(radix_lwe_right), bsks, (uint64_t **)(ksks),
        mem, num_blocks);
    break;
  case 1024:
    host_integer_overflowing_sub_kb<uint64_t, AmortizedDegree<1024>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_overflowed),
        static_cast<uint64_t *>(radix_lwe_left),
        static_cast<uint64_t *>(radix_lwe_right), bsks, (uint64_t **)(ksks),
        mem, num_blocks);
    break;
  case 2048:
    host_integer_overflowing_sub_kb<uint64_t, AmortizedDegree<2048>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_overflowed),
        static_cast<uint64_t *>(radix_lwe_left),
        static_cast<uint64_t *>(radix_lwe_right), bsks, (uint64_t **)(ksks),
        mem, num_blocks);
    break;
  case 4096:
    host_integer_overflowing_sub_kb<uint64_t, AmortizedDegree<4096>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_overflowed),
        static_cast<uint64_t *>(radix_lwe_left),
        static_cast<uint64_t *>(radix_lwe_right), bsks, (uint64_t **)(ksks),
        mem, num_blocks);
    break;
  case 8192:
    host_integer_overflowing_sub_kb<uint64_t, AmortizedDegree<8192>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_overflowed),
        static_cast<uint64_t *>(radix_lwe_left),
        static_cast<uint64_t *>(radix_lwe_right), bsks, (uint64_t **)(ksks),
        mem, num_blocks);
    break;
  case 16384:
    host_integer_overflowing_sub_kb<uint64_t, AmortizedDegree<16384>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_overflowed),
        static_cast<uint64_t *>(radix_lwe_left),
        static_cast<uint64_t *>(radix_lwe_right), bsks, (uint64_t **)(ksks),
        mem, num_blocks);
    break;
  default:
    PANIC("Cuda error (integer overflowing sub): unsupported polynomial size. "
          "Only N = 512, 1024, 2048, 4096, 8192, 16384 is supported")
  }
}

void cleanup_cuda_integer_radix_overflowing_sub(void **streams,
                                                uint32_t *gpu_indexes,
                                                uint32_t gpu_count,
                                                int8_t **mem_ptr_void) {
  int_overflowing_sub_memory<uint64_t> *mem_ptr =
      (int_overflowing_sub_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
