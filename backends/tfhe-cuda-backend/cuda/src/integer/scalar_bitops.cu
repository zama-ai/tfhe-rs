#include "integer/scalar_bitops.cuh"

void cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void *lwe_array_input, void *clear_blocks,
    uint32_t num_clear_blocks, int8_t *mem_ptr, void **bsks, void **ksks,
    uint32_t lwe_ciphertext_count, BITOP_TYPE op) {

  host_integer_radix_scalar_bitop_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<uint64_t *>(lwe_array_input),
      static_cast<uint64_t *>(clear_blocks), num_clear_blocks,
      (int_bitop_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks),
      lwe_ciphertext_count, op);
}
