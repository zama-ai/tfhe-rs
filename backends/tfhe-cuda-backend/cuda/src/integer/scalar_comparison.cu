#include "integer/scalar_comparison.cuh"

void cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, void const *scalar_blocks,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t num_scalar_blocks) {

  if (lwe_array_out->num_radix_blocks != lwe_array_in->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  auto num_radix_blocks = lwe_array_in->num_radix_blocks;
  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;
  switch (buffer->op) {
  case EQ:
  case NE:
    host_integer_radix_scalar_equality_check_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
        lwe_array_in, static_cast<const uint64_t *>(scalar_blocks), buffer,
        bsks, (uint64_t **)(ksks), num_radix_blocks, num_scalar_blocks);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
    if (lwe_array_in->num_radix_blocks % 2 != 0)
      PANIC("Cuda error (scalar comparisons): the number of radix blocks has "
            "to be even.")
    host_integer_radix_scalar_difference_check_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
        lwe_array_in, static_cast<const uint64_t *>(scalar_blocks), buffer,
        buffer->diff_buffer->operator_f, bsks, (uint64_t **)(ksks),
        num_radix_blocks, num_scalar_blocks);
    break;
  case MAX:
  case MIN:
    if (lwe_array_in->num_radix_blocks % 2 != 0)
      PANIC("Cuda error (scalar max/min): the number of radix blocks has to be "
            "even.")
    host_integer_radix_scalar_maxmin_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
        lwe_array_in, static_cast<const uint64_t *>(scalar_blocks), buffer,
        bsks, (uint64_t **)(ksks), num_radix_blocks, num_scalar_blocks);
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
}
