#include "integer/scalar_comparison.cuh"

#include <iostream>
#include <utility> // for std::pair

std::pair<bool, bool> get_invert_flags(COMPARISON_TYPE compare) {
  bool invert_operands;
  bool invert_subtraction_result;

  switch (compare) {
  case COMPARISON_TYPE::LT:
    invert_operands = false;
    invert_subtraction_result = false;
    break;
  case COMPARISON_TYPE::LE:
    invert_operands = true;
    invert_subtraction_result = true;
    break;
  case COMPARISON_TYPE::GT:
    invert_operands = true;
    invert_subtraction_result = false;
    break;
  case COMPARISON_TYPE::GE:
    invert_operands = false;
    invert_subtraction_result = true;
    break;
  default:
    PANIC("Cuda error: invalid comparison type")
  }

  return {invert_operands, invert_subtraction_result};
}

void cuda_integer_scalar_comparison_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI const *lwe_array_out_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_ffi, void const *scalar_blocks,
    void const *h_scalar_blocks, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_scalar_blocks) {
  CudaRadixCiphertext lwe_array_out_local(*lwe_array_out_ffi);
  const CudaRadixCiphertext *lwe_array_out = &lwe_array_out_local;
  const CudaRadixCiphertext lwe_array_in_local(*lwe_array_in_ffi);
  const CudaRadixCiphertext *lwe_array_in = &lwe_array_in_local;

  PANIC_IF_FALSE(lwe_array_out_ffi != lwe_array_in_ffi,
                 "Output and input pointers must be different for out-of-place "
                 "operations");

  // The output ciphertext might be a boolean block or a radix ciphertext
  // depending on the case (eq/gt vs max/min) so the amount of blocks to
  // consider for calculation is the one of the input
  auto num_radix_blocks = lwe_array_in->num_radix_blocks;
  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;
  switch (buffer->op) {
  case EQ:
  case NE:
    host_scalar_equality_check<uint64_t>(
        CudaStreams(streams), lwe_array_out, lwe_array_in,
        static_cast<const uint64_t *>(scalar_blocks), buffer, bsks,
        (uint64_t **)(ksks), num_radix_blocks, num_scalar_blocks);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
    if (num_radix_blocks % 2 != 0 && num_radix_blocks != 1)
      PANIC("Cuda error (scalar comparisons): the number of radix blocks has "
            "to be even or equal to 1.")
    host_scalar_difference_check<uint64_t>(
        CudaStreams(streams), lwe_array_out, lwe_array_in,
        static_cast<const uint64_t *>(scalar_blocks),
        static_cast<const uint64_t *>(h_scalar_blocks), buffer,
        buffer->diff_buffer->operator_f, bsks, (uint64_t **)(ksks),
        num_radix_blocks, num_scalar_blocks);
    break;
  case MAX:
  case MIN:
    if (lwe_array_in->num_radix_blocks % 2 != 0)
      PANIC("Cuda error (scalar max/min): the number of radix blocks has to be "
            "even.")
    host_scalar_maxmin<uint64_t>(
        CudaStreams(streams), lwe_array_out, lwe_array_in,
        static_cast<const uint64_t *>(scalar_blocks),
        static_cast<const uint64_t *>(h_scalar_blocks), buffer, bsks,
        (uint64_t **)(ksks), num_radix_blocks, num_scalar_blocks);
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
}
