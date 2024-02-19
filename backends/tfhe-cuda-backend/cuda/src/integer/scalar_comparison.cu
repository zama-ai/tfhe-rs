#include "integer/scalar_comparison.cuh"

void cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *scalar_blocks, int8_t *mem_ptr, void *bsk, void *ksk,
    uint32_t lwe_ciphertext_count, uint32_t num_scalar_blocks) {

  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;
  switch (buffer->op) {
  case EQ:
  case NE:
    host_integer_radix_scalar_equality_check_kb<uint64_t>(
        stream, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(scalar_blocks), buffer, bsk,
        static_cast<uint64_t *>(ksk), lwe_ciphertext_count, num_scalar_blocks);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
    host_integer_radix_scalar_difference_check_kb<uint64_t>(
        stream, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(scalar_blocks), buffer,
        buffer->diff_buffer->operator_f, bsk, static_cast<uint64_t *>(ksk),
        lwe_ciphertext_count, num_scalar_blocks);
    break;
  case MAX:
  case MIN:
    host_integer_radix_scalar_maxmin_kb<uint64_t>(
        stream, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(scalar_blocks), buffer, bsk,
        static_cast<uint64_t *>(ksk), lwe_ciphertext_count, num_scalar_blocks);
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
}
