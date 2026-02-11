#include "integer/scalar_bitops.cuh"

void cuda_integer_scalar_bitop_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_input, void const *clear_blocks,
    void const *h_clear_blocks, uint32_t num_clear_blocks, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks) {

  host_scalar_bitop<uint64_t>(
      CudaStreams(streams), lwe_array_out, lwe_array_input,
      static_cast<const uint64_t *>(clear_blocks),
      static_cast<const uint64_t *>(h_clear_blocks), num_clear_blocks,
      (int_bitop_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks));
}

void update_degrees_after_scalar_bitand(uint64_t *output_degrees,
                                        uint64_t const *clear_degrees,
                                        uint64_t const *input_degrees,
                                        uint32_t num_clear_blocks) {
  for (uint i = 0; i < num_clear_blocks; i++) {
    output_degrees[i] = std::min(clear_degrees[i], input_degrees[i]);
  }
}
void update_degrees_after_scalar_bitor(uint64_t *output_degrees,
                                       uint64_t const *clear_degrees,
                                       uint64_t const *input_degrees,
                                       uint32_t num_clear_blocks) {
  for (uint i = 0; i < num_clear_blocks; i++) {
    auto max = std::max(clear_degrees[i], input_degrees[i]);
    auto min = std::min(clear_degrees[i], input_degrees[i]);
    auto result = max;

    for (uint j = 0; j < min + 1; j++) {
      if ((max | j) > result) {
        result = max | j;
      }
    }
    output_degrees[i] = result;
  }
}
void update_degrees_after_scalar_bitxor(uint64_t *output_degrees,
                                        uint64_t const *clear_degrees,
                                        uint64_t const *input_degrees,
                                        uint32_t num_clear_blocks) {
  for (uint i = 0; i < num_clear_blocks; i++) {
    auto max = std::max(clear_degrees[i], input_degrees[i]);
    auto min = std::min(clear_degrees[i], input_degrees[i]);
    auto result = max;

    // Try every possibility to find the worst case
    for (uint j = 0; j < min + 1; j++) {
      if ((max ^ j) > result) {
        result = max ^ j;
      }
    }
    output_degrees[i] = result;
  }
}
