#ifndef CUDA_INTEGER_VECTOR_FIND_CUH
#define CUDA_INTEGER_VECTOR_FIND_CUH

#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/vector_find.h"

template <typename Torus>
__host__ void host_compute_equality_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *const *many_luts_output_list,
    const uint64_t *h_decomposed_cleartexts,
    int_equality_selectors_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  uint32_t num_possible_values = mem_ptr->num_possible_values;
  uint32_t num_blocks = mem_ptr->num_blocks_in_value;
  uint32_t message_modulus = mem_ptr->params.message_modulus;

  for (uint32_t i = 0; i < num_possible_values; i++) {

    const uint64_t *current_clear_blocks =
        &h_decomposed_cleartexts[i * num_blocks];

    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t block_value = current_clear_blocks[j];

      if (block_value >= message_modulus) {
        PANIC("Cuda error: block value in compute_equality_selectors "
              "exceeds message modulus");
      }

      CudaRadixCiphertextFFI const *input_ct =
          many_luts_output_list[block_value];

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          mem_ptr->tmp_block_comparisons, j, j + 1, input_ct, j, j + 1);
    }

    CudaRadixCiphertextFFI *current_output_block = &lwe_array_out_list[i];

    host_integer_are_all_comparisons_block_true<Torus>(
        streams, current_output_block, mem_ptr->tmp_block_comparisons,
        mem_ptr->comparison_buffer, bsks, (Torus **)ksks, num_blocks);
  }
}

template <typename Torus>
uint64_t scratch_cuda_compute_equality_selectors(
    CudaStreams streams, int_equality_selectors_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_possible_values, uint32_t num_blocks,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_equality_selectors_buffer<Torus>(
      streams, params, num_possible_values, num_blocks, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

#endif
