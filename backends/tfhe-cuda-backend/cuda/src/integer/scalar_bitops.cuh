#ifndef CUDA_INTEGER_SCALAR_BITWISE_OPS_CUH
#define CUDA_INTEGER_SCALAR_BITWISE_OPS_CUH

#include "integer/bitwise_ops.cuh"
#include <omp.h>

template <typename Torus>
__host__ void host_integer_radix_scalar_bitop_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input, Torus const *clear_blocks,
    uint32_t num_clear_blocks, int_bitop_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  if (output->num_radix_blocks != input->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be equal")
  if (output->lwe_dimension != input->lwe_dimension)
    PANIC("Cuda error: input and output num radix blocks must be equal")
  auto lut = mem_ptr->lut;
  auto op = mem_ptr->op;
  auto num_radix_blocks = output->num_radix_blocks;

  if (num_clear_blocks == 0) {
    if (op == SCALAR_BITAND) {
      set_zero_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                                   output, 0, num_radix_blocks);
    } else {
      if (input != output)
        copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], output,
                                           input);
    }
  } else {
    // We have all possible LUTs pre-computed and we use the decomposed scalar
    // as index to recover the right one
    uint64_t degrees[num_clear_blocks];
    uint64_t clear_degrees[num_clear_blocks];
    cuda_memcpy_async_to_cpu(&clear_degrees, clear_blocks,
                             num_clear_blocks * sizeof(Torus), streams[0],
                             gpu_indexes[0]);
    if (mem_ptr->op == BITOP_TYPE::SCALAR_BITAND) {
      update_degrees_after_scalar_bitand(degrees, clear_degrees, input->degrees,
                                         num_clear_blocks);
    } else if (mem_ptr->op == BITOP_TYPE::SCALAR_BITOR) {
      update_degrees_after_scalar_bitor(degrees, clear_degrees, input->degrees,
                                        num_clear_blocks);
    } else if (mem_ptr->op == SCALAR_BITXOR) {
      update_degrees_after_scalar_bitxor(degrees, clear_degrees, input->degrees,
                                         num_clear_blocks);
    }
    cuda_memcpy_async_gpu_to_gpu(lut->get_lut_indexes(0, 0), clear_blocks,
                                 num_clear_blocks * sizeof(Torus), streams[0],
                                 gpu_indexes[0]);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, output, input, bsks, ksks, lut,
        num_clear_blocks);
    memcpy(output->degrees, degrees, num_clear_blocks * sizeof(uint64_t));

    if (op == SCALAR_BITAND && num_clear_blocks < num_radix_blocks) {
      set_zero_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                                   output, num_clear_blocks,
                                                   num_radix_blocks);
    }
  }
}

#endif
