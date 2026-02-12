#ifndef CUDA_INTEGER_SCALAR_BITWISE_OPS_CUH
#define CUDA_INTEGER_SCALAR_BITWISE_OPS_CUH

#include "integer/bitwise_ops.cuh"

template <typename Torus, typename KSTorus>
__host__ void
host_scalar_bitop(CudaStreams streams, CudaRadixCiphertextFFI *output,
                  CudaRadixCiphertextFFI const *input,
                  Torus const *clear_blocks, Torus const *h_clear_blocks,
                  uint32_t num_clear_blocks, int_bitop_buffer<Torus> *mem_ptr,
                  void *const *bsks, KSTorus *const *ksks) {

  if (output->num_radix_blocks != input->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be equal")
  if (output->lwe_dimension != input->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimension must be equal")
  auto lut = mem_ptr->lut;
  auto op = mem_ptr->op;
  auto num_radix_blocks = output->num_radix_blocks;

  if (num_clear_blocks == 0) {
    if (op == SCALAR_BITAND) {
      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), output, 0, num_radix_blocks);
    } else {
      if (input != output)
        copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                           streams.gpu_index(0), output, input);
    }
  } else {
    // We have all possible LUTs pre-computed and we use the decomposed scalar
    // as index to recover the right one
    uint64_t degrees[num_clear_blocks];
    if (mem_ptr->op == BITOP_TYPE::SCALAR_BITAND) {
      update_degrees_after_scalar_bitand(degrees, h_clear_blocks,
                                         input->degrees, num_clear_blocks);
    } else if (mem_ptr->op == BITOP_TYPE::SCALAR_BITOR) {
      update_degrees_after_scalar_bitor(degrees, h_clear_blocks, input->degrees,
                                        num_clear_blocks);
    } else if (mem_ptr->op == SCALAR_BITXOR) {
      update_degrees_after_scalar_bitxor(degrees, h_clear_blocks,
                                         input->degrees, num_clear_blocks);
    }
    auto active_streams = streams.active_gpu_subset(
        num_clear_blocks, mem_ptr->lut->params.pbs_type);
    lut->set_lut_indexes_and_broadcast_from_gpu(active_streams, clear_blocks,
                                                num_clear_blocks);

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, output, input, bsks, ksks, lut, num_clear_blocks);
    memcpy(output->degrees, degrees,
           safe_mul_sizeof<uint64_t>(num_clear_blocks));

    if (op == SCALAR_BITAND && num_clear_blocks < num_radix_blocks) {
      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), output, num_clear_blocks,
          num_radix_blocks);
    }
  }
}

#endif
