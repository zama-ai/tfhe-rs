#ifndef TFHE_RS_ABS_CUH
#define TFHE_RS_ABS_CUH

#include "crypto/keyswitch.cuh"
#include "integer/abs.h"
#include "integer/bitwise_ops.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/scalar_shifts.cuh"
#include "radix_ciphertext.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_abs(CudaStreams streams,
                                           int_abs_buffer<Torus> **mem_ptr,
                                           bool is_signed, uint32_t num_blocks,
                                           int_radix_params params,
                                           bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  if (is_signed) {
    *mem_ptr = new int_abs_buffer<Torus>(streams, params, num_blocks,
                                         allocate_gpu_memory, size_tracker);
  }
  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_abs(CudaStreams streams, CudaRadixCiphertextFFI *ct,
                               void *const *bsks, uint64_t *const *ksks,
                               int_abs_buffer<uint64_t> *mem_ptr,
                               bool is_signed) {
  if (!is_signed)
    return;

  auto mask = mem_ptr->mask;

  uint32_t num_bits_in_ciphertext =
      (31 - __builtin_clz(mem_ptr->params.message_modulus)) *
      ct->num_radix_blocks;

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     mask, ct);

  host_arithmetic_scalar_shift_inplace<Torus>(
      streams, mask, num_bits_in_ciphertext - 1,
      mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ct, mask, ct,
                       ct->num_radix_blocks, mem_ptr->params.message_modulus,
                       mem_ptr->params.carry_modulus);

  uint32_t requested_flag = outputFlag::FLAG_NONE;
  uint32_t uses_carry = 0;
  host_propagate_single_carry<Torus>(streams, ct, nullptr, nullptr,
                                     mem_ptr->scp_mem, bsks, ksks,
                                     requested_flag, uses_carry);

  host_bitop<Torus>(streams, ct, mask, ct, mem_ptr->bitxor_mem, bsks, ksks);
}

#endif // TFHE_RS_ABS_CUH
