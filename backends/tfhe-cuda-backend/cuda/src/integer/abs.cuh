#ifndef TFHE_RS_ABS_CUH
#define TFHE_RS_ABS_CUH

#include "crypto/keyswitch.cuh"
#include "integer/bitwise_ops.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/negation.cuh"
#include "integer/scalar_shifts.cuh"
#include "radix_ciphertext.cuh"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_abs_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_abs_buffer<Torus> **mem_ptr, bool is_signed,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  if (is_signed) {
    *mem_ptr = new int_abs_buffer<Torus>(streams, gpu_indexes, gpu_count,
                                         params, num_blocks,
                                         allocate_gpu_memory, size_tracker);
  }
  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_abs_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *ct, void *const *bsks,
    uint64_t *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    int_abs_buffer<uint64_t> *mem_ptr, bool is_signed) {
  if (!is_signed)
    return;

  auto mask = mem_ptr->mask;

  uint32_t num_bits_in_ciphertext =
      (31 - __builtin_clz(mem_ptr->params.message_modulus)) *
      ct->num_radix_blocks;

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], mask, ct);

  host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
      streams, gpu_indexes, gpu_count, mask, num_bits_in_ciphertext - 1,
      mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key);
  host_addition<Torus>(streams[0], gpu_indexes[0], ct, mask, ct,
                       ct->num_radix_blocks, mem_ptr->params.message_modulus,
                       mem_ptr->params.carry_modulus);

  uint32_t requested_flag = outputFlag::FLAG_NONE;
  uint32_t uses_carry = 0;
  host_propagate_single_carry<Torus>(
      streams, gpu_indexes, gpu_count, ct, nullptr, nullptr, mem_ptr->scp_mem,
      bsks, ksks, ms_noise_reduction_key, requested_flag, uses_carry);

  host_integer_radix_bitop_kb<Torus>(streams, gpu_indexes, gpu_count, ct, mask,
                                     ct, mem_ptr->bitxor_mem, bsks, ksks,
                                     ms_noise_reduction_key);
}

#endif // TFHE_RS_ABS_CUH
