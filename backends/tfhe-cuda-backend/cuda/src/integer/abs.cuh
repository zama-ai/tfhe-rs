#ifndef TFHE_RS_ABS_CUH
#define TFHE_RS_ABS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer/bitwise_ops.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/negation.cuh"
#include "integer/scalar_shifts.cuh"
#include "linear_algebra.h"
#include "pbs/programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
__host__ void scratch_cuda_integer_abs_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_abs_buffer<Torus> **mem_ptr, bool is_signed,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  if (is_signed)
    *mem_ptr =
        new int_abs_buffer<Torus>(streams, gpu_indexes, gpu_count, params,
                                  num_blocks, allocate_gpu_memory);
}

template <typename Torus>
__host__ void
host_integer_abs_kb(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                    uint32_t gpu_count, Torus *ct, void *const *bsks,
                    uint64_t *const *ksks, int_abs_buffer<uint64_t> *mem_ptr,
                    bool is_signed, uint32_t num_blocks) {
  if (!is_signed)
    return;

  auto radix_params = mem_ptr->params;
  auto mask = mem_ptr->mask;

  auto big_lwe_dimension = radix_params.big_lwe_dimension;
  auto big_lwe_size = big_lwe_dimension + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
  uint32_t num_bits_in_ciphertext =
      (31 - __builtin_clz(radix_params.message_modulus)) * num_blocks;

  cuda_memcpy_async_gpu_to_gpu(mask, ct, num_blocks * big_lwe_size_bytes,
                               streams[0], gpu_indexes[0]);

  host_integer_radix_arithmetic_scalar_shift_kb_inplace(
      streams, gpu_indexes, gpu_count, mask, num_bits_in_ciphertext - 1,
      mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks, num_blocks);
  host_addition<Torus>(streams[0], gpu_indexes[0], ct, mask, ct,
                       radix_params.big_lwe_dimension, num_blocks);

  uint32_t requested_flag = outputFlag::FLAG_NONE;
  uint32_t uses_carry = 0;
  host_propagate_single_carry<Torus>(
      streams, gpu_indexes, gpu_count, ct, nullptr, nullptr, mem_ptr->scp_mem,
      bsks, ksks, num_blocks, requested_flag, uses_carry);

  host_integer_radix_bitop_kb(streams, gpu_indexes, gpu_count, ct, mask, ct,
                              mem_ptr->bitxor_mem, bsks, ksks, num_blocks);
}

#endif // TFHE_RS_ABS_CUH
