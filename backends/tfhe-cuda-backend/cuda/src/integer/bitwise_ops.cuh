#ifndef CUDA_INTEGER_BITWISE_OPS_CUH
#define CUDA_INTEGER_BITWISE_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/bitwise_ops.h"
#include "integer/integer_utilities.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"

template <typename Torus>
__host__ void
host_bitnot(CudaStreams streams, CudaRadixCiphertextFFI *radix_ciphertext,
            uint32_t ct_message_modulus, uint32_t param_message_modulus,
            uint32_t param_carry_modulus) {

  constexpr Torus TORUS_ONE = (sizeof(Torus) == 4) ? 1U : 1ULL;
  const Torus encoded_scalar =
      (TORUS_ONE << ((sizeof(Torus) * 8 - 1) -
                     __builtin_ctz(param_message_modulus *
                                   param_carry_modulus))) *
      (ct_message_modulus - 1);

  host_negation<Torus>(
      streams.stream(0), streams.gpu_index(0), (Torus *)radix_ciphertext->ptr,
      (Torus *)radix_ciphertext->ptr, radix_ciphertext->lwe_dimension,
      radix_ciphertext->num_radix_blocks);

  host_addition_plaintext_scalar<Torus>(
      streams.stream(0), streams.gpu_index(0), (Torus *)radix_ciphertext->ptr,
      (Torus *)radix_ciphertext->ptr, encoded_scalar,
      radix_ciphertext->lwe_dimension, radix_ciphertext->num_radix_blocks);
}

template <typename Torus>
__host__ void host_boolean_bitnot(CudaStreams streams,
                                 CudaRadixCiphertextFFI *lwe_array,
                                 boolean_bitnot_buffer<Torus> *mem_ptr,
                                 void *const *bsks, Torus *const *ksks) {
  if (mem_ptr->unchecked == false) {
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, lwe_array, lwe_array, bsks, ksks, mem_ptr->message_extract_lut,
        lwe_array->num_radix_blocks);
  }

  host_bitnot<Torus>(streams, lwe_array, 2, mem_ptr->params.message_modulus,
                     mem_ptr->params.carry_modulus);
}

template <typename Torus>
__host__ void host_bitop(CudaStreams streams,
                         CudaRadixCiphertextFFI *lwe_array_out,
                         CudaRadixCiphertextFFI const *lwe_array_1,
                         CudaRadixCiphertextFFI const *lwe_array_2,
                         int_bitop_buffer<Torus> *mem_ptr, void *const *bsks,
                         Torus *const *ksks) {

  PANIC_IF_FALSE(
      lwe_array_out->num_radix_blocks == lwe_array_1->num_radix_blocks &&
          lwe_array_out->num_radix_blocks == lwe_array_2->num_radix_blocks,
      "Cuda error: input and output num radix blocks must be equal");

  PANIC_IF_FALSE(lwe_array_out->lwe_dimension == lwe_array_1->lwe_dimension &&
                     lwe_array_out->lwe_dimension == lwe_array_2->lwe_dimension,
                 "Cuda error: input and output lwe dimension must be equal");

  auto lut = mem_ptr->lut;
  uint64_t degrees[lwe_array_1->num_radix_blocks];
  if (mem_ptr->op == BITOP_TYPE::BITAND) {
    update_degrees_after_bitand(degrees, lwe_array_1->degrees,
                                lwe_array_2->degrees,
                                lwe_array_1->num_radix_blocks);
  } else if (mem_ptr->op == BITOP_TYPE::BITOR) {
    update_degrees_after_bitor(degrees, lwe_array_1->degrees,
                               lwe_array_2->degrees,
                               lwe_array_1->num_radix_blocks);
  } else if (mem_ptr->op == BITOP_TYPE::BITXOR) {
    update_degrees_after_bitxor(degrees, lwe_array_1->degrees,
                                lwe_array_2->degrees,
                                lwe_array_1->num_radix_blocks);
  }

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, lwe_array_out, lwe_array_1, lwe_array_2, bsks, ksks, lut,
      lwe_array_out->num_radix_blocks, lut->params.message_modulus);

  memcpy(lwe_array_out->degrees, degrees,
         lwe_array_out->num_radix_blocks * sizeof(uint64_t));
}

template <typename Torus>
__host__ uint64_t scratch_cuda_boolean_bitnot(
    CudaStreams streams, boolean_bitnot_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t lwe_ciphertext_count, bool is_unchecked,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new boolean_bitnot_buffer<Torus>(
      streams, params, lwe_ciphertext_count, is_unchecked, allocate_gpu_memory,
      size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ uint64_t scratch_cuda_bitop(CudaStreams streams,
                                     int_bitop_buffer<Torus> **mem_ptr,
                                     uint32_t num_radix_blocks,
                                     int_radix_params params, BITOP_TYPE op,
                                     bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_bitop_buffer<Torus>(streams, op, params, num_radix_blocks,
                                         allocate_gpu_memory, size_tracker);
  return size_tracker;
}

#endif
