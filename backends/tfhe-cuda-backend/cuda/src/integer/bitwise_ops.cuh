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
__host__ uint64_t scratch_cuda_boolean_bitop(
    CudaStreams streams, boolean_bitop_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, BITOP_TYPE op,
    bool is_unchecked, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new boolean_bitop_buffer<Torus>(streams, op, is_unchecked, params,
                                             num_radix_blocks,
                                             allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void host_boolean_bitop(CudaStreams streams,
                                 CudaRadixCiphertextFFI *lwe_array_out,
                                 CudaRadixCiphertextFFI const *lwe_array_1,
                                 CudaRadixCiphertextFFI const *lwe_array_2,
                                 boolean_bitop_buffer<Torus> *mem_ptr,
                                 void *const *bsks, KSTorus *const *ksks) {

  PANIC_IF_FALSE(
      lwe_array_out->num_radix_blocks == lwe_array_1->num_radix_blocks &&
          lwe_array_out->num_radix_blocks == lwe_array_2->num_radix_blocks,
      "Cuda error: input and output num radix blocks must be equal");

  PANIC_IF_FALSE(lwe_array_out->lwe_dimension == lwe_array_1->lwe_dimension &&
                     lwe_array_out->lwe_dimension == lwe_array_2->lwe_dimension,
                 "Cuda error: input and output lwe dimension must be equal");

  auto all_degrees_are_zero =
      [&](CudaRadixCiphertextFFI const *lwe_array) -> bool {
    for (size_t i = 0; i < lwe_array->num_radix_blocks; ++i) {
      if (lwe_array->degrees[i]) {
        return false;
      }
    }
    return true;
  };

  if (all_degrees_are_zero(lwe_array_1)) {
    if (mem_ptr->op == BITOP_TYPE::BITAND) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 0,
          lwe_array_1->num_radix_blocks, lwe_array_1, 0,
          lwe_array_1->num_radix_blocks);
      memcpy(lwe_array_out->degrees, lwe_array_1->degrees,
             safe_mul_sizeof<uint64_t>(lwe_array_out->num_radix_blocks));
    } else {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 0,
          lwe_array_2->num_radix_blocks, lwe_array_2, 0,
          lwe_array_2->num_radix_blocks);
      memcpy(lwe_array_out->degrees, lwe_array_2->degrees,
             safe_mul_sizeof<uint64_t>(lwe_array_out->num_radix_blocks));
    }
    return;
  }

  if (all_degrees_are_zero(lwe_array_2)) {
    if (mem_ptr->op == BITOP_TYPE::BITAND) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 0,
          lwe_array_2->num_radix_blocks, lwe_array_2, 0,
          lwe_array_2->num_radix_blocks);
      memcpy(lwe_array_out->degrees, lwe_array_2->degrees,
             safe_mul_sizeof<uint64_t>(lwe_array_out->num_radix_blocks));
    } else {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 0,
          lwe_array_1->num_radix_blocks, lwe_array_1, 0,
          lwe_array_1->num_radix_blocks);
      memcpy(lwe_array_out->degrees, lwe_array_1->degrees,
             safe_mul_sizeof<uint64_t>(lwe_array_out->num_radix_blocks));
    }
    return;
  }

  auto needs_noise_reduction =
      [&](CudaRadixCiphertextFFI const *lwe_array) -> bool {
    bool carries_empty = true;
    for (size_t i = 0; i < lwe_array->num_radix_blocks; ++i) {
      if (lwe_array->degrees[i] >= mem_ptr->params.message_modulus) {
        carries_empty = false;
        break;
      }
    }
    if (mem_ptr->unchecked == false && carries_empty == false) {
      return true;
    }
    return false;
  };

  CudaRadixCiphertextFFI lwe_array_left;
  CudaRadixCiphertextFFI lwe_array_right;

  if (needs_noise_reduction(lwe_array_1)) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_lwe_left, 0,
        lwe_array_1->num_radix_blocks, lwe_array_1, 0,
        lwe_array_1->num_radix_blocks);
    as_radix_ciphertext_slice<Torus>(&lwe_array_left, mem_ptr->tmp_lwe_left, 0,
                                     lwe_array_1->num_radix_blocks);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &lwe_array_left, &lwe_array_left, bsks, ksks,
        mem_ptr->message_extract_lut, lwe_array_left.num_radix_blocks);
  } else {
    as_radix_ciphertext_slice<Torus>(&lwe_array_left, lwe_array_1, 0,
                                     lwe_array_1->num_radix_blocks);
  }

  if (needs_noise_reduction(lwe_array_2)) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_lwe_right, 0,
        lwe_array_2->num_radix_blocks, lwe_array_2, 0,
        lwe_array_2->num_radix_blocks);
    as_radix_ciphertext_slice<Torus>(&lwe_array_right, mem_ptr->tmp_lwe_right,
                                     0, lwe_array_2->num_radix_blocks);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &lwe_array_right, &lwe_array_right, bsks, ksks,
        mem_ptr->message_extract_lut, lwe_array_right.num_radix_blocks);
  } else {
    as_radix_ciphertext_slice<Torus>(&lwe_array_right, lwe_array_2, 0,
                                     lwe_array_2->num_radix_blocks);
  }

  auto lut = mem_ptr->lut;
  uint64_t degrees[lwe_array_left.num_radix_blocks];
  if (mem_ptr->op == BITOP_TYPE::BITAND) {
    update_degrees_after_bitand(degrees, lwe_array_left.degrees,
                                lwe_array_right.degrees,
                                lwe_array_left.num_radix_blocks);
  } else if (mem_ptr->op == BITOP_TYPE::BITOR) {
    update_degrees_after_bitor(degrees, lwe_array_left.degrees,
                               lwe_array_right.degrees,
                               lwe_array_left.num_radix_blocks);
  } else if (mem_ptr->op == BITOP_TYPE::BITXOR) {
    update_degrees_after_bitxor(degrees, lwe_array_left.degrees,
                                lwe_array_right.degrees,
                                lwe_array_left.num_radix_blocks);
  }

  // shift argument is hardcoded as 2 here, because natively message modulus for
  // boolean block should be 2. lookup table is generated with same factor.
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, lwe_array_out, &lwe_array_left, &lwe_array_right, bsks, ksks,
      lut, lwe_array_out->num_radix_blocks, 2);

  memcpy(lwe_array_out->degrees, degrees,
         safe_mul_sizeof<uint64_t>(lwe_array_out->num_radix_blocks));
}

// updates degrees based on `ct_message_modulus`
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

  for (size_t i = 0; i < radix_ciphertext->num_radix_blocks; ++i) {
    radix_ciphertext->degrees[i] = ct_message_modulus - 1;
  }
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

template <typename Torus, typename KSTorus>
__host__ void host_boolean_bitnot(CudaStreams streams,
                                  CudaRadixCiphertextFFI *lwe_array,
                                  boolean_bitnot_buffer<Torus> *mem_ptr,
                                  void *const *bsks, KSTorus *const *ksks) {
  bool carries_empty = true;
  for (size_t i = 0; i < lwe_array->num_radix_blocks; ++i) {
    if (lwe_array->degrees[i] >= mem_ptr->params.message_modulus) {
      carries_empty = false;
      break;
    }
  }
  if (mem_ptr->unchecked == false && carries_empty == false) {
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, lwe_array, lwe_array, bsks, ksks, mem_ptr->message_extract_lut,
        lwe_array->num_radix_blocks);
  }

  host_bitnot<Torus>(streams, lwe_array, 2, mem_ptr->params.message_modulus,
                     mem_ptr->params.carry_modulus);
  // we don't need to update degrees, because `host_bitnot` updates degrees
  // based on ct_message_modulus and not param_message_modulus
  // this function calls `host_bitnot` with `ct_message_modulus = 2`
}

template <typename Torus, typename KSTorus>
__host__ void host_bitop(CudaStreams streams,
                         CudaRadixCiphertextFFI *lwe_array_out,
                         CudaRadixCiphertextFFI const *lwe_array_1,
                         CudaRadixCiphertextFFI const *lwe_array_2,
                         int_bitop_buffer<Torus> *mem_ptr, void *const *bsks,
                         KSTorus *const *ksks) {

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
         safe_mul_sizeof<uint64_t>(lwe_array_out->num_radix_blocks));
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
