#ifndef SCALAR_DIV_CUH
#define SCALAR_DIV_CUH

#include "integer/integer_utilities.h"
#include "integer/scalar_mul.cuh"
#include "integer/scalar_shifts.cuh"
#include "integer/subtraction.cuh"

template <typename Torus>
__host__ uint64_t scratch_integer_unsigned_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, const int_radix_params params,
    int_unsigned_scalar_div_mem<Torus> **mem_ptr, uint32_t num_radix_blocks,
    const bool allocate_gpu_memory, bool is_divisor_power_of_two,
    bool log2_divisor_exceeds_threshold, bool multiplier_exceeds_threshold,
    uint32_t num_scalar_bits, uint32_t ilog2_divisor) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_unsigned_scalar_div_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      allocate_gpu_memory, is_divisor_power_of_two,
      log2_divisor_exceeds_threshold, multiplier_exceeds_threshold,
      ilog2_divisor, num_scalar_bits, &size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_unsigned_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *numerator_ct,
    int_unsigned_scalar_div_mem<Torus> *mem_ptr, Torus *const *ksks,
    uint64_t const *decomposed_scalar, uint64_t const *has_at_least_one_set,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_scalars, bool multiplier_exceeds_threshold,
    bool is_divisor_power_of_two, bool log2_divisor_exceeds_threshold,
    uint32_t ilog2_divisor, uint64_t shift_pre, uint32_t shift_post,
    uint64_t rhs) {

  if (ilog2_divisor == (uint32_t)0) {
    return;
  }

  if (is_divisor_power_of_two) {

    host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct, ilog2_divisor,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

    return;
  }

  if (log2_divisor_exceeds_threshold) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], numerator_ct,
                                       mem_ptr->tmp_ffi);

    return;
  }

  if (multiplier_exceeds_threshold) {

    if (shift_pre != (uint64_t)0) {
      PANIC("shift_pre should be == 0");
    }

    if (shift_post == (uint32_t)0) {
      PANIC("shift_post should be > 0");
    }

    CudaRadixCiphertextFFI *numerator_cpy = mem_ptr->tmp_ffi;

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       numerator_cpy, numerator_ct);

    host_integer_radix_scalar_mul_high_kb(
        streams, gpu_indexes, gpu_count, numerator_cpy,
        mem_ptr->scalar_mul_high_mem, ksks, rhs, decomposed_scalar,
        has_at_least_one_set, ms_noise_reduction_key, bsks, num_scalars);

    host_sub_and_propagate_single_carry(
        streams, gpu_indexes, gpu_count, numerator_ct, numerator_cpy, nullptr,
        nullptr, mem_ptr->sub_and_propagate_mem, bsks, ksks,
        ms_noise_reduction_key, FLAG_NONE, (uint32_t)0);

    host_integer_radix_logical_scalar_shift_kb_inplace(
        streams, gpu_indexes, gpu_count, numerator_ct, (uint32_t)1,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

    host_add_and_propagate_single_carry(
        streams, gpu_indexes, gpu_count, numerator_ct, numerator_cpy, nullptr,
        nullptr, mem_ptr->scp_mem, bsks, ksks, ms_noise_reduction_key,
        FLAG_NONE, (uint32_t)0);

    host_integer_radix_logical_scalar_shift_kb_inplace(
        streams, gpu_indexes, gpu_count, numerator_ct, shift_post - (uint32_t)1,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

    return;
  }

  host_integer_radix_logical_scalar_shift_kb_inplace(
      streams, gpu_indexes, gpu_count, numerator_ct, shift_pre,
      mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
      numerator_ct->num_radix_blocks);

  host_integer_radix_scalar_mul_high_kb(
      streams, gpu_indexes, gpu_count, numerator_ct,
      mem_ptr->scalar_mul_high_mem, ksks, rhs, decomposed_scalar,
      has_at_least_one_set, ms_noise_reduction_key, bsks, num_scalars);

  host_integer_radix_logical_scalar_shift_kb_inplace(
      streams, gpu_indexes, gpu_count, numerator_ct, shift_post,
      mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
      numerator_ct->num_radix_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_integer_signed_scalar_div_radix_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_radix_params params,
    int_signed_scalar_div_mem<Torus> **mem_ptr, uint32_t num_radix_blocks,
    uint32_t num_scalar_bits, const bool allocate_gpu_memory,
    bool is_absolute_divisor_one, bool is_divisor_negative,
    bool l_exceed_threshold, bool is_power_of_two, bool multiplier_is_small) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_signed_scalar_div_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      num_scalar_bits, allocate_gpu_memory, is_absolute_divisor_one,
      is_divisor_negative, l_exceed_threshold, is_power_of_two,
      multiplier_is_small, &size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_signed_scalar_div_radix_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *numerator_ct,
    int_signed_scalar_div_mem<Torus> *mem_ptr, Torus *const *ksks,
    void *const *bsks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    bool is_absolute_divisor_one, bool is_divisor_negative,
    bool l_exceed_threshold, bool is_power_of_two, bool multiplier_is_small,
    uint32_t l, uint32_t shift_post, bool is_rhs_power_of_two, bool is_rhs_zero,
    bool is_rhs_one, uint32_t rhs_shift, uint32_t numerator_bits,
    uint32_t num_scalars, uint64_t const *decomposed_scalar,
    uint64_t const *has_at_least_one_set) {

  if (is_absolute_divisor_one) {
    if (is_divisor_negative) {
      CudaRadixCiphertextFFI *tmp = mem_ptr->tmp_ffi;

      host_integer_radix_negation<Torus>(
          streams, gpu_indexes, gpu_count, tmp, numerator_ct,
          mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus,
          numerator_ct->num_radix_blocks);

      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                         numerator_ct, tmp);
    }
    return;
  }

  if (l_exceed_threshold) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], numerator_ct, 0,
        numerator_ct->num_radix_blocks);

    return;
  }

  CudaRadixCiphertextFFI *tmp = mem_ptr->tmp_ffi;

  if (is_power_of_two) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], tmp,
                                       numerator_ct);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp, l - 1,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

    host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp, numerator_bits - l,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        tmp->num_radix_blocks);

    host_add_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, tmp, numerator_ct, nullptr, nullptr,
        mem_ptr->scp_mem, bsks, ksks, ms_noise_reduction_key, FLAG_NONE,
        (uint32_t)0);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp, l,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

  } else if (multiplier_is_small) {

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], tmp,
                                       numerator_ct);

    host_integer_radix_signed_scalar_mul_high_kb<Torus>(
        streams, gpu_indexes, gpu_count, tmp, mem_ptr->scalar_mul_high_mem,
        ksks, is_rhs_power_of_two, is_rhs_zero, is_rhs_one, rhs_shift,
        decomposed_scalar, has_at_least_one_set, ms_noise_reduction_key, bsks,
        num_scalars);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp, shift_post,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

    CudaRadixCiphertextFFI *xsign = mem_ptr->xsign_ffi;
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], xsign,
                                       numerator_ct);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, xsign, numerator_bits - 1,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

    host_sub_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, tmp, xsign, nullptr, nullptr,
        mem_ptr->sub_and_propagate_mem, bsks, ksks, ms_noise_reduction_key,
        FLAG_NONE, (uint32_t)0);

  } else {

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], tmp,
                                       numerator_ct);

    host_integer_radix_signed_scalar_mul_high_kb<Torus>(
        streams, gpu_indexes, gpu_count, tmp, mem_ptr->scalar_mul_high_mem,
        ksks, is_rhs_power_of_two, is_rhs_zero, is_rhs_one, rhs_shift,
        decomposed_scalar, has_at_least_one_set, ms_noise_reduction_key, bsks,
        num_scalars);

    host_add_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, tmp, numerator_ct, nullptr, nullptr,
        mem_ptr->scp_mem, bsks, ksks, ms_noise_reduction_key, FLAG_NONE,
        (uint32_t)0);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp, shift_post,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

    CudaRadixCiphertextFFI *xsign = mem_ptr->xsign_ffi;
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], xsign,
                                       numerator_ct);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, xsign, numerator_bits - 1,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

    host_sub_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, tmp, xsign, nullptr, nullptr,
        mem_ptr->sub_and_propagate_mem, bsks, ksks, ms_noise_reduction_key,
        FLAG_NONE, (uint32_t)0);
  }

  if (is_divisor_negative) {
    host_integer_radix_negation<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct, tmp,
        mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus,
        numerator_ct->num_radix_blocks);
  } else {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], numerator_ct,
                                       tmp);
  }
}

#endif
