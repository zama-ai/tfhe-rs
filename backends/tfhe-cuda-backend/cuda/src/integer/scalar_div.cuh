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
    uint32_t ilog2_divisor) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_unsigned_scalar_div_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      allocate_gpu_memory, is_divisor_power_of_two,
      log2_divisor_exceeds_threshold, multiplier_exceeds_threshold,
      ilog2_divisor, &size_tracker);

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

#endif
