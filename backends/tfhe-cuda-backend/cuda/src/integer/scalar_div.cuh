#ifndef SCALAR_DIV_CUH
#define SCALAR_DIV_CUH

#include "integer/integer_utilities.h"
#include "integer/scalar_mul.cuh"
#include "integer/scalar_shifts.cuh"

template <typename Torus>
__host__ uint64_t scratch_integer_unsigned_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, const int_radix_params params,
    int_unsigned_scalar_div_mem<Torus> **mem_ptr, uint32_t num_radix_blocks,
    const bool allocate_gpu_memory, SHIFT_OR_ROTATE_TYPE shift_type,
    uint32_t requested_flag_in, bool anticipated_buffer_drop) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_unsigned_scalar_div_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      allocate_gpu_memory, shift_type, requested_flag_in,
      anticipated_buffer_drop, &size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ uint64_t scratch_integer_signed_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, const int_radix_params params,
    int_signed_scalar_div_mem<Torus> **mem_ptr, uint32_t num_radix_blocks,
    const bool allocate_gpu_memory, SHIFT_OR_ROTATE_TYPE shift_type,
    uint32_t requested_flag_in, bool anticipated_buffer_drop) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_signed_scalar_div_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      allocate_gpu_memory, shift_type, requested_flag_in,
      anticipated_buffer_drop, &size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_unsigned_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *numerator_ct,
    int_unsigned_scalar_div_mem<Torus> *mem_ptr, Torus *const *ksks,
    uint64_t const *decomposed_scalar, uint64_t const *has_at_least_one_set,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_scalars, uint64_t multiplier,
    uint64_t shift_pre, uint64_t shift_post, uint32_t numerator_bits) {

  if ((uint32_t)multiplier >= (uint32_t)1 << numerator_bits) {

    if (shift_pre != 0) {
      PANIC("shift_pre should be == 0");
    }

    if (shift_post == 0) {
      PANIC("shift_post should be > 0");
    }

    uint64_t inverse = multiplier - (uint64_t)((uint32_t)1 << numerator_bits);

    host_integer_radix_scalar_mul_high_kb(
        streams, gpu_indexes, gpu_count, numerator_ct,
        mem_ptr->scalar_mul_high_mem, ksks, inverse, decomposed_scalar,
        has_at_least_one_set, ms_noise_reduction_key, bsks, num_scalars);

  } else {

    host_integer_radix_logical_scalar_shift_kb_inplace(
        streams, gpu_indexes, gpu_count, numerator_ct, shift_pre,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

    host_integer_radix_scalar_mul_high_kb(
        streams, gpu_indexes, gpu_count, numerator_ct,
        mem_ptr->scalar_mul_high_mem, ksks, multiplier, decomposed_scalar,
        has_at_least_one_set, ms_noise_reduction_key, bsks, num_scalars);

    host_integer_radix_logical_scalar_shift_kb_inplace(
        streams, gpu_indexes, gpu_count, numerator_ct, shift_post,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);
  }
}

#endif
