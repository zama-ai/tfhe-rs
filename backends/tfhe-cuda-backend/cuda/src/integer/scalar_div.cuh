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
__host__ void host_integer_unsigned_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *numerator_ct,
    int_unsigned_scalar_div_mem<Torus> *mem_ptr, Torus *const *ksks,
    uint64_t const *decomposed_scalar, uint64_t const *has_at_least_one_set,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_scalars, bool multiplier_exceeds_threshold,
    uint64_t shift_pre, uint32_t shift_post,
    CudaRadixCiphertextFFI *carry_out_sub,
    CudaRadixCiphertextFFI *carry_out_add,
    const CudaRadixCiphertextFFI *input_carries_sub,
    const CudaRadixCiphertextFFI *input_carries_add, uint32_t requested_flag,
    uint32_t uses_carry, uint64_t rhs) {

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
        streams, gpu_indexes, gpu_count, numerator_ct, numerator_cpy,
        carry_out_sub, input_carries_sub, mem_ptr->sub_and_propagate_mem, bsks,
        ksks, ms_noise_reduction_key, requested_flag, uses_carry);

    host_integer_radix_logical_scalar_shift_kb_inplace(
        streams, gpu_indexes, gpu_count, numerator_ct, 1,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

    host_add_and_propagate_single_carry(
        streams, gpu_indexes, gpu_count, numerator_ct, numerator_cpy,
        carry_out_add, input_carries_add, mem_ptr->scp_mem, bsks, ksks,
        ms_noise_reduction_key, requested_flag, uses_carry);

    host_integer_radix_logical_scalar_shift_kb_inplace(
        streams, gpu_indexes, gpu_count, numerator_ct, shift_post - (uint32_t)1,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

  } else {

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
}

#endif
