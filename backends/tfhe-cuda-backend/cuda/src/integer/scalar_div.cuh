#ifndef SCALAR_DIV_CUH
#define SCALAR_DIV_CUH

#include "integer/integer_utilities.h"
#include "integer/scalar_bitops.cuh"
#include "integer/scalar_mul.cuh"
#include "integer/scalar_shifts.cuh"
#include "integer/subtraction.cuh"

template <typename Torus>
__host__ uint64_t scratch_integer_unsigned_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, const int_radix_params params,
    int_unsigned_scalar_div_mem<Torus> **mem_ptr, uint32_t num_radix_blocks,
    const CudaScalarDivisorFFI *scalar_properties,
    const bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_unsigned_scalar_div_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      scalar_properties, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_unsigned_scalar_div_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *numerator_ct,
    int_unsigned_scalar_div_mem<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties) {

  if (scalar_properties->is_abs_divisor_one) {
    return;
  }

  if (scalar_properties->is_divisor_pow2) {
    host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct,
        scalar_properties->ilog2_divisor, mem_ptr->logical_scalar_shift_mem,
        bsks, ksks, ms_noise_reduction_key, numerator_ct->num_radix_blocks);
    return;
  }

  if (scalar_properties->is_divisor_wider_than_numerator) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], numerator_ct,
                                       mem_ptr->tmp_ffi);
    return;
  }

  if (scalar_properties->is_multiplier_geq_numerator_magnitude) {

    if (scalar_properties->shift_pre != (uint64_t)0) {
      PANIC("shift_pre should be == 0");
    }

    if (scalar_properties->shift_post == (uint32_t)0) {
      PANIC("shift_post should be > 0");
    }

    CudaRadixCiphertextFFI *numerator_cpy = mem_ptr->tmp_ffi;

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       numerator_cpy, numerator_ct);

    host_integer_radix_scalar_mul_high_kb<Torus>(
        streams, gpu_indexes, gpu_count, numerator_cpy,
        mem_ptr->scalar_mul_high_mem, ksks, ms_noise_reduction_key, bsks,
        scalar_properties);

    host_sub_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct, numerator_cpy, nullptr,
        nullptr, mem_ptr->sub_and_propagate_mem, bsks, ksks,
        ms_noise_reduction_key, FLAG_NONE, (uint32_t)0);

    host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct, (uint32_t)1,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

    host_add_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct, numerator_cpy, nullptr,
        nullptr, mem_ptr->scp_mem, bsks, ksks, ms_noise_reduction_key,
        FLAG_NONE, (uint32_t)0);

    host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct,
        scalar_properties->shift_post - (uint32_t)1,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        numerator_ct->num_radix_blocks);

    return;
  }

  host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
      streams, gpu_indexes, gpu_count, numerator_ct,
      scalar_properties->shift_pre, mem_ptr->logical_scalar_shift_mem, bsks,
      ksks, ms_noise_reduction_key, numerator_ct->num_radix_blocks);

  host_integer_radix_scalar_mul_high_kb<Torus>(
      streams, gpu_indexes, gpu_count, numerator_ct,
      mem_ptr->scalar_mul_high_mem, ksks, ms_noise_reduction_key, bsks,
      scalar_properties);

  host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
      streams, gpu_indexes, gpu_count, numerator_ct,
      scalar_properties->shift_post, mem_ptr->logical_scalar_shift_mem, bsks,
      ksks, ms_noise_reduction_key, numerator_ct->num_radix_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_integer_signed_scalar_div_radix_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_radix_params params,
    int_signed_scalar_div_mem<Torus> **mem_ptr, uint32_t num_radix_blocks,
    const CudaScalarDivisorFFI *scalar_properties,
    const bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_signed_scalar_div_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      scalar_properties, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_signed_scalar_div_radix_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *numerator_ct,
    int_signed_scalar_div_mem<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties, uint32_t numerator_bits) {

  if (scalar_properties->is_abs_divisor_one) {
    if (scalar_properties->is_divisor_negative) {
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

  if (scalar_properties->is_multiplier_wider_than_numerator) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], numerator_ct, 0,
        numerator_ct->num_radix_blocks);
    return;
  }

  CudaRadixCiphertextFFI *tmp = mem_ptr->tmp_ffi;

  if (scalar_properties->is_divisor_pow2) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], tmp,
                                       numerator_ct);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp,
        scalar_properties->multiplier_length - 1,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

    host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp,
        numerator_bits - scalar_properties->multiplier_length,
        mem_ptr->logical_scalar_shift_mem, bsks, ksks, ms_noise_reduction_key,
        tmp->num_radix_blocks);

    host_add_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, tmp, numerator_ct, nullptr, nullptr,
        mem_ptr->scp_mem, bsks, ksks, ms_noise_reduction_key, FLAG_NONE,
        (uint32_t)0);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp,
        scalar_properties->multiplier_length,
        mem_ptr->arithmetic_scalar_shift_mem, bsks, ksks,
        ms_noise_reduction_key);

  } else if (!scalar_properties->is_multiplier_geq_numerator_magnitude) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], tmp,
                                       numerator_ct);

    host_integer_radix_signed_scalar_mul_high_kb<Torus>(
        streams, gpu_indexes, gpu_count, tmp, mem_ptr->scalar_mul_high_mem,
        ksks, scalar_properties, ms_noise_reduction_key, bsks);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp, scalar_properties->shift_post,
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
        ksks, scalar_properties, ms_noise_reduction_key, bsks);

    host_add_and_propagate_single_carry<Torus>(
        streams, gpu_indexes, gpu_count, tmp, numerator_ct, nullptr, nullptr,
        mem_ptr->scp_mem, bsks, ksks, ms_noise_reduction_key, FLAG_NONE,
        (uint32_t)0);

    host_integer_radix_arithmetic_scalar_shift_kb_inplace<Torus>(
        streams, gpu_indexes, gpu_count, tmp, scalar_properties->shift_post,
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

  if (scalar_properties->is_divisor_negative) {
    host_integer_radix_negation<Torus>(
        streams, gpu_indexes, gpu_count, numerator_ct, tmp,
        mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus,
        numerator_ct->num_radix_blocks);
  } else {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], numerator_ct,
                                       tmp);
  }
}

template <typename Torus>
__host__ uint64_t scratch_integer_unsigned_scalar_div_rem_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, const int_radix_params params,
    int_unsigned_scalar_div_rem_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, const CudaScalarDivisorFFI *scalar_properties,
    const bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unsigned_scalar_div_rem_buffer<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      scalar_properties, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_unsigned_scalar_div_rem_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *quotient_ct,
    CudaRadixCiphertextFFI *remainder_ct,
    int_unsigned_scalar_div_rem_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties, Torus const *clear_blocks,
    Torus const *h_clear_blocks, uint32_t num_clear_blocks) {

  auto numerator_ct = mem_ptr->numerator_ct;
  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], numerator_ct,
                                     quotient_ct);

  host_integer_unsigned_scalar_div_radix(
      streams, gpu_indexes, gpu_count, quotient_ct, mem_ptr->unsigned_div_mem,
      bsks, ksks, ms_noise_reduction_key, scalar_properties);

  if (scalar_properties->is_divisor_pow2) {

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], remainder_ct,
                                       numerator_ct);
    host_integer_radix_scalar_bitop_kb(
        streams, gpu_indexes, gpu_count, remainder_ct, remainder_ct,
        clear_blocks, h_clear_blocks, num_clear_blocks, mem_ptr->bitop_mem,
        bsks, ksks, ms_noise_reduction_key);

  } else {
    if (!scalar_properties->is_divisor_zero) {
      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                         remainder_ct, quotient_ct);

      if (!scalar_properties->is_abs_divisor_one &&
          remainder_ct->num_radix_blocks != 0) {

        host_integer_scalar_mul_radix<Torus>(
            streams, gpu_indexes, gpu_count, remainder_ct,
            scalar_properties->decomposed_divisor,
            scalar_properties->divisor_has_at_least_one_set,
            mem_ptr->scalar_mul_mem, bsks, ksks, ms_noise_reduction_key,
            mem_ptr->params.message_modulus,
            scalar_properties->num_scalars_divisor);
      }
    }

    host_sub_and_propagate_single_carry(
        streams, gpu_indexes, gpu_count, numerator_ct, remainder_ct, nullptr,
        nullptr, mem_ptr->sub_and_propagate_mem, bsks, ksks,
        ms_noise_reduction_key, FLAG_NONE, (uint32_t)0);

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], remainder_ct,
                                       numerator_ct);
  }
}

template <typename Torus>
__host__ uint64_t scratch_integer_signed_scalar_div_rem_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, const int_radix_params params,
    int_signed_scalar_div_rem_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, const CudaScalarDivisorFFI *scalar_properties,
    const bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_signed_scalar_div_rem_buffer<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      scalar_properties, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_signed_scalar_div_rem_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *quotient_ct,
    CudaRadixCiphertextFFI *remainder_ct,
    int_signed_scalar_div_rem_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties, uint32_t numerator_bits) {

  auto numerator_ct = mem_ptr->numerator_ct;
  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], numerator_ct,
                                     quotient_ct);

  host_integer_signed_scalar_div_radix_kb(
      streams, gpu_indexes, gpu_count, quotient_ct, mem_ptr->signed_div_mem,
      bsks, ksks, ms_noise_reduction_key, scalar_properties, numerator_bits);

  host_propagate_single_carry<Torus>(
      streams, gpu_indexes, gpu_count, quotient_ct, nullptr, nullptr,
      mem_ptr->scp_mem, bsks, ksks, ms_noise_reduction_key, FLAG_NONE,
      (uint32_t)0);

  if (!scalar_properties->is_divisor_negative &&
      scalar_properties->is_divisor_pow2) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], remainder_ct,
                                       quotient_ct);

    host_integer_radix_logical_scalar_shift_kb_inplace(
        streams, gpu_indexes, gpu_count, remainder_ct,
        scalar_properties->ilog2_divisor, mem_ptr->logical_scalar_shift_mem,
        bsks, ksks, ms_noise_reduction_key, remainder_ct->num_radix_blocks);

  } else if (!scalar_properties->is_divisor_zero) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], remainder_ct,
                                       quotient_ct);

    bool is_divisor_one = scalar_properties->is_abs_divisor_one &&
                          !scalar_properties->is_divisor_negative;

    if (!is_divisor_one && remainder_ct->num_radix_blocks != 0) {
      host_integer_scalar_mul_radix<Torus>(
          streams, gpu_indexes, gpu_count, remainder_ct,
          scalar_properties->decomposed_divisor,
          scalar_properties->divisor_has_at_least_one_set,
          mem_ptr->scalar_mul_mem, bsks, ksks, ms_noise_reduction_key,
          mem_ptr->params.message_modulus,
          scalar_properties->num_scalars_divisor);
    }
  }

  host_sub_and_propagate_single_carry(
      streams, gpu_indexes, gpu_count, numerator_ct, remainder_ct, nullptr,
      nullptr, mem_ptr->sub_and_propagate_mem, bsks, ksks,
      ms_noise_reduction_key, FLAG_NONE, (uint32_t)0);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], remainder_ct,
                                     numerator_ct);
}

#endif
