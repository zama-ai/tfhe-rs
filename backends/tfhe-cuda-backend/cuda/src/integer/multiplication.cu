#include "integer/multiplication.cuh"
#include "polynomial/dispatch.cuh"

void cuda_integer_mult_inplace_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *radix_lwe_inout,
    bool const is_bool_left, CudaRadixCiphertextFFI const *radix_lwe_right,
    bool const is_bool_right, void *const *bsks, void *const *ksks,
    int8_t *mem_ptr, uint32_t polynomial_size, uint32_t num_blocks) {
  // In-place variant: radix_lwe_inout *= radix_lwe_right, no aliasing check
  // needed
  PUSH_RANGE("mul_inplace")
  DISPATCH_POLY_SIZE(polynomial_size, AmortizedDegreePolicy,
                     host_integer_mult_radix<uint64_t, Params>(
                         CudaStreams(streams), radix_lwe_inout, radix_lwe_inout,
                         is_bool_left, radix_lwe_right, is_bool_right, bsks,
                         (uint64_t **)(ksks),
                         (int_mul_memory<uint64_t> *)mem_ptr, num_blocks));
  POP_RANGE()
}

uint64_t scratch_cuda_integer_mult_inplace_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, bool const is_boolean_left,
    bool const is_boolean_right, uint32_t message_modulus,
    uint32_t carry_modulus, CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_radix_blocks,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  const uint32_t polynomial_size = bsk_params.polynomial_size;
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  if (polynomial_size < 256 || polynomial_size > 16384 ||
      (polynomial_size & (polynomial_size - 1)) != 0)
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Supported N's are powers of two in the interval [256..16384].")

  return scratch_cuda_integer_mult_radix_ciphertext<uint64_t>(
      CudaStreams(streams), (int_mul_memory<uint64_t> **)mem_ptr,
      is_boolean_left, is_boolean_right, num_radix_blocks, params,
      allocate_gpu_memory);
}

void cleanup_cuda_integer_mult_inplace_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup mul")
  int_mul_memory<uint64_t> *mem_ptr =
      (int_mul_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}

uint64_t scratch_cuda_partial_sum_ciphertexts_vec_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks_in_radix,
    uint32_t max_num_radix_in_vec, uint32_t message_modulus,
    uint32_t carry_modulus, bool reduce_degrees_for_single_carry_propagation,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  return scratch_cuda_integer_partial_sum_ciphertexts_vec<uint64_t>(
      CudaStreams(streams),
      (int_sum_ciphertexts_vec_memory<uint64_t> **)mem_ptr, num_blocks_in_radix,
      max_num_radix_in_vec, reduce_degrees_for_single_carry_propagation, params,
      allocate_gpu_memory);
}

void cuda_partial_sum_ciphertexts_vec_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *radix_lwe_out,
    CudaRadixCiphertextFFI *radix_lwe_vec, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {
  PANIC_IF_FALSE(radix_lwe_out != radix_lwe_vec,
                 "Output and input pointers must be different for out-of-place "
                 "operations");

  auto mem = (int_sum_ciphertexts_vec_memory<uint64_t> *)mem_ptr;
  if (radix_lwe_vec->num_radix_blocks % radix_lwe_out->num_radix_blocks != 0)
    PANIC("Cuda error: input vector length should be a multiple of the "
          "output's number of radix blocks")
  host_integer_partial_sum_ciphertexts_vec<uint64_t>(
      CudaStreams(streams), radix_lwe_out, radix_lwe_vec, bsks,
      (uint64_t **)(ksks), mem, radix_lwe_out->num_radix_blocks,
      radix_lwe_vec->num_radix_blocks / radix_lwe_out->num_radix_blocks);
}

void cleanup_cuda_partial_sum_ciphertexts_vec_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void) {
  int_sum_ciphertexts_vec_memory<uint64_t> *mem_ptr =
      (int_sum_ciphertexts_vec_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_mul_add_fixed_point_with_rescaling_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t lhs_blocks,
    uint32_t rhs_blocks, uint32_t rescaling, uint32_t precision,
    uint32_t message_modulus, uint32_t carry_modulus,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  // The fixed-point shape takes its addend through `added`, never as extra
  // terms.
  return scratch_cuda_mul_add_fixed_point<uint64_t>(
      CudaStreams(streams),
      (int_mul_add_fixed_point_memory<uint64_t> **)mem_ptr,
      MUL_ADD_MODE_FIXED_POINT, lhs_blocks, rhs_blocks, rescaling, precision,
      /*max_extra_terms=*/0, params, allocate_gpu_memory);
}

/// @brief FFI entry point for the fixed-point fused multiply-add:
/// result[L] = trunc_beta^(R+|rescaling|)( lhs[L] * rhs[R] ) + added[L].
/// @param result Output, L blocks; must not alias lhs or added.
/// @param lhs Left operand, at least L blocks.
/// @param rhs Right operand, at least R blocks.
/// @param added Accumulator addend of L blocks, or null.
/// @param mem_ptr Scratch buffer from
/// scratch_cuda_mul_add_fixed_point_with_rescaling_64_async.
void cuda_mul_add_fixed_point_with_rescaling_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *result,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    CudaRadixCiphertextFFI const *added, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {
  PANIC_IF_FALSE(result != lhs && result != added,
                 "Output and input pointers must be different for "
                 "out-of-place operations");
  host_mul_add_fixed_point_with_rescaling<uint64_t>(
      CudaStreams(streams), result, lhs, rhs, added,
      (int_mul_add_fixed_point_memory<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks));
}

void cleanup_cuda_mul_add_fixed_point_with_rescaling_64(CudaStreamsFFI streams,
                                                        int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup mul_add_fixed_point")
  int_mul_add_fixed_point_memory<uint64_t> *mem_ptr =
      (int_mul_add_fixed_point_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}

uint64_t scratch_cuda_mul_low_partial_sum_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t num_blocks,
    uint32_t max_extra_terms, uint32_t message_modulus, uint32_t carry_modulus,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  // The mul-low shape is square and keeps every column: no rescaling, and a
  // zero precision so that nothing is skipped.
  return scratch_cuda_mul_add_fixed_point<uint64_t>(
      CudaStreams(streams),
      (int_mul_add_fixed_point_memory<uint64_t> **)mem_ptr,
      MUL_ADD_MODE_MUL_LOW, num_blocks, num_blocks, /*rescaling=*/0,
      /*precision=*/0, max_extra_terms, params, allocate_gpu_memory);
}

/// @brief FFI entry point for the low half of lhs[n] * rhs[n], plus the
/// caller-supplied addends. Leaves the carries alone unless asked to
/// propagate them.
/// @param result Output, n blocks; must not alias lhs or rhs.
/// @param lhs Left operand, n blocks.
/// @param rhs Right operand, n blocks.
/// @param extra_terms Radix list of num_extra_terms * n blocks, or null.
/// @param num_extra_terms Number of addends in extra_terms.
/// @param propagate_carries Returns clean carries when set, the raw column sum
/// otherwise.
/// @param mem_ptr Scratch buffer from
/// scratch_cuda_mul_low_partial_sum_64_async.
void cuda_mul_low_partial_sum_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *result,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    CudaRadixCiphertextFFI const *extra_terms, uint32_t num_extra_terms,
    bool propagate_carries, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {
  PANIC_IF_FALSE(result != lhs && result != rhs,
                 "Output and input pointers must be different for "
                 "out-of-place operations");
  host_mul_low_partial_sum<uint64_t>(
      CudaStreams(streams), result, lhs, rhs, extra_terms, num_extra_terms,
      propagate_carries, (int_mul_add_fixed_point_memory<uint64_t> *)mem_ptr,
      bsks, (uint64_t **)(ksks));
}

void cleanup_cuda_mul_low_partial_sum_64(CudaStreamsFFI streams,
                                         int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup mul_low_partial_sum")
  int_mul_add_fixed_point_memory<uint64_t> *mem_ptr =
      (int_mul_add_fixed_point_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
