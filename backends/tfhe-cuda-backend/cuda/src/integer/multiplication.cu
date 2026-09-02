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
