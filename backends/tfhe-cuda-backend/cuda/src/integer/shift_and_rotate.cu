#include "shift_and_rotate.cuh"

uint64_t scratch_cuda_shift_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus,
    SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed, bool allocate_gpu_memory) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus);

  return scratch_cuda_shift<uint64_t>(
      CudaStreams(streams), (int_shift_buffer<uint64_t> **)mem_ptr, num_blocks,
      params, shift_type, is_signed, allocate_gpu_memory);
}

/**
 * @brief Shifts lwe_array in place by the encrypted amount lwe_shift.
 *
 * An amount of the bit width or more yields 0, or the sign of the input for
 * an arithmetic right shift.
 *
 * @param lwe_array Value to shift, without carries.
 * @param lwe_shift Encrypted amount, same block count as lwe_array.
 * @param mem_ptr Scratch from scratch_cuda_shift_64_inplace_async.
 */
void cuda_shift_64_inplace_async(CudaStreamsFFI streams,
                                 CudaRadixCiphertextFFI *lwe_array,
                                 CudaRadixCiphertextFFI const *lwe_shift,
                                 int8_t *mem_ptr, void *const *bsks,
                                 void *const *ksks) {

  host_shift_inplace<uint64_t>(CudaStreams(streams), lwe_array, lwe_shift,
                               (int_shift_buffer<uint64_t> *)mem_ptr, bsks,
                               (uint64_t **)(ksks));
}

void cleanup_cuda_shift_64_inplace(CudaStreamsFFI streams,
                                   int8_t **mem_ptr_void) {
  int_shift_buffer<uint64_t> *mem_ptr =
      (int_shift_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_rotate_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus,
    SHIFT_OR_ROTATE_TYPE rotate_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint32_t active_bits_divisor, bool allocate_gpu_memory) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus);

  return scratch_cuda_rotate<uint64_t>(
      CudaStreams(streams), (int_rotate_buffer<uint64_t> **)mem_ptr, num_blocks,
      params, rotate_type, scalar_divisor_ffi, active_bits_divisor,
      allocate_gpu_memory);
}

/**
 * @brief Rotates lwe_array in place by the encrypted amount lwe_shift.
 *
 * The divisor parameters are the clear operands of the reduction of the
 * amount, see host_reduce_rotation_amount. Bit widths that are a power of two
 * never read them, null pointers and 0 are fine there.
 *
 * @param lwe_array Value to rotate, without carries.
 * @param lwe_shift Encrypted amount, same block count as lwe_array.
 * @param mem_ptr Scratch from scratch_cuda_rotate_64_inplace_async.
 * @param scalar_divisor_ffi Magic numbers of the division by the bit width.
 * @param divisor_has_at_least_one_set Bit positions inside a block where the
 * bit width has a bit set.
 * @param decomposed_divisor Bits of the bit width, least significant first.
 * @param num_scalars_divisor Length of decomposed_divisor.
 */
void cuda_rotate_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    CudaRadixCiphertextFFI const *lwe_shift, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint64_t const *divisor_has_at_least_one_set,
    uint64_t const *decomposed_divisor, uint32_t num_scalars_divisor) {

  host_rotate_inplace<uint64_t>(CudaStreams(streams), lwe_array, lwe_shift,
                                (int_rotate_buffer<uint64_t> *)mem_ptr, bsks,
                                (uint64_t **)(ksks), scalar_divisor_ffi,
                                divisor_has_at_least_one_set,
                                decomposed_divisor, num_scalars_divisor);
}

void cleanup_cuda_rotate_64_inplace(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void) {
  int_rotate_buffer<uint64_t> *mem_ptr =
      (int_rotate_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
