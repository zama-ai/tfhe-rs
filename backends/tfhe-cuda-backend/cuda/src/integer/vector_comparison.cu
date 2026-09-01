#include "integer/vector_comparison.cuh"

uint64_t scratch_cuda_unchecked_all_eq_slices_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_all_eq_slices<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_all_eq_slices_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_all_eq_slices_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI const *match_ct_ffi,
    CudaRadixCiphertextFFI const *lhs_ffi,
    CudaRadixCiphertextFFI const *rhs_ffi, uint32_t num_inputs,
    uint32_t num_blocks, int8_t *mem, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  const CudaRadixCiphertext *match_ct = &match_ct_local;
  const CudaRadixCiphertext lhs_local(*lhs_ffi);
  const CudaRadixCiphertext *lhs = &lhs_local;
  const CudaRadixCiphertext rhs_local(*rhs_ffi);
  const CudaRadixCiphertext *rhs = &rhs_local;

  PANIC_IF_FALSE(match_ct_ffi != lhs_ffi,
                 "Output and first input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(match_ct_ffi != rhs_ffi,
                 "Output and second input pointers must be different for "
                 "out-of-place operations");

  host_unchecked_all_eq_slices<uint64_t>(
      CudaStreams(streams), match_ct, lhs, rhs, num_inputs, num_blocks,
      (int_unchecked_all_eq_slices_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_all_eq_slices_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void) {
  int_unchecked_all_eq_slices_buffer<uint64_t> *mem_ptr =
      (int_unchecked_all_eq_slices_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_contains_sub_slice_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_lhs, uint32_t num_rhs,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_contains_sub_slice<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_contains_sub_slice_buffer<uint64_t> **)mem_ptr, params,
      num_lhs, num_rhs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_contains_sub_slice_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI const *match_ct_ffi,
    CudaRadixCiphertextFFI const *lhs_ffi,
    CudaRadixCiphertextFFI const *rhs_ffi, uint32_t num_rhs,
    uint32_t num_blocks, int8_t *mem, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  const CudaRadixCiphertext *match_ct = &match_ct_local;
  const CudaRadixCiphertext lhs_local(*lhs_ffi);
  const CudaRadixCiphertext *lhs = &lhs_local;
  const CudaRadixCiphertext rhs_local(*rhs_ffi);
  const CudaRadixCiphertext *rhs = &rhs_local;

  PANIC_IF_FALSE(match_ct_ffi != lhs_ffi,
                 "Output and first input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(match_ct_ffi != rhs_ffi,
                 "Output and second input pointers must be different for "
                 "out-of-place operations");

  host_unchecked_contains_sub_slice<uint64_t>(
      CudaStreams(streams), match_ct, lhs, rhs, num_rhs, num_blocks,
      (int_unchecked_contains_sub_slice_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_contains_sub_slice_64(CudaStreamsFFI streams,
                                                  int8_t **mem_ptr_void) {
  int_unchecked_contains_sub_slice_buffer<uint64_t> *mem_ptr =
      (int_unchecked_contains_sub_slice_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
