#include "integer/vector_comparison.cuh"
#include <vector>

static inline bool ffi_alias_in_vec(CudaRadixCiphertextFFI const *p,
                                    VecCudaRadixCiphertextFFI const *vec) {
  return p >= vec->ptr && p < vec->ptr + vec->num_ciphertexts;
}

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
    VecCudaRadixCiphertextFFI const *lhs_ffi,
    VecCudaRadixCiphertextFFI const *rhs_ffi,
    uint32_t num_blocks, int8_t *mem, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  const CudaRadixCiphertext *match_ct = &match_ct_local;

  std::vector<CudaRadixCiphertext> lhs_storage;
  lhs_storage.reserve(lhs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < lhs_ffi->num_ciphertexts; i++) {
    lhs_storage.emplace_back(lhs_ffi->ptr[i]);
  }

  std::vector<CudaRadixCiphertext> rhs_storage;
  rhs_storage.reserve(rhs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < rhs_ffi->num_ciphertexts; i++) {
    rhs_storage.emplace_back(rhs_ffi->ptr[i]);
  }

  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, lhs_ffi),
                 "Output and first input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, rhs_ffi),
                 "Output and second input pointers must be different for "
                 "out-of-place operations");

  host_unchecked_all_eq_slices<uint64_t>(
      CudaStreams(streams), match_ct, lhs_storage.data(), rhs_storage.data(),
      lhs_ffi->num_ciphertexts, num_blocks,
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
    VecCudaRadixCiphertextFFI const *lhs_ffi,
    VecCudaRadixCiphertextFFI const *rhs_ffi,
    uint32_t num_blocks, int8_t *mem, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  const CudaRadixCiphertext *match_ct = &match_ct_local;

  std::vector<CudaRadixCiphertext> lhs_storage;
  lhs_storage.reserve(lhs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < lhs_ffi->num_ciphertexts; i++) {
    lhs_storage.emplace_back(lhs_ffi->ptr[i]);
  }

  std::vector<CudaRadixCiphertext> rhs_storage;
  rhs_storage.reserve(rhs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < rhs_ffi->num_ciphertexts; i++) {
    rhs_storage.emplace_back(rhs_ffi->ptr[i]);
  }

  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, lhs_ffi),
                 "Output and first input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, rhs_ffi),
                 "Output and second input pointers must be different for "
                 "out-of-place operations");

  host_unchecked_contains_sub_slice<uint64_t>(
      CudaStreams(streams), match_ct, lhs_storage.data(), rhs_storage.data(),
      rhs_ffi->num_ciphertexts, num_blocks,
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
