#include "integer/oprf.cuh"

uint64_t scratch_cuda_integer_grouped_oprf_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks_to_process,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    uint32_t total_random_bits, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_grouped_oprf_async<uint64_t>(
      CudaStreams(streams), (int_grouped_oprf_memory<uint64_t> **)mem_ptr,
      params, num_blocks_to_process, total_random_bits, allocate_gpu_memory);
}

void cuda_integer_grouped_oprf_64_async(CudaStreamsFFI streams,
                                        CudaRadixCiphertextFFI *radix_lwe_out,
                                        const void *seeded_lwe_input,
                                        uint32_t num_blocks_to_process,
                                        int8_t *mem, void *const *bsks) {

  host_integer_grouped_oprf<uint64_t>(
      CudaStreams(streams), radix_lwe_out, (const uint64_t *)seeded_lwe_input,
      num_blocks_to_process, (int_grouped_oprf_memory<uint64_t> *)mem, bsks);
}

void cleanup_cuda_integer_grouped_oprf_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void) {

  int_grouped_oprf_memory<uint64_t> *mem_ptr =
      (int_grouped_oprf_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

/// @brief FFI entry point allocating the scratch buffer for the 64-bit
/// custom-range grouped OPRF.
///
/// @param mem_ptr Receives the newly allocated scratch buffer.
/// @param bsk_params Bootstrapping key parameters for the OPRF.
/// @param ksk_params Keyswitch key parameters for the OPRF.
/// @param num_blocks_intermediate Computed on the Rust side; scratch and
/// execute must pass the same value.
/// @param num_input_random_bits Number of random bits generated before range
/// mapping.
/// @param num_scalar_bits Bit-width of the scalar the intermediate value is
/// multiplied by.
/// @param noise_reduction_type Modulus-switch noise reduction strategy.
/// @param apply_rerand When true, allocate the re-randomization scratch; when
/// false, allocate only the plain custom-range scratch and ignore the rerand
/// parameters.
/// @param rerand_ksk_params Keyswitch key parameters for the re-randomization
/// stage (only read when apply_rerand is true).
/// @param rerand_mode Re-randomization mode selecting whether a keyswitch is
/// applied (only read when apply_rerand is true).
uint64_t scratch_cuda_integer_grouped_oprf_custom_range_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks_intermediate,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    uint32_t num_input_random_bits, uint32_t num_scalar_bits,
    PBS_MS_REDUCTION_T noise_reduction_type, bool apply_rerand,
    CudaLweKeyswitchKeyParamsFFI rerand_ksk_params, RERAND_MODE rerand_mode) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  uint64_t size_tracker = 0;

  if (apply_rerand) {
    int_radix_params rerand_params(
        PBS_TYPE::CLASSICAL, 0, 0, rerand_ksk_params.input_lwe_dimension,
        rerand_ksk_params.output_lwe_dimension, rerand_ksk_params.level_count,
        rerand_ksk_params.base_log, 0, 0, 0, message_modulus, carry_modulus,
        PBS_MS_REDUCTION_T::NO_REDUCTION);

    size_tracker =
        scratch_cuda_integer_grouped_oprf_custom_range_async<uint64_t>(
            CudaStreams(streams),
            reinterpret_cast<int_grouped_oprf_custom_range_memory<uint64_t> **>(
                mem_ptr),
            params, rerand_params, num_blocks_intermediate,
            num_input_random_bits, num_scalar_bits, rerand_mode,
            allocate_gpu_memory);
  } else {
    size_tracker =
        scratch_cuda_integer_grouped_oprf_custom_range_async<uint64_t>(
            CudaStreams(streams),
            reinterpret_cast<int_grouped_oprf_custom_range_memory<uint64_t> **>(
                mem_ptr),
            params, num_blocks_intermediate, num_input_random_bits,
            num_scalar_bits, allocate_gpu_memory);
  }

  return size_tracker;
}

/// @brief FFI entry point running the 64-bit custom-range grouped OPRF.
///
/// @param radix_lwe_out Output radix ciphertext holding the range-mapped
/// result.
/// @param num_blocks_intermediate Must match the value passed at scratch
/// allocation.
/// @param seeded_lwe_input Seeded LWE ciphertext used as the OPRF input.
/// @param decomposed_scalar Blockwise decomposition of the scalar multiplier.
/// @param has_at_least_one_set Per-scalar flag marking non-zero scalar blocks.
/// @param num_scalars Number of scalar blocks in decomposed_scalar.
/// @param shift Right-shift amount applied after the scalar multiply.
/// @param lwe_flattened_encryptions_of_zero_compact_array_in Compact array of
/// encryptions of zero consumed by the re-randomization stage (only read when
/// rerand was enabled at scratch time).
/// @param mem Pre-allocated scratch buffer for this operation.
/// @param compute_bsks Array of bootstrapping key pointers for the
/// scalar-multiply and shift stages.
/// @param rerand_ksks Array of keyswitch key pointers for the re-randomization
/// stage (only read when rerand was enabled at scratch time).
void cuda_integer_grouped_oprf_custom_range_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *radix_lwe_out,
    uint32_t num_blocks_intermediate, const void *seeded_lwe_input,
    const uint64_t *decomposed_scalar, const uint64_t *has_at_least_one_set,
    uint32_t num_scalars, uint32_t shift,
    const void *lwe_flattened_encryptions_of_zero_compact_array_in, int8_t *mem,
    void *const *bsks, void *const *compute_bsks, void *const *ksks,
    void *const *rerand_ksks) {

  host_integer_grouped_oprf_custom_range<uint64_t>(
      CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
      static_cast<const uint64_t *>(seeded_lwe_input), decomposed_scalar,
      has_at_least_one_set, num_scalars, shift,
      static_cast<const uint64_t *>(
          lwe_flattened_encryptions_of_zero_compact_array_in),
      reinterpret_cast<int_grouped_oprf_custom_range_memory<uint64_t> *>(mem),
      bsks, compute_bsks, reinterpret_cast<uint64_t *const *>(ksks),
      reinterpret_cast<uint64_t *const *>(rerand_ksks));
}

/// @brief FFI entry point releasing the custom-range grouped OPRF scratch
/// buffer.
///
/// @param mem_ptr_void Address of the scratch buffer pointer, set to nullptr
/// after release.
void cleanup_cuda_integer_grouped_oprf_custom_range_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void) {
  auto *mem_ptr =
      reinterpret_cast<int_grouped_oprf_custom_range_memory<uint64_t> *>(
          *mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
