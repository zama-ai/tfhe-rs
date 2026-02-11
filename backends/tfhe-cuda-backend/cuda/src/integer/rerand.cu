#include "rerand.cuh"

extern "C" {
uint64_t scratch_cuda_rerand_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory) {
  PUSH_RANGE("scratch rerand")
  int_radix_params params(PBS_TYPE::CLASSICAL, 0, 0, big_lwe_dimension,
                          small_lwe_dimension, ks_level, ks_base_log, 0, 0, 0,
                          message_modulus, carry_modulus,
                          PBS_MS_REDUCTION_T::NO_REDUCTION);

  uint64_t ret = scratch_cuda_rerand<uint64_t>(
      CudaStreams(streams), (int_rerand_mem<uint64_t> **)mem_ptr,
      lwe_ciphertext_count, params, allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

/* Executes the re-randomization procedure, adding encryptions of zero to each
 * element of an array of LWE ciphertexts. This method expects the encryptions
 * of zero to be provided as input in the format of a flattened compact
 * ciphertext list, generated using a compact public key.
 */
void cuda_rerand_64_async(
    CudaStreamsFFI streams, void *lwe_array,
    const void *lwe_flattened_encryptions_of_zero_compact_array_in,
    int8_t *mem_ptr, void *const *ksk) {

  auto rerand_buffer = reinterpret_cast<int_rerand_mem<uint64_t> *>(mem_ptr);

  switch (rerand_buffer->params.big_lwe_dimension) {
  case 256:
    host_rerand_inplace<uint64_t, AmortizedDegree<256>>(
        streams, static_cast<uint64_t *>(lwe_array),
        static_cast<const uint64_t *>(
            lwe_flattened_encryptions_of_zero_compact_array_in),
        (uint64_t **)(ksk), rerand_buffer);
    break;
  case 512:
    host_rerand_inplace<uint64_t, AmortizedDegree<512>>(
        streams, static_cast<uint64_t *>(lwe_array),
        static_cast<const uint64_t *>(
            lwe_flattened_encryptions_of_zero_compact_array_in),
        (uint64_t **)(ksk), rerand_buffer);
    break;
  case 1024:
    host_rerand_inplace<uint64_t, AmortizedDegree<1024>>(
        streams, static_cast<uint64_t *>(lwe_array),
        static_cast<const uint64_t *>(
            lwe_flattened_encryptions_of_zero_compact_array_in),
        (uint64_t **)(ksk), rerand_buffer);
    break;
  case 2048:
    host_rerand_inplace<uint64_t, AmortizedDegree<2048>>(
        streams, static_cast<uint64_t *>(lwe_array),
        static_cast<const uint64_t *>(
            lwe_flattened_encryptions_of_zero_compact_array_in),
        (uint64_t **)(ksk), rerand_buffer);
    break;
  case 4096:
    host_rerand_inplace<uint64_t, AmortizedDegree<4096>>(
        streams, static_cast<uint64_t *>(lwe_array),
        static_cast<const uint64_t *>(
            lwe_flattened_encryptions_of_zero_compact_array_in),
        (uint64_t **)(ksk), rerand_buffer);
    break;
  case 8192:
    host_rerand_inplace<uint64_t, AmortizedDegree<8192>>(
        streams, static_cast<uint64_t *>(lwe_array),
        static_cast<const uint64_t *>(
            lwe_flattened_encryptions_of_zero_compact_array_in),
        (uint64_t **)(ksk), rerand_buffer);
    break;
  case 16384:
    host_rerand_inplace<uint64_t, AmortizedDegree<16384>>(
        streams, static_cast<uint64_t *>(lwe_array),
        static_cast<const uint64_t *>(
            lwe_flattened_encryptions_of_zero_compact_array_in),
        (uint64_t **)(ksk), rerand_buffer);
    break;
  default:
    PANIC("CUDA error: lwe_dimension not supported."
          "Supported n's are powers of two"
          " in the interval [256..16384].");
    break;
  }
}

void cleanup_cuda_rerand_64(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup rerand")
  int_rerand_mem<uint64_t> *mem_ptr =
      (int_rerand_mem<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
}
