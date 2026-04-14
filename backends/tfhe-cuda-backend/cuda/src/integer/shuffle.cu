#include "integer/shuffle.cuh"

uint64_t scratch_cuda_integer_bitonic_shuffle_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t key_num_radix_blocks, uint32_t data_num_radix_blocks,
    uint32_t num_values, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool data_is_signed, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch bitonic shuffle")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  uint64_t ret = scratch_cuda_integer_bitonic_shuffle<uint64_t>(
      CudaStreams(streams), (int_bitonic_shuffle_buffer<uint64_t> **)mem_ptr,
      key_num_radix_blocks, data_num_radix_blocks, num_values, params,
      data_is_signed, allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

// Drives the in-place bitonic shuffle on a vector of homomorphic integers
// keyed by separate homomorphic keys. Forwards to host_bitonic_shuffle.
// Inputs
// - keys, values: parallel pointer arrays of length num_values
// - mem_ptr: scratch from scratch_cuda_integer_bitonic_shuffle_64_async
// Operation
// host_bitonic_shuffle(keys, values, num_values, mem_ptr, bsks, ksks).
// Outputs
// - keys[], values[] permuted in place to ascending order by keys
//
void cuda_integer_bitonic_shuffle_64_async(CudaStreamsFFI streams,
                                           CudaRadixCiphertextFFI **keys,
                                           CudaRadixCiphertextFFI **values,
                                           uint32_t num_values, int8_t *mem_ptr,
                                           void *const *bsks,
                                           void *const *ksks) {

  PUSH_RANGE("bitonic shuffle")
  host_bitonic_shuffle<uint64_t>(
      CudaStreams(streams), keys, values, num_values,
      (int_bitonic_shuffle_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks);
  POP_RANGE()
}

// Releases the GPU scratch held by the bitonic shuffle buffer.
// Inputs
// - mem_ptr_void: pointer-to-pointer holding the bitonic shuffle scratch
// Operation
// reinterprets as int_bitonic_shuffle_buffer<uint64_t>, calls release()
// then delete.
// Outputs
// - *mem_ptr_void set to nullptr
//
void cleanup_cuda_integer_bitonic_shuffle_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void) {

  PUSH_RANGE("cleanup bitonic shuffle")
  int_bitonic_shuffle_buffer<uint64_t> *mem_ptr =
      (int_bitonic_shuffle_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}

uint64_t scratch_cuda_integer_oprf_bitonic_shuffle_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t key_num_radix_blocks, uint32_t data_num_radix_blocks,
    uint32_t num_values, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool data_is_signed, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch oprf bitonic shuffle")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  uint64_t ret = scratch_cuda_integer_oprf_bitonic_shuffle<uint64_t>(
      CudaStreams(streams),
      (int_oprf_bitonic_shuffle_buffer<uint64_t> **)mem_ptr,
      key_num_radix_blocks, data_num_radix_blocks, num_values, params,
      data_is_signed, allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

// Generates random sort keys via OPRF and runs a bitonic shuffle keyed by
// those keys, in a single in-place backend call.
// Inputs
// - values: pointer array of length num_values
// - seeded_lwe_input: per-block seed material for OPRF
// - mem_ptr: scratch from scratch_cuda_integer_oprf_bitonic_shuffle_64_async
// Operation
// host_oprf_bitonic_shuffle(values, num_values, seeded_lwe_input, ...).
// Outputs
// - values[] permuted uniformly at random
//
void cuda_integer_oprf_bitonic_shuffle_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI **values,
    uint32_t num_values, const void *seeded_lwe_input, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks) {

  PUSH_RANGE("oprf bitonic shuffle")
  host_oprf_bitonic_shuffle<uint64_t>(
      CudaStreams(streams), values, num_values,
      static_cast<const uint64_t *>(seeded_lwe_input),
      (int_oprf_bitonic_shuffle_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks);
  POP_RANGE()
}

// Releases the GPU scratch held by the OPRF bitonic shuffle buffer.
// Inputs
// - mem_ptr_void: pointer-to-pointer holding the OPRF bitonic shuffle scratch
// Operation
// reinterprets as int_oprf_bitonic_shuffle_buffer<uint64_t>, calls release()
// then delete.
// Outputs
// - *mem_ptr_void set to nullptr
//
void cleanup_cuda_integer_oprf_bitonic_shuffle_64(CudaStreamsFFI streams,
                                                  int8_t **mem_ptr_void) {

  PUSH_RANGE("cleanup oprf bitonic shuffle")
  int_oprf_bitonic_shuffle_buffer<uint64_t> *mem_ptr =
      (int_oprf_bitonic_shuffle_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
