#include "programmable_bootstrap_amortized.cuh"

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the amortized PBS on 64 bits inputs, into `buffer`. It also
 * configures SM options on the GPU in case FULLSM or PARTIALSM mode is going to
 * be used.
 */
uint64_t scratch_cuda_programmable_bootstrap_amortized_64_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  switch (polynomial_size) {
  case 256:
    size_tracker =
        scratch_programmable_bootstrap_amortized<uint64_t,
                                                 AmortizedDegree<256>>(
            static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
            glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
            allocate_gpu_memory);
    return size_tracker;
  case 512:
    size_tracker =
        scratch_programmable_bootstrap_amortized<uint64_t,
                                                 AmortizedDegree<512>>(
            static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
            glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
            allocate_gpu_memory);
    return size_tracker;
  case 1024:
    size_tracker =
        scratch_programmable_bootstrap_amortized<uint64_t,
                                                 AmortizedDegree<1024>>(
            static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
            glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
            allocate_gpu_memory);
    return size_tracker;
  case 2048:
    size_tracker =
        scratch_programmable_bootstrap_amortized<uint64_t,
                                                 AmortizedDegree<2048>>(
            static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
            glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
            allocate_gpu_memory);
    return size_tracker;
  case 4096:
    size_tracker =
        scratch_programmable_bootstrap_amortized<uint64_t,
                                                 AmortizedDegree<4096>>(
            static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
            glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
            allocate_gpu_memory);
    return size_tracker;
  case 8192:
    size_tracker =
        scratch_programmable_bootstrap_amortized<uint64_t,
                                                 AmortizedDegree<8192>>(
            static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
            glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
            allocate_gpu_memory);
    return size_tracker;
  case 16384:
    size_tracker =
        scratch_programmable_bootstrap_amortized<uint64_t,
                                                 AmortizedDegree<16384>>(
            static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
            glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
            allocate_gpu_memory);
    return size_tracker;
  default:
    PANIC("Cuda error (amortized PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

/* Perform the programmable bootstrapping on a batch of input u32 LWE
 * ciphertexts. See the corresponding operation on 64 bits for more details.
 */
void cuda_programmable_bootstrap_amortized_lwe_ciphertext_vector_32_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *pbs_buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples) {

  if (base_log > 32)
    PANIC("Cuda error (amortized PBS): base log should be > number of bits in "
          "the ciphertext representation (32)");

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap_amortized<uint32_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint32_t *)lwe_array_out,
        (uint32_t *)lwe_output_indexes, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (uint32_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 512:
    host_programmable_bootstrap_amortized<uint32_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint32_t *)lwe_array_out,
        (uint32_t *)lwe_output_indexes, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (uint32_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 1024:
    host_programmable_bootstrap_amortized<uint32_t, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint32_t *)lwe_array_out,
        (uint32_t *)lwe_output_indexes, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (uint32_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 2048:
    host_programmable_bootstrap_amortized<uint32_t, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint32_t *)lwe_array_out,
        (uint32_t *)lwe_output_indexes, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (uint32_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 4096:
    host_programmable_bootstrap_amortized<uint32_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint32_t *)lwe_array_out,
        (uint32_t *)lwe_output_indexes, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (uint32_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 8192:
    host_programmable_bootstrap_amortized<uint32_t, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint32_t *)lwe_array_out,
        (uint32_t *)lwe_output_indexes, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (uint32_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 16384:
    host_programmable_bootstrap_amortized<uint32_t, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint32_t *)lwe_array_out,
        (uint32_t *)lwe_output_indexes, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (uint32_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  default:
    PANIC("Cuda error (amortized PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

/* Perform the programmable bootstrapping on a batch of input u64 LWE
 * ciphertexts. This functions performs best for large numbers of inputs (> 10).
 * - `v_stream` is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 *  - lwe_array_out: output batch of num_samples bootstrapped ciphertexts c =
 * (a0,..an-1,b) where n is the LWE dimension
 *  - lut_vector: should hold as many luts of size polynomial_size
 * as there are input ciphertexts, but actually holds
 * num_luts vectors to reduce memory usage
 *  - lut_vector_indexes: stores the index corresponding to
 * which lut of lut_vector to use for each LWE input in
 * lwe_array_in
 *  - lwe_array_in: input batch of num_samples LWE ciphertexts, containing n
 * mask values + 1 body value
 *  - bootstrapping_key: GGSW encryption of the LWE secret key sk1
 * under secret key sk2
 * bsk = Z + sk1 H
 * where H is the gadget matrix and Z is a matrix (k+1).l
 * containing GLWE encryptions of 0 under sk2.
 * bsk is thus a tensor of size (k+1)^2.l.N.n
 * where l is the number of decomposition levels and
 * k is the GLWE dimension, N is the polynomial size for
 * GLWE. The polynomial size for GLWE and the lut
 * are the same because they have to be in the same ring
 * to be multiplied.
 * - input_lwe_dimension: size of the Torus vector used to encrypt the input
 * LWE ciphertexts - referred to as n above (~ 600)
 * - polynomial_size: size of the test polynomial (lut) and size of the
 * GLWE polynomials (~1024) (where `size` refers to the polynomial degree + 1).
 * - base_log: log of the base used for the gadget matrix - B = 2^base_log (~8)
 * - level_count: number of decomposition levels in the gadget matrix (~4)
 * - num_samples: number of encrypted input messages
 * used
 *
 * This function calls a wrapper to a device kernel that performs the
 * bootstrapping:
 * 	- the kernel is templatized based on integer discretization and
 * polynomial degree
 * 	- num_samples blocks of threads are launched, where each thread is going
 * to handle one or more polynomial coefficients at each stage:
 * 		- perform the blind rotation
 * 		- round the result
 * 		- decompose into level_count levels, then for each level:
 * 		  - switch to the FFT domain
 * 		  - multiply with the bootstrapping key
 * 		  - come back to the coefficients representation
 * 	- between each stage a synchronization of the threads is necessary
 * 	- in case the device has enough shared memory, temporary arrays used for
 * the different stages (accumulators) are stored into the shared memory
 * 	- the accumulators serve to combine the results for all decomposition
 * levels
 * 	- the constant memory (64K) is used for storing the roots of identity
 * values for the FFT
 */
void cuda_programmable_bootstrap_amortized_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *pbs_buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples) {

  if (base_log > 64)
    PANIC("Cuda error (amortized PBS): base log should be > number of bits in "
          "the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap_amortized<uint64_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t *)lwe_output_indexes, (uint64_t *)lut_vector,
        (uint64_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (uint64_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 512:
    host_programmable_bootstrap_amortized<uint64_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t *)lwe_output_indexes, (uint64_t *)lut_vector,
        (uint64_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (uint64_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 1024:
    host_programmable_bootstrap_amortized<uint64_t, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t *)lwe_output_indexes, (uint64_t *)lut_vector,
        (uint64_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (uint64_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 2048:
    host_programmable_bootstrap_amortized<uint64_t, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t *)lwe_output_indexes, (uint64_t *)lut_vector,
        (uint64_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (uint64_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 4096:
    host_programmable_bootstrap_amortized<uint64_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t *)lwe_output_indexes, (uint64_t *)lut_vector,
        (uint64_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (uint64_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 8192:
    host_programmable_bootstrap_amortized<uint64_t, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t *)lwe_output_indexes, (uint64_t *)lut_vector,
        (uint64_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (uint64_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  case 16384:
    host_programmable_bootstrap_amortized<uint64_t, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t *)lwe_output_indexes, (uint64_t *)lut_vector,
        (uint64_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (uint64_t *)lwe_input_indexes, (double2 *)bootstrapping_key, pbs_buffer,
        glwe_dimension, lwe_dimension, polynomial_size, base_log, level_count,
        num_samples);
    break;
  default:
    PANIC("Cuda error (amortized PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

/*
 * This cleanup function frees the data for the amortized PBS on GPU in
 * buffer for 32 or 64 bits inputs.
 */
void cleanup_cuda_programmable_bootstrap_amortized_64(void *stream,
                                                      uint32_t gpu_index,
                                                      int8_t **pbs_buffer) {

  // Free memory
  cuda_drop_async(*pbs_buffer, static_cast<cudaStream_t>(stream), gpu_index);
  *pbs_buffer = nullptr;
  cuda_synchronize_stream(static_cast<cudaStream_t>(stream), gpu_index);
}
