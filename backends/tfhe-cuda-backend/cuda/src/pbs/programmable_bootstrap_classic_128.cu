#include "programmable_bootstrap_classic_128.cuh"

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the PBS on 128 bits inputs, into `buffer`. It also configures SM options on
 * the GPU in case FULLSM or PARTIALSM mode is going to be used.
 */
void scratch_cuda_programmable_bootstrap_128(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  auto buffer = (pbs_buffer_128<CLASSICAL> **)pbs_buffer;
  switch (polynomial_size) {
  case 256:
    scratch_programmable_bootstrap_128<AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
    break;
  case 512:
    scratch_programmable_bootstrap_128<AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
    break;
  case 1024:
    scratch_programmable_bootstrap_128<AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
    break;
  case 2048:
    scratch_programmable_bootstrap_128<AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
    break;
  case 4096:
    scratch_programmable_bootstrap_128<AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..4096].")
  }
}

template <typename Torus>
void executor_cuda_programmable_bootstrap_lwe_ciphertext_vector_128(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double const *bootstrapping_key,
    pbs_buffer_128<CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride) {

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap_128<AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 512:
    host_programmable_bootstrap_128<AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 1024:
    host_programmable_bootstrap_128<AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 2048:
    host_programmable_bootstrap_128<AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 4096:
    host_programmable_bootstrap_128<AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..4096].")
  }
}

/* Perform bootstrapping on a batch of input u128 LWE ciphertexts.
 *
 * - `v_stream` is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 *  - lwe_array_out: output batch of num_samples bootstrapped ciphertexts c =
 * (a0,..an-1,b) where n is the LWE dimension
 *  - lut_vector: should hold as many luts of size polynomial_size
 * as there are input ciphertexts, but actually holds
 * num_luts vectors to reduce memory usage
 *  - lut_vector_indexes: stores the index corresponding to
 * which lut to use for each sample in
 * lut_vector
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
 * - lwe_dimension: size of the Torus vector used to encrypt the input
 * LWE ciphertexts - referred to as n above (~ 600)
 * - glwe_dimension: size of the polynomial vector used to encrypt the LUT
 * GLWE ciphertexts - referred to as k above. Only the value 1 is supported for
 * this parameter.
 * - polynomial_size: size of the test polynomial (lut) and size of the
 * GLWE polynomial (~1024)
 * - base_log: log base used for the gadget matrix - B = 2^base_log (~8)
 * - level_count: number of decomposition levels in the gadget matrix (~4)
 * - num_samples: number of encrypted input messages
 *
 * This function calls a wrapper to a device kernel that performs the
 * bootstrapping:
 * 	- the kernel is templatized based on integer discretization and
 * polynomial degree
 * 	- num_samples * level_count * (glwe_dimension + 1) blocks of threads are
 * launched, where each thread	is going to handle one or more polynomial
 * coefficients at each stage, for a given level of decomposition, either for
 * the LUT mask or its body:
 * 		- perform the blind rotation
 * 		- round the result
 * 		- get the decomposition for the current level
 * 		- switch to the FFT domain
 * 		- multiply with the bootstrapping key
 * 		- come back to the coefficients representation
 * 	- between each stage a synchronization of the threads is necessary (some
 * synchronizations happen at the block level, some happen between blocks, using
 * cooperative groups).
 * 	- in case the device has enough shared memory, temporary arrays used for
 * the different stages (accumulators) are stored into the shared memory
 * 	- the accumulators serve to combine the results for all decomposition
 * levels
 * 	- the constant memory (64K) is used for storing the roots of identity
 * values for the FFT
 */
void cuda_programmable_bootstrap_lwe_ciphertext_vector_128(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride) {
  if (base_log > 64)
    PANIC("Cuda error (classical PBS): base log should be <= 64")
  if ((glwe_dimension + 1) * level_count > 8)
    PANIC("Cuda error (multi-bit PBS): (k + 1)*l should be <= 8")

  pbs_buffer_128<CLASSICAL> *buffer = (pbs_buffer_128<CLASSICAL> *)mem_ptr;

  executor_cuda_programmable_bootstrap_lwe_ciphertext_vector_128<__uint128_t>(
      stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
      static_cast<const __uint128_t *>(lwe_output_indexes),
      static_cast<const __uint128_t *>(lut_vector),
      static_cast<const __uint128_t *>(lut_vector_indexes),
      static_cast<const __uint128_t *>(lwe_array_in),
      static_cast<const __uint128_t *>(lwe_input_indexes),
      static_cast<const double *>(bootstrapping_key), buffer, lwe_dimension,
      glwe_dimension, polynomial_size, base_log, level_count, num_samples,
      num_many_lut, lut_stride);
}

/*
 * This cleanup function frees the data on GPU for the PBS buffer for 32 or 64
 * bits inputs.
 */
void cleanup_cuda_programmable_bootstrap_128(void *stream, uint32_t gpu_index,
                                         int8_t **buffer) {
  auto x = (pbs_buffer_128<CLASSICAL> *)(*buffer);
  x->release(static_cast<cudaStream_t>(stream), gpu_index);
}