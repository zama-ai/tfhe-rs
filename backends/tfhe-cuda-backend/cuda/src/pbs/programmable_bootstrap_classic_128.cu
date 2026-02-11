#include "programmable_bootstrap_classic_128.cuh"

bool has_support_to_cuda_programmable_bootstrap_128_cg(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t num_samples, uint32_t max_shared_memory) {
  return supports_cooperative_groups_on_programmable_bootstrap_128(
      glwe_dimension, polynomial_size, level_count, num_samples,
      max_shared_memory);
}

uint64_t scratch_cuda_programmable_bootstrap_128_vector_64(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  return scratch_cuda_programmable_bootstrap_128_vector<uint64_t>(
      stream, gpu_index,
      (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> **)pbs_buffer,
      lwe_dimension, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, allocate_gpu_memory, noise_reduction_type);
}

uint64_t scratch_cuda_programmable_bootstrap_128_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  return scratch_cuda_programmable_bootstrap_128_vector_64(
      stream, gpu_index, pbs_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, level_count, input_lwe_ciphertext_count,
      allocate_gpu_memory, noise_reduction_type);
}

template <typename InputTorus>
void executor_cuda_programmable_bootstrap_128(
    void *stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples) {

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap_128<InputTorus, Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 512:
    host_programmable_bootstrap_128<InputTorus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 1024:
    host_programmable_bootstrap_128<InputTorus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 2048:
    host_programmable_bootstrap_128<InputTorus, Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    host_programmable_bootstrap_128<InputTorus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  default:
    PANIC("Cuda error (classical PBS128): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..4096].")
  }
}

template <typename InputTorus>
void executor_cuda_programmable_bootstrap_cg_lwe_ciphertext_vector_128(
    void *stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples) {

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap_cg_128<InputTorus, Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 512:
    host_programmable_bootstrap_cg_128<InputTorus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 1024:
    host_programmable_bootstrap_cg_128<InputTorus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 2048:
    host_programmable_bootstrap_cg_128<InputTorus, Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    host_programmable_bootstrap_cg_128<InputTorus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
        polynomial_size, base_log, level_count, num_samples);
    break;
  default:
    PANIC("Cuda error (classical PBS128): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..4096].")
  }
}

template <typename InputTorus>
void host_programmable_bootstrap_lwe_ciphertext_vector_128(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    __uint128_t const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples) {
  if (base_log > 64)
    PANIC("Cuda error (classical PBS): base log should be <= 64")

  switch (buffer->pbs_variant) {
  case DEFAULT:
    executor_cuda_programmable_bootstrap_128<InputTorus>(
        stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
        lut_vector, static_cast<InputTorus const *>(lwe_array_in),
        static_cast<const double *>(bootstrapping_key), buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples);
    break;
  case CG:
    executor_cuda_programmable_bootstrap_cg_lwe_ciphertext_vector_128<
        InputTorus>(
        stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
        lut_vector, static_cast<InputTorus const *>(lwe_array_in),
        static_cast<const double *>(bootstrapping_key), buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples);
    break;
  default:
    PANIC("Cuda error (PBS): unknown pbs variant.")
  }
}

/* Perform bootstrapping on a batch of input u128 LWE ciphertexts, storing the
 * result in the same index for each ciphertext.
 *
 * - `v_stream` is a void pointer to the CUDA stream used in the kernel launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 * - `lwe_array_out`: output batch of `num_samples` bootstrapped ciphertexts
 *   c = (a0, .., a(n−1), b), where n is the LWE dimension
 * - `lut_vector`: must contain exactly one LUT (of size `polynomial_size`) that
 *   will be applied uniformly to every input ciphertext
 * - `lwe_array_in`: input batch of `num_samples` LWE ciphertexts, each
 * containing n mask values + 1 body value
 * - `bootstrapping_key`: GGSW encryption of the LWE secret key sk1 under secret
 * key sk2
 *
 *    bsk = Z + sk1 * H
 *
 *   where H is the gadget matrix and Z is a matrix (k+1)*l containing GLWE
 * encryptions of 0 under sk2. bsk is thus a tensor of size (k+1)^2 * l * N * n,
 * where l is the number of decomposition levels, k is the GLWE dimension, and N
 * is the polynomial size. (The polynomial size for GLWE and the LUT must match
 * so they live in the same ring.)
 *
 * - `lwe_dimension`: size of the Torus vector used to encrypt the input LWE
 * ciphertexts (referred to as n, typically ~600)
 * - `glwe_dimension`: size of the polynomial vector used to encrypt the LUT
 * GLWE ciphertexts (referred to as k). Currently only k=1 is supported.
 * - `polynomial_size`: size of the test polynomial (LUT) and the GLWE
 * polynomial (~1024)
 * - `base_log`: logarithm of the base used for the gadget matrix (B =
 * 2^base_log, ~8)
 * - `level_count`: number of decomposition levels in the gadget matrix (~4)
 * - `num_samples`: number of encrypted input messages
 *
 * This function calls a wrapper to a device kernel that performs the
 * bootstrapping:
 *   - The kernel is templated based on integer discretization and polynomial
 * degree.
 *   - `num_samples * level_count * (glwe_dimension + 1)` blocks of threads are
 *     launched, where each thread handles one or more polynomial coefficients
 * at each stage (for a given decomposition level), either for the LUT mask or
 * its body: • Perform the blind rotation • Round the result • Decompose the
 * current level • Switch to the FFT domain • Multiply with the bootstrapping
 * key • Come back to the coefficient representation
 *   - Between stages, some synchronizations happen at block level and between
 * blocks (using cooperative groups).
 *   - If the device has sufficient shared memory, temporary arrays for
 * intermediate results (accumulators) are stored in shared memory.
 *   - These accumulators serve to combine the results for all decomposition
 * levels.
 *   - The 64 KB of constant memory is used for storing the roots of unity for
 * the FFT.
 */

void cuda_programmable_bootstrap_128_async(
    void *streams, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *mem_ptr, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples) {
  pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *buffer =
      (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *)mem_ptr;

  host_programmable_bootstrap_lwe_ciphertext_vector_128<uint64_t>(
      streams, gpu_index, lwe_array_out,
      static_cast<const __uint128_t *>(lut_vector), lwe_array_in,
      bootstrapping_key, buffer, lwe_dimension, glwe_dimension, polynomial_size,
      base_log, level_count, num_samples);
}

/*
 * This cleanup function frees the data on GPU for the PBS buffer for 32 or 64
 * bits inputs.
 */
void cleanup_cuda_programmable_bootstrap_128(void *stream, uint32_t gpu_index,
                                             int8_t **buffer) {
  auto x = (pbs_buffer_128<__uint128_t, PBS_TYPE::CLASSICAL> *)(*buffer);
  x->release(static_cast<cudaStream_t>(stream), gpu_index);
  delete x;
  *buffer = nullptr;
}
