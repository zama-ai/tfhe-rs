#include "polynomial/dispatch.cuh"
#include "programmable_bootstrap_classic.cuh"

/*
 * The 64-bit classical PBS has exactly two flavors:
 *  - SPECIALIZED_2_2: the throughput-oriented kernel tuned for the 2_2
 *    parameters (N=2048, k=1, l=1). It requires the bootstrapping key in the
 *    FFT16x16x4 2_2 specialized layout.
 *  - DEFAULT: the generic split step-one/step-two implementation that works
 *    for any parameter set, with the key in the default FFT layout.
 *
 * The scratch function decides once, through supports_2_2_specialized_pbs, and
 * stores the choice in the buffer; the launch dispatches on it. The
 * bootstrapping key conversion decides through the same gate, so the key
 * layout and the kernel reading it always agree.
 */

template <typename Torus>
uint64_t scratch_cuda_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  // Degree<2048> is measured to outperform AmortizedDegree<2048> for the
  // classic PBS.
  uint64_t size_tracker = 0;
  DISPATCH_POLY_SIZE(
      polynomial_size, ClassicPBSDegreePolicy,
      size_tracker = scratch_programmable_bootstrap<Torus, Params>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type));
  // Recorded so the launch guard can compare scratch and launch parameters.
  (*buffer)->pbs_base_log = base_log;
  return size_tracker;
}

template <typename Torus>
uint64_t scratch_cuda_programmable_bootstrap_2_2_specialized(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  // The 2_2 specialized kernel keeps everything in registers and shared memory,
  // so the buffer only records the variant and the noise reduction type. Its
  // fixed attributes are applied here, once, so launches pay no driver calls.
  cuda_set_device(gpu_index);
  configure_2_2_specialized_kernel_for_base_log<Torus>(base_log, lwe_dimension,
                                                       __FILE__, __LINE__);
  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<Torus, CLASSICAL>(
      static_cast<cudaStream_t>(stream), gpu_index, lwe_dimension,
      glwe_dimension, polynomial_size, level_count, input_lwe_ciphertext_count,
      pbs_variant_tag<PBS_VARIANT::SPECIALIZED_2_2>{}, allocate_gpu_memory,
      noise_reduction_type, size_tracker);
  // Recorded so the launch guard can compare scratch and launch parameters.
  (*buffer)->pbs_base_log = base_log;
  return size_tracker;
}

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the PBS on 64 bits inputs, into `buffer`. It also configures SM options on
 * the GPU in case FULLSM or PARTIALSM mode is going to be used.
 */
uint64_t scratch_cuda_programmable_bootstrap_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  // The gate reads the compute capability of the current device.
  cuda_set_device(gpu_index);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  auto **typed_buffer = (pbs_buffer<uint64_t, CLASSICAL> **)buffer;
  uint64_t size_tracker;
  if (supports_2_2_specialized_pbs<uint64_t>(polynomial_size, glwe_dimension,
                                             level_count, lwe_dimension,
                                             base_log, max_shared_memory))
    size_tracker =
        scratch_cuda_programmable_bootstrap_2_2_specialized<uint64_t>(
            stream, gpu_index, typed_buffer, lwe_dimension, glwe_dimension,
            polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
            allocate_gpu_memory, noise_reduction_type);
  else
    size_tracker = scratch_cuda_programmable_bootstrap<uint64_t>(
        stream, gpu_index, typed_buffer, lwe_dimension, glwe_dimension,
        polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory, noise_reduction_type);
  return size_tracker;
}

template <typename Torus>
void cuda_programmable_bootstrap_lwe_ciphertext_vector_async(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride) {

  // Degree<2048> is measured to outperform AmortizedDegree<2048> for the
  // classic PBS.
  DISPATCH_POLY_SIZE(polynomial_size, ClassicPBSDegreePolicy,
                     host_programmable_bootstrap<Torus, Params>(
                         static_cast<cudaStream_t>(stream), gpu_index,
                         lwe_array_out, lwe_output_indexes, lut_vector,
                         lut_vector_indexes, lwe_array_in, lwe_input_indexes,
                         bootstrapping_key, buffer, glwe_dimension,
                         lwe_dimension, polynomial_size, base_log, level_count,
                         num_samples, num_many_lut, lut_stride));
}

template <typename Torus>
void cuda_programmable_bootstrap_2_2_specialized_lwe_ciphertext_vector_async(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride) {

  host_programmable_bootstrap_2_2_specialized<Torus>(
      static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
      lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
      lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
      lwe_dimension, polynomial_size, base_log, level_count, num_samples,
      num_many_lut, lut_stride);
}

/* Perform bootstrapping on a batch of input u64 LWE ciphertexts.
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
void cuda_programmable_bootstrap_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride) {
  if (base_log > 64)
    PANIC("Cuda error (classical PBS): base log should be <= 64")

  auto *pbs_buf = (pbs_buffer<uint64_t, CLASSICAL> *)buffer;

  check_cuda_error(cudaGetLastError());

  // The variant stored in the buffer at scratch time and the bootstrapping key
  // layout chosen at conversion time are both functions of the same gate over
  // the same parameters, so when the launch parameters match the scratch
  // parameters the kernel and the key layout agree by construction. A scratch
  // that decided with different parameters than the launch can pair a kernel
  // with the wrong key layout and silently return wrong results; fail loudly
  // instead.
  PANIC_IF_FALSE(
      pbs_buf->lwe_dimension == lwe_dimension &&
          pbs_buf->glwe_dimension == glwe_dimension &&
          pbs_buf->polynomial_size == polynomial_size &&
          pbs_buf->pbs_base_log == base_log &&
          pbs_buf->level_count == level_count,
      "Cuda error (classical PBS): the pbs buffer was allocated for "
      "(lwe_dimension=%u, glwe_dimension=%u, polynomial_size=%u, base_log=%u, "
      "level_count=%u) but launched with (lwe_dimension=%u, glwe_dimension=%u, "
      "polynomial_size=%u, base_log=%u, level_count=%u): the scratch was given "
      "different parameters than the launch.",
      pbs_buf->lwe_dimension, pbs_buf->glwe_dimension, pbs_buf->polynomial_size,
      pbs_buf->pbs_base_log, pbs_buf->level_count, lwe_dimension,
      glwe_dimension, polynomial_size, base_log, level_count);

  // The buffer's device scratch is sized for input_lwe_ciphertext_count
  // samples; launching more would index past it. Launching fewer is fine and
  // common (buffers are scratched for the maximum batch).
  PANIC_IF_FALSE(
      num_samples <= pbs_buf->input_lwe_ciphertext_count,
      "Cuda error (classical PBS): the pbs buffer was allocated for %u "
      "samples but launched with num_samples=%u.",
      pbs_buf->input_lwe_ciphertext_count, num_samples);

  switch (pbs_buf->pbs_variant) {
  case PBS_VARIANT::SPECIALIZED_2_2:
    cuda_programmable_bootstrap_2_2_specialized_lwe_ciphertext_vector_async<
        uint64_t>(stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
                  static_cast<const uint64_t *>(lwe_output_indexes),
                  static_cast<const uint64_t *>(lut_vector),
                  static_cast<const uint64_t *>(lut_vector_indexes),
                  static_cast<const uint64_t *>(lwe_array_in),
                  static_cast<const uint64_t *>(lwe_input_indexes),
                  static_cast<const double2 *>(bootstrapping_key), pbs_buf,
                  lwe_dimension, glwe_dimension, polynomial_size, base_log,
                  level_count, num_samples, num_many_lut, lut_stride);
    break;
  case PBS_VARIANT::DEFAULT:
    cuda_programmable_bootstrap_lwe_ciphertext_vector_async<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_output_indexes),
        static_cast<const uint64_t *>(lut_vector),
        static_cast<const uint64_t *>(lut_vector_indexes),
        static_cast<const uint64_t *>(lwe_array_in),
        static_cast<const uint64_t *>(lwe_input_indexes),
        static_cast<const double2 *>(bootstrapping_key), pbs_buf, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (PBS): unknown pbs variant.")
  }
}

// Test-only entry point: builds a DEFAULT buffer regardless of what the
// automatic selection would pick, so the generic split kernels can be tested
// on parameters the 2_2 specialized kernel supports (with a key converted to
// the default layout).
uint64_t scratch_cuda_programmable_bootstrap_default_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  return scratch_cuda_programmable_bootstrap<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)buffer,
      lwe_dimension, glwe_dimension, polynomial_size, base_log, level_count,
      input_lwe_ciphertext_count, allocate_gpu_memory, noise_reduction_type);
}

// Test-only entry point: launches the DEFAULT (split step-one/step-two)
// kernels directly, regardless of what the automatic selection would pick.
void cuda_programmable_bootstrap_default_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride) {
  if (base_log > 64)
    PANIC("Cuda error (classical PBS): base log should be <= 64")

  pbs_buffer<uint64_t, CLASSICAL> *buffer =
      (pbs_buffer<uint64_t, CLASSICAL> *)mem_ptr;
  PANIC_IF_FALSE(buffer->pbs_variant == PBS_VARIANT::DEFAULT,
                 "Cuda error (classical PBS): expected a DEFAULT buffer.");

  cuda_programmable_bootstrap_lwe_ciphertext_vector_async<uint64_t>(
      stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_output_indexes),
      static_cast<const uint64_t *>(lut_vector),
      static_cast<const uint64_t *>(lut_vector_indexes),
      static_cast<const uint64_t *>(lwe_array_in),
      static_cast<const uint64_t *>(lwe_input_indexes),
      static_cast<const double2 *>(bootstrapping_key), buffer, lwe_dimension,
      glwe_dimension, polynomial_size, base_log, level_count, num_samples,
      num_many_lut, lut_stride);
}

// Test-only entry point: builds a SPECIALIZED_2_2 buffer, bypassing the compute
// capability policy of the automatic selection (the hard parameter and shared
// memory constraints still apply).
uint64_t scratch_cuda_programmable_bootstrap_2_2_specialized_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  cuda_set_device(gpu_index);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  PANIC_IF_FALSE(pbs_2_2_specialized_params_checker<uint64_t>(
                     polynomial_size, glwe_dimension, level_count,
                     lwe_dimension, base_log, max_shared_memory),
                 "Cuda error (classical PBS): 2_2 specialized scratch requires "
                 "(N=2048, level_count=1, glwe_dimension=1, lwe_dimension <= "
                 "%u, base_log in [%u, %u], sufficient shared memory).",
                 SPECIALIZED_2_2_PARAMS_MAX_LWE_DIMENSION,
                 SPECIALIZED_2_2_PARAMS_MIN_BASE_LOG,
                 SPECIALIZED_2_2_PARAMS_MAX_BASE_LOG);
  return scratch_cuda_programmable_bootstrap_2_2_specialized<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)buffer,
      lwe_dimension, glwe_dimension, polynomial_size, base_log, level_count,
      input_lwe_ciphertext_count, allocate_gpu_memory, noise_reduction_type);
}

// Test-only entry point: launches the SPECIALIZED_2_2 (throughput-oriented)
// kernel directly. The key must have been converted to the 2_2 specialized
// layout.
void cuda_programmable_bootstrap_2_2_specialized_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride) {
  if (base_log > 64)
    PANIC("Cuda error (classical PBS): base log should be <= 64")

  pbs_buffer<uint64_t, CLASSICAL> *buffer =
      (pbs_buffer<uint64_t, CLASSICAL> *)mem_ptr;
  PANIC_IF_FALSE(
      buffer->pbs_variant == PBS_VARIANT::SPECIALIZED_2_2,
      "Cuda error (classical PBS): expected a SPECIALIZED_2_2 buffer.");

  cuda_programmable_bootstrap_2_2_specialized_lwe_ciphertext_vector_async<
      uint64_t>(stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
                static_cast<const uint64_t *>(lwe_output_indexes),
                static_cast<const uint64_t *>(lut_vector),
                static_cast<const uint64_t *>(lut_vector_indexes),
                static_cast<const uint64_t *>(lwe_array_in),
                static_cast<const uint64_t *>(lwe_input_indexes),
                static_cast<const double2 *>(bootstrapping_key), buffer,
                lwe_dimension, glwe_dimension, polynomial_size, base_log,
                level_count, num_samples, num_many_lut, lut_stride);
}

/*
 * This cleanup function frees the data on GPU for the PBS buffer for 64
 * bits inputs.
 */
void cleanup_cuda_programmable_bootstrap_64(void *stream, uint32_t gpu_index,
                                            int8_t **buffer) {
  auto *pbs_buf = (pbs_buffer<uint64_t, CLASSICAL> *)(*buffer);
  pbs_buf->release(static_cast<cudaStream_t>(stream), gpu_index);
  delete pbs_buf;
  *buffer = nullptr;
}

template bool pbs_2_2_specialized_params_checker<uint64_t>(
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count,
    uint32_t lwe_dimension, uint32_t base_log, uint32_t max_shared_memory);

template bool supports_2_2_specialized_pbs<uint64_t>(
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count,
    uint32_t lwe_dimension, uint32_t base_log, uint32_t max_shared_memory);
