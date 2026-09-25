// programmable_bootstrap_testing_128.h is included because this file DEFINES
// the per-variant entry points declared there, so the compiler can check the
// definitions against the declarations. No production path in this file calls
// them: the dispatchers below reach the flavors through the templates in the
// .cuh, the way the vanilla PBS-128 dispatcher does.
#include "pbs/programmable_bootstrap_testing_128.h"
#include "programmable_bootstrap_classic_128_halfhalf.cuh"

bool supports_cooperative_groups_on_programmable_bootstrap_128_halfhalf(
    int glwe_dimension, int polynomial_size, int max_level_count,
    int num_samples, uint32_t max_shared_memory) {
  switch (polynomial_size) {
  case 256:
    return verify_cuda_programmable_bootstrap_128_halfhalf_cg_grid_size<
        Degree<256>>(glwe_dimension, max_level_count, num_samples,
                     max_shared_memory);
  case 512:
    return verify_cuda_programmable_bootstrap_128_halfhalf_cg_grid_size<
        Degree<512>>(glwe_dimension, max_level_count, num_samples,
                     max_shared_memory);
  case 1024:
    return verify_cuda_programmable_bootstrap_128_halfhalf_cg_grid_size<
        Degree<1024>>(glwe_dimension, max_level_count, num_samples,
                      max_shared_memory);
  case 2048:
    return verify_cuda_programmable_bootstrap_128_halfhalf_cg_grid_size<
        Degree<2048>>(glwe_dimension, max_level_count, num_samples,
                      max_shared_memory);
  case 4096:
    return verify_cuda_programmable_bootstrap_128_halfhalf_cg_grid_size<
        AmortizedDegree<4096>>(glwe_dimension, max_level_count, num_samples,
                               max_shared_memory);
  default:
    PANIC("Cuda error (classical PBS128 halfhalf): unsupported polynomial "
          "size. Supported N's are powers of two in [256..4096].")
  }
}

bool supports_relaxed_on_programmable_bootstrap_128_halfhalf(
    CudaHalfhalfPbsParamsFFI p, uint32_t max_shared_memory) {
  return has_support_to_cuda_programmable_bootstrap_host_driven_tbc_128_halfhalf<
      uint64_t, Degree<PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE>>(p,
                                                             max_shared_memory);
}

uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    CudaHalfhalfPbsParamsFFI p, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  validate_halfhalf_params(p);

  // The relaxed opt-in sits above the CG > DEFAULT chain rather than inside
  // scratch_cuda_programmable_bootstrap_128_halfhalf_vector: it is not a
  // fourth tier of that automatic selection but an explicit override of it,
  // and it needs the whole parameter struct, which the vector dispatcher does
  // not carry. It shares TFHE_RS_GPU_PBS128_RELAXED_TBC with the vanilla
  // classic PBS-128 host-driven TBC flavor, so one switch turns relaxed TBC
  // arithmetic on for every 128-bit bootstrap a process runs. Relaxed DEFAULT
  // is a separate, independent switch
  // (TFHE_RS_GPU_PBS128_RELAXED_DEFAULT). Exact halfhalf TBC is not
  // implemented: FORCE_TBC without RELAXED_TBC panics rather than falling back.
  if (is_force_tbc_pbs128_requested() && !is_relaxed_tbc_pbs128_requested()) {
    PANIC(
        "Cuda error (classical PBS128 halfhalf): TFHE_RS_GPU_PBS128_FORCE_TBC "
        "asks for exact halfhalf thread-block-cluster PBS128, which is not "
        "implemented. Set TFHE_RS_GPU_PBS128_RELAXED_TBC=1 for the relaxed "
        "host-driven TBC path.");
  }
  if (is_relaxed_tbc_pbs128_requested()) {
#if CUDA_ARCH >= 900
    // Hoisted out of the macro call: the commas of the template arguments would
    // be read as macro argument separators.
    const bool is_supported =
        has_support_to_cuda_programmable_bootstrap_host_driven_tbc_128_halfhalf<
            uint64_t, Degree<PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE>>(
            p, cuda_get_max_shared_memory(gpu_index));
    // Loud rather than a silent fallback: a run that asked for the relaxed
    // flavor and quietly got the default one would report success without
    // having tested anything.
    PANIC_IF_FALSE(
        is_supported,
        "Cuda error (classical PBS128 halfhalf): "
        "TFHE_RS_GPU_PBS128_RELAXED_TBC "
        "asks for the relaxed arithmetic flavor of the 128-bit halfhalf "
        "programmable bootstrap, which is only tuned for the noise-squashing "
        "parameters on a GPU with distributed shared memory.");

    return scratch_programmable_bootstrap_host_driven_tbc_128_halfhalf<
        uint64_t, Degree<PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> **)pbs_buffer, p,
        input_lwe_ciphertext_count, allocate_gpu_memory, noise_reduction_type);
#else
    PANIC("Cuda error (classical PBS128 halfhalf): "
          "TFHE_RS_GPU_PBS128_RELAXED_TBC "
          "asks for the relaxed arithmetic flavor of the 128-bit halfhalf "
          "programmable bootstrap, which needs distributed shared memory, so "
          "compute capability 9.0 or above.");
#endif
  }

  uint32_t global_max_level = halfhalf_global_max_level(p);

  return scratch_cuda_programmable_bootstrap_128_halfhalf_vector<uint64_t>(
      stream, gpu_index,
      (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> **)pbs_buffer,
      p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
      global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
      noise_reduction_type);
}

template <typename InputTorus>
void executor_cuda_programmable_bootstrap_128_halfhalf(
    void *stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

  switch (halfhalf_params.polynomial_size) {
  case 256:
    host_programmable_bootstrap_128_halfhalf<InputTorus, Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 512:
    host_programmable_bootstrap_128_halfhalf<InputTorus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 1024:
    host_programmable_bootstrap_128_halfhalf<InputTorus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 2048:
    host_programmable_bootstrap_128_halfhalf<InputTorus, Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 4096:
    host_programmable_bootstrap_128_halfhalf<InputTorus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  default:
    PANIC("Cuda error (classical PBS128 halfhalf): unsupported polynomial "
          "size. Supported N's are powers of two in [256..4096].")
  }
}

template <typename InputTorus>
void executor_cuda_programmable_bootstrap_cg_128_halfhalf(
    void *stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

  switch (halfhalf_params.polynomial_size) {
  case 256:
    host_programmable_bootstrap_cg_128_halfhalf<InputTorus, Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 512:
    host_programmable_bootstrap_cg_128_halfhalf<InputTorus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 1024:
    host_programmable_bootstrap_cg_128_halfhalf<InputTorus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 2048:
    host_programmable_bootstrap_cg_128_halfhalf<InputTorus, Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  case 4096:
    host_programmable_bootstrap_cg_128_halfhalf<InputTorus,
                                                AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  default:
    PANIC("Cuda error (classical PBS128 halfhalf): unsupported polynomial "
          "size. Supported N's are powers of two in [256..4096].")
  }
}

#if CUDA_ARCH >= 900
// The relaxed host-driven TBC flavor is specialized for the halfhalf
// noise-squashing shape only.
template <typename InputTorus>
void executor_cuda_programmable_bootstrap_host_driven_tbc_128_halfhalf(
    void *stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

  switch (halfhalf_params.polynomial_size) {
  case PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE:
    host_programmable_bootstrap_host_driven_tbc_128_halfhalf<
        InputTorus, Degree<PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out, lut_vector,
        lwe_array_in, bootstrapping_key, buffer, halfhalf_params, num_samples);
    break;
  default:
    PANIC("Cuda error (classical PBS128 halfhalf host-driven TBC): "
          "unsupported polynomial size. Supported N for the relaxed flavor is "
          "only 2048.")
  }
}
#endif

template <typename InputTorus>
void host_programmable_bootstrap_lwe_ciphertext_vector_128_halfhalf(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    __uint128_t const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

  switch (buffer->pbs_variant) {
  case DEFAULT:
    executor_cuda_programmable_bootstrap_128_halfhalf<InputTorus>(
        stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
        lut_vector, static_cast<InputTorus const *>(lwe_array_in),
        static_cast<const double *>(bootstrapping_key), buffer, halfhalf_params,
        num_samples);
    break;
  case CG:
    executor_cuda_programmable_bootstrap_cg_128_halfhalf<InputTorus>(
        stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
        lut_vector, static_cast<InputTorus const *>(lwe_array_in),
        static_cast<const double *>(bootstrapping_key), buffer, halfhalf_params,
        num_samples);
    break;
#if CUDA_ARCH >= 900
  case TBC_HOST_DRIVEN:
    executor_cuda_programmable_bootstrap_host_driven_tbc_128_halfhalf<
        InputTorus>(stream, gpu_index,
                    static_cast<__uint128_t *>(lwe_array_out), lut_vector,
                    static_cast<InputTorus const *>(lwe_array_in),
                    static_cast<const double *>(bootstrapping_key), buffer,
                    halfhalf_params, num_samples);
    break;
#endif
  default:
    PANIC("Cuda error (PBS128 halfhalf): unknown pbs variant.")
  }
}

void cuda_programmable_bootstrap_128_halfhalf_async(
    void *streams, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *mem_ptr,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

  pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *buffer =
      (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *)mem_ptr;

  host_programmable_bootstrap_lwe_ciphertext_vector_128_halfhalf<uint64_t>(
      streams, gpu_index, lwe_array_out,
      static_cast<const __uint128_t *>(lut_vector), lwe_array_in,
      bootstrapping_key, buffer, halfhalf_params, num_samples);
}

void cleanup_cuda_programmable_bootstrap_128_halfhalf(void *stream,
                                                      uint32_t gpu_index,
                                                      int8_t **buffer) {
  auto x = (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *)(*buffer);
  x->release(static_cast<cudaStream_t>(stream), gpu_index);
  delete x;
  *buffer = nullptr;
}

// Test-only per-variant entry points for 128-bit halfhalf PBS.
// These bypass the CG > DEFAULT auto-dispatch.

uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_default_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    CudaHalfhalfPbsParamsFFI p, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  validate_halfhalf_params(p);

  uint32_t global_max_level = halfhalf_global_max_level(p);

  auto buffer = (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> **)pbs_buffer;
  switch (p.polynomial_size) {
  case 256:
    return scratch_programmable_bootstrap_128_halfhalf<uint64_t, Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 512:
    return scratch_programmable_bootstrap_128_halfhalf<uint64_t, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 1024:
    return scratch_programmable_bootstrap_128_halfhalf<uint64_t, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 2048:
    return scratch_programmable_bootstrap_128_halfhalf<uint64_t, Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 4096:
    return scratch_programmable_bootstrap_128_halfhalf<uint64_t,
                                                       AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  default:
    PANIC("Cuda error (classical PBS128 halfhalf DEFAULT test): unsupported "
          "polynomial size. Supported N's are powers of two in [256..4096].")
  }
}

void cuda_programmable_bootstrap_128_halfhalf_default_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *mem_ptr,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

  auto *buffer = (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *)mem_ptr;

  executor_cuda_programmable_bootstrap_128_halfhalf<uint64_t>(
      stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
      static_cast<const __uint128_t *>(lut_vector),
      static_cast<uint64_t const *>(lwe_array_in),
      static_cast<const double *>(bootstrapping_key), buffer, halfhalf_params,
      num_samples);
}

uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_cg_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    CudaHalfhalfPbsParamsFFI p, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  validate_halfhalf_params(p);

  uint32_t global_max_level = halfhalf_global_max_level(p);

  auto buffer = (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> **)pbs_buffer;
  switch (p.polynomial_size) {
  case 256:
    return scratch_programmable_bootstrap_cg_128_halfhalf<uint64_t,
                                                          Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 512:
    return scratch_programmable_bootstrap_cg_128_halfhalf<uint64_t,
                                                          Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 1024:
    return scratch_programmable_bootstrap_cg_128_halfhalf<uint64_t,
                                                          Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 2048:
    return scratch_programmable_bootstrap_cg_128_halfhalf<uint64_t,
                                                          Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  case 4096:
    return scratch_programmable_bootstrap_cg_128_halfhalf<
        uint64_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer,
        p.input_lwe_dimension, p.glwe_dimension, p.polynomial_size,
        global_max_level, input_lwe_ciphertext_count, allocate_gpu_memory,
        noise_reduction_type);
  default:
    PANIC("Cuda error (classical PBS128 halfhalf CG test): unsupported "
          "polynomial size. Supported N's are powers of two in [256..4096].")
  }
}

void cuda_programmable_bootstrap_128_halfhalf_cg_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *mem_ptr,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

  auto *buffer = (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *)mem_ptr;

  executor_cuda_programmable_bootstrap_cg_128_halfhalf<uint64_t>(
      stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
      static_cast<const __uint128_t *>(lut_vector),
      static_cast<uint64_t const *>(lwe_array_in),
      static_cast<const double *>(bootstrapping_key), buffer, halfhalf_params,
      num_samples);
}

// Test-only entry point for the relaxed TBC arithmetic flavor. It bypasses
// the TFHE_RS_GPU_PBS128_RELAXED_TBC opt-in so the test binary can exercise
// the flavor without the env var, which is read once per process and would
// otherwise order-couple the tests in one binary. The production path keeps
// the opt-in.
// Callers must check supports_relaxed_on_programmable_bootstrap_128_halfhalf
// first; this panics on an unsupported shape rather than falling back.

uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    CudaHalfhalfPbsParamsFFI p, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  validate_halfhalf_params(p);

#if CUDA_ARCH >= 900
  auto buffer = (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> **)pbs_buffer;
  return scratch_programmable_bootstrap_host_driven_tbc_128_halfhalf<
      uint64_t, Degree<PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE>>(
      static_cast<cudaStream_t>(stream), gpu_index, buffer, p,
      input_lwe_ciphertext_count, allocate_gpu_memory, noise_reduction_type);
#else
  (void)stream;
  (void)gpu_index;
  (void)pbs_buffer;
  (void)input_lwe_ciphertext_count;
  (void)allocate_gpu_memory;
  (void)noise_reduction_type;
  PANIC("Cuda error (classical PBS128 halfhalf): the relaxed arithmetic "
        "flavor needs distributed shared memory, so compute capability 9.0 or "
        "above.")
#endif
}

void cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *mem_ptr,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples) {

#if CUDA_ARCH >= 900
  auto *buffer = (pbs_buffer_128<uint64_t, PBS_TYPE::CLASSICAL> *)mem_ptr;

  executor_cuda_programmable_bootstrap_host_driven_tbc_128_halfhalf<uint64_t>(
      stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
      static_cast<const __uint128_t *>(lut_vector),
      static_cast<uint64_t const *>(lwe_array_in),
      static_cast<const double *>(bootstrapping_key), buffer, halfhalf_params,
      num_samples);
#else
  (void)stream;
  (void)gpu_index;
  (void)lwe_array_out;
  (void)lut_vector;
  (void)lwe_array_in;
  (void)bootstrapping_key;
  (void)mem_ptr;
  (void)halfhalf_params;
  (void)num_samples;
  PANIC("Cuda error (classical PBS128 halfhalf): the relaxed arithmetic "
        "flavor needs distributed shared memory, so compute capability 9.0 or "
        "above.")
#endif
}
