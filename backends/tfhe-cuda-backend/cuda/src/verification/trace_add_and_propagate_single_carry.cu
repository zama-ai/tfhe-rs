// Verification trace of host_add_and_propagate_single_carry (test builds
// only). The file compiles to nothing without VERIFICATION_TRACE.
#ifdef VERIFICATION_TRACE

#include "checked_arithmetic.h"
#include "device.h"
#include "integer/integer.h"
#include "integer/integer_utilities.h"
#include "integer/radix_ciphertext.cuh"
#include "pbs/pbs_enums.h"
#include "verification/trace.h"
#include "verification/trace_entry.h"
#include <string>
#include <vector>

namespace {

// GPU default 2_2 parameter set:
// V1_9_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.
constexpr uint32_t kMessageModulus = 4;
constexpr uint32_t kCarryModulus = 4;
constexpr uint32_t kSmallLweDimension = 920;
constexpr uint32_t kGlweDimension = 1;
constexpr uint32_t kPolynomialSize = 2048;
constexpr uint32_t kBigLweDimension = kGlweDimension * kPolynomialSize;
constexpr uint32_t kPbsBaseLog = 22;
constexpr uint32_t kPbsLevel = 1;
constexpr uint32_t kKsBaseLog = 3;
constexpr uint32_t kKsLevel = 5;
constexpr uint32_t kGroupingFactor = 4;

const char *flag_name(uint32_t flag) {
  switch (flag) {
  case outputFlag::FLAG_NONE:
    return "none";
  case outputFlag::FLAG_OVERFLOW:
    return "overflow";
  case outputFlag::FLAG_CARRY:
    return "carry";
  }
  return "unknown";
}

// Zero-filled device buffer of `count` u64.
uint64_t *zero_device_array(cudaStream_t stream, uint32_t gpu_index,
                            size_t count) {
  auto size = safe_mul_sizeof<uint64_t>(count);
  auto *ptr = (uint64_t *)cuda_malloc_async(size, stream, gpu_index);
  cuda_memset_async(ptr, 0, size, stream, gpu_index);
  return ptr;
}

// Fresh input metadata: what the Rust side declares for clean encryptions.
void set_meta(CudaRadixCiphertextFFI *ct, uint64_t degree, uint64_t noise) {
  for (uint32_t i = 0; i < ct->num_radix_blocks; i++) {
    ct->degrees[i] = degree;
    ct->noise_levels[i] = noise;
  }
}

} // namespace

uint32_t cuda_verification_trace_add_and_propagate_single_carry_64(
    const char *out_dir, uint32_t gpu_index, uint32_t num_blocks) {
  using verification::Trace;
  PANIC_IF_FALSE(num_blocks > 0,
                 "Cuda error (verification trace): num_blocks must be > 0");

  cudaStream_t stream = cuda_create_stream(gpu_index);
  void *stream_array[1] = {stream};
  uint32_t gpu_array[1] = {gpu_index};
  CudaStreamsFFI streams{stream_array, gpu_array, 1};

  CudaLweBootstrapKeyParamsFFI bsk_params{};
  bsk_params.input_lwe_dimension = kSmallLweDimension;
  bsk_params.glwe_dimension = kGlweDimension;
  bsk_params.polynomial_size = kPolynomialSize;
  bsk_params.base_log = kPbsBaseLog;
  bsk_params.level_count = kPbsLevel;
  bsk_params.big_lwe_dimension = kBigLweDimension;
  bsk_params.pbs_type = PBS_TYPE::MULTI_BIT;
  bsk_params.pbs_params.multi_bit.grouping_factor = kGroupingFactor;
  CudaLweKeyswitchKeyParamsFFI ksk_params{kBigLweDimension, kSmallLweDimension,
                                          kKsBaseLog, kKsLevel};

  // Zero keys in the device layouts the kernels expect (multi-bit BSK:
  // n * l * (k+1)^2 * N * 2^g / g words; KSK: l * (n_small+1) * n_big words).
  size_t bsk_words =
      safe_mul((size_t)kSmallLweDimension, (size_t)kPbsLevel,
               (size_t)(kGlweDimension + 1), (size_t)(kGlweDimension + 1)) *
      safe_mul((size_t)kPolynomialSize, (size_t)(1 << kGroupingFactor)) /
      kGroupingFactor;
  size_t ksk_words =
      safe_mul((size_t)kKsLevel, (size_t)(kSmallLweDimension + 1),
               (size_t)kBigLweDimension);
  void *bsks[1] = {zero_device_array(stream, gpu_index, bsk_words)};
  void *ksks[1] = {zero_device_array(stream, gpu_index, ksk_words)};

  // One trace per value of the public parameters.
  //
  //   clear -> ALLOC inputs -> BEGIN -> scratch -> op -> END -> cleanup/FREE
  uint32_t written = 0;
  for (uint32_t flag : {outputFlag::FLAG_NONE, outputFlag::FLAG_OVERFLOW,
                        outputFlag::FLAG_CARRY}) {
    for (uint32_t uses_carry : {0u, 1u}) {
      Trace::get().clear();

      // The Rust side always passes valid carry_out / carry_in blocks; the op
      // only touches them when the flag / uses_carry asks for it.
      uint64_t size_tracker = 0;
      CudaRadixCiphertextFFI lhs, rhs, carry_out, carry_in;
      create_zero_radix_ciphertext_async<uint64_t>(stream, gpu_index, &lhs,
                                                   num_blocks, kBigLweDimension,
                                                   size_tracker, true);
      create_zero_radix_ciphertext_async<uint64_t>(stream, gpu_index, &rhs,
                                                   num_blocks, kBigLweDimension,
                                                   size_tracker, true);
      create_zero_radix_ciphertext_async<uint64_t>(
          stream, gpu_index, &carry_out, 1, kBigLweDimension, size_tracker,
          true);
      create_zero_radix_ciphertext_async<uint64_t>(stream, gpu_index, &carry_in,
                                                   1, kBigLweDimension,
                                                   size_tracker, true);
      set_meta(&lhs, kMessageModulus - 1, NoiseLevel::NOMINAL);
      set_meta(&rhs, kMessageModulus - 1, NoiseLevel::NOMINAL);
      set_meta(&carry_in, 1, NoiseLevel::NOMINAL);

      std::vector<CudaRadixCiphertextFFI const *> inputs = {&lhs, &rhs};
      if (uses_carry)
        inputs.push_back(&carry_in);
      verification::begin<uint64_t>("add_and_propagate_single_carry", inputs,
                                    kMessageModulus, kCarryModulus,
                                    {flag, uses_carry, num_blocks});

      int8_t *mem = nullptr;
      scratch_cuda_add_and_propagate_single_carry_64_inplace_async(
          streams, &mem, bsk_params, ksk_params, num_blocks, kMessageModulus,
          kCarryModulus, flag, true);
      cuda_add_and_propagate_single_carry_64_inplace_async(
          streams, &lhs, &rhs, &carry_out, &carry_in, mem, bsks, ksks, flag,
          uses_carry);
      cuda_synchronize_stream(stream, gpu_index);

      std::vector<CudaRadixCiphertextFFI const *> outputs = {&lhs};
      if (flag != outputFlag::FLAG_NONE)
        outputs.push_back(&carry_out);
      verification::end<uint64_t>("add_and_propagate_single_carry", outputs);

      cleanup_cuda_add_and_propagate_single_carry_64_inplace(streams, &mem);
      for (auto *ct : {&lhs, &rhs, &carry_out, &carry_in})
        release_radix_ciphertext_async(stream, gpu_index, ct, true);
      cuda_synchronize_stream(stream, gpu_index);

      std::string path =
          std::string(out_dir) + "/add_and_propagate_single_carry_b" +
          std::to_string(num_blocks) + "_flag_" + flag_name(flag) + "_carry" +
          std::to_string(uses_carry) + ".trace";
      Trace::get().dump_text(path.c_str());
      written++;
    }
  }

  cuda_drop_async(bsks[0], stream, gpu_index);
  cuda_drop_async(ksks[0], stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  cuda_destroy_stream(stream, gpu_index);
  return written;
}

#endif // VERIFICATION_TRACE
