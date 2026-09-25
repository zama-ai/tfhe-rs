#include "checked_arithmetic.h"
#include "device.h"
#include "helper_multi_gpu.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <gtest/gtest.h>
#include <setup_and_teardown.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

const unsigned REPETITIONS = 2;
const unsigned SAMPLES = 50;

typedef struct {
  int input_lwe_dimension;
  int output_lwe_dimension;
  DynamicDistribution noise_distribution;
  int ksk_base_log;
  int ksk_level;
  int message_modulus;
  int carry_modulus;
  int number_of_inputs;
} KeyswitchTestParams;

// LWE decryption for the two output widths of the keyswitch.
static uint64_t decrypt_lwe(const uint64_t *ct, const uint64_t *sk, int dim) {
  uint64_t decrypted = 0;
  core_crypto_lwe_decrypt(&decrypted, ct, sk, dim);
  return decrypted;
}
// The C API only decrypts 64-bit LWEs, the 32-bit case is a plain dot product.
static uint32_t decrypt_lwe(const uint32_t *ct, const uint64_t *sk, int dim) {
  uint32_t mask = 0;
  for (int i = 0; i < dim; i++)
    mask += ct[i] * (uint32_t)sk[i];
  return ct[dim] - mask;
}

class KeyswitchTestPrimitives_u64
    : public ::testing::TestWithParam<KeyswitchTestParams> {
protected:
  int input_lwe_dimension;
  int output_lwe_dimension;
  DynamicDistribution noise_distribution;
  int ksk_base_log;
  int ksk_level;
  int message_modulus;
  int carry_modulus;
  int number_of_inputs;
  int payload_modulus;
  uint64_t delta;
  cudaStream_t stream;
  uint32_t gpu_index = 0;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  uint64_t *d_ksk_array;
  uint64_t *d_lwe_ct_out_array;
  uint64_t *d_lwe_ct_in_array;
  uint64_t *lwe_input_indexes;
  uint64_t *lwe_output_indexes;
  // 32-bit ksk and output for the 64 -> 32 flavors.
  uint32_t *d_ksk_array_u32;
  uint32_t *d_lwe_ct_out_array_u32;

  // Runs the given keyswitch flavor on every repetition and sample, then
  // decrypts the outputs with the output key and checks the decoded message.
  template <typename OutTorus>
  void run_and_check_keyswitch(
      const OutTorus *d_ksk_flavor, OutTorus *d_lwe_ct_out,
      const std::function<void(uint64_t *d_lwe_ct_in, const OutTorus *d_ksk,
                               OutTorus *d_lwe_ct_out, int eff_inputs)>
          &run_ks) {
    const uint eff_reps = is_sanitizer_run() ? 1u : REPETITIONS;
    const uint eff_samples = is_sanitizer_run() ? 1u : SAMPLES;
    const int eff_inputs =
        is_sanitizer_run() ? std::min(number_of_inputs, 2) : number_of_inputs;
    constexpr int out_bits = 8 * sizeof(OutTorus);
    const OutTorus delta_out =
        ((OutTorus)1 << (out_bits - 1)) / (OutTorus)payload_modulus;
    std::vector<OutTorus> lwe_out_ct((size_t)(output_lwe_dimension + 1) *
                                     eff_inputs);
    size_t ksk_size =
        (size_t)ksk_level * (output_lwe_dimension + 1) * input_lwe_dimension;
    for (uint r = 0; r < eff_reps; r++) {
      uint64_t *lwe_out_sk =
          lwe_sk_out_array + (ptrdiff_t)(r * output_lwe_dimension);
      const OutTorus *d_ksk = d_ksk_flavor + (ptrdiff_t)(ksk_size * r);
      for (uint s = 0; s < eff_samples; s++) {
        uint64_t *d_lwe_ct_in =
            d_lwe_ct_in_array + (ptrdiff_t)((r * SAMPLES * number_of_inputs +
                                             s * number_of_inputs) *
                                            (input_lwe_dimension + 1));
        run_ks(d_lwe_ct_in, d_ksk, d_lwe_ct_out, eff_inputs);

        cuda_memcpy_async_to_cpu(
            lwe_out_ct.data(), d_lwe_ct_out,
            safe_mul_sizeof<OutTorus>((size_t)eff_inputs,
                                      (size_t)(output_lwe_dimension + 1)),
            stream, gpu_index);
        cuda_synchronize_stream(stream, gpu_index);
        for (int i = 0; i < eff_inputs; i++) {
          uint64_t plaintext = plaintexts[r * SAMPLES * number_of_inputs +
                                          s * number_of_inputs + i];
          OutTorus decrypted =
              decrypt_lwe(lwe_out_ct.data() + i * (output_lwe_dimension + 1),
                          lwe_out_sk, output_lwe_dimension);
          // The keyswitch to a smaller torus keeps the most significant bits.
          OutTorus expected = (OutTorus)(plaintext >> (64 - out_bits));
          EXPECT_NE(decrypted, expected);
          // The bit before the message
          OutTorus rounding_bit = delta_out >> 1;
          // Compute the rounding bit
          OutTorus rounding = (decrypted & rounding_bit) << 1;
          OutTorus decoded = (decrypted + rounding) / delta_out;
          EXPECT_EQ((uint64_t)decoded, plaintext / delta);
        }
      }
    }
  }

public:
  // Test arithmetic functions
  void SetUp() {
    stream = cuda_create_stream(gpu_index);

    // TestParams
    input_lwe_dimension = (int)GetParam().input_lwe_dimension;
    output_lwe_dimension = (int)GetParam().output_lwe_dimension;
    noise_distribution = (DynamicDistribution)GetParam().noise_distribution;
    ksk_base_log = (int)GetParam().ksk_base_log;
    ksk_level = (int)GetParam().ksk_level;
    message_modulus = (int)GetParam().message_modulus;
    carry_modulus = (int)GetParam().carry_modulus;
    number_of_inputs = (int)GetParam().number_of_inputs;

    Seed seed;
    init_seed(&seed);

    keyswitch_setup(stream, gpu_index, &seed, &lwe_sk_in_array,
                    &lwe_sk_out_array, &d_ksk_array, &plaintexts,
                    &d_lwe_ct_in_array, &lwe_input_indexes, &d_lwe_ct_out_array,
                    &lwe_output_indexes, input_lwe_dimension,
                    output_lwe_dimension, noise_distribution, ksk_base_log,
                    ksk_level, message_modulus, carry_modulus, &payload_modulus,
                    &delta, number_of_inputs, REPETITIONS, SAMPLES);

    Seed ksk_seed;
    init_seed(&ksk_seed);
    generate_lwe_keyswitch_keys_u32(
        stream, gpu_index, &d_ksk_array_u32, lwe_sk_in_array, lwe_sk_out_array,
        input_lwe_dimension, output_lwe_dimension, ksk_level, ksk_base_log,
        &ksk_seed, noise_distribution, REPETITIONS);
    d_lwe_ct_out_array_u32 = (uint32_t *)cuda_malloc_async(
        safe_mul_sizeof<uint32_t>(output_lwe_dimension + 1, number_of_inputs),
        stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
  }

  void TearDown() {
    cuda_drop_async(d_ksk_array_u32, stream, gpu_index);
    cuda_drop_async(d_lwe_ct_out_array_u32, stream, gpu_index);
    keyswitch_teardown(stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array,
                       d_ksk_array, plaintexts, d_lwe_ct_in_array,
                       lwe_input_indexes, d_lwe_ct_out_array,
                       lwe_output_indexes);
  }
};

TEST_P(KeyswitchTestPrimitives_u64, keyswitch_classic) {
  run_and_check_keyswitch<uint64_t>(
      d_ksk_array, d_lwe_ct_out_array,
      [&](uint64_t *d_lwe_ct_in, const uint64_t *d_ksk, uint64_t *d_out,
          int eff_inputs) {
        cuda_keyswitch_lwe_ciphertext_vector_64_64_async(
            stream, gpu_index, (void *)d_out, (void *)lwe_output_indexes,
            (void *)d_lwe_ct_in, (void *)lwe_input_indexes, (void *)d_ksk,
            input_lwe_dimension, output_lwe_dimension, ksk_base_log, ksk_level,
            eff_inputs);
      });
}

TEST_P(KeyswitchTestPrimitives_u64, keyswitch_gemm) {
  if (!cuda_all_gpus_support_sm80()) {
    GTEST_SKIP() << "GEMM keyswitch requires compute capability 8.0.";
  }
  run_and_check_keyswitch<uint64_t>(
      d_ksk_array, d_lwe_ct_out_array,
      [&](uint64_t *d_lwe_ct_in, const uint64_t *d_ksk, uint64_t *d_out,
          int eff_inputs) {
        cuda_keyswitch_gemm_64_64_async(
            stream, gpu_index, (void *)d_out, (void *)lwe_output_indexes,
            (void *)d_lwe_ct_in, (void *)lwe_input_indexes, (void *)d_ksk,
            input_lwe_dimension, output_lwe_dimension, ksk_base_log, ksk_level,
            eff_inputs, false);
      });
}

TEST_P(KeyswitchTestPrimitives_u64, keyswitch_gemm_trivial_indexes) {
  if (!cuda_all_gpus_support_sm80()) {
    GTEST_SKIP() << "GEMM keyswitch requires compute capability 8.0.";
  }
  run_and_check_keyswitch<uint64_t>(
      d_ksk_array, d_lwe_ct_out_array,
      [&](uint64_t *d_lwe_ct_in, const uint64_t *d_ksk, uint64_t *d_out,
          int eff_inputs) {
        cuda_keyswitch_gemm_64_64_async(
            stream, gpu_index, (void *)d_out, (void *)lwe_output_indexes,
            (void *)d_lwe_ct_in, (void *)lwe_input_indexes, (void *)d_ksk,
            input_lwe_dimension, output_lwe_dimension, ksk_base_log, ksk_level,
            eff_inputs, true);
      });
}

TEST_P(KeyswitchTestPrimitives_u64, keyswitch_classic_64_32) {
  run_and_check_keyswitch<uint32_t>(
      d_ksk_array_u32, d_lwe_ct_out_array_u32,
      [&](uint64_t *d_lwe_ct_in, const uint32_t *d_ksk, uint32_t *d_out,
          int eff_inputs) {
        cuda_keyswitch_lwe_ciphertext_vector_64_32_async(
            stream, gpu_index, (void *)d_out, (void *)lwe_output_indexes,
            (void *)d_lwe_ct_in, (void *)lwe_input_indexes, (void *)d_ksk,
            input_lwe_dimension, output_lwe_dimension, ksk_base_log, ksk_level,
            eff_inputs);
      });
}

TEST_P(KeyswitchTestPrimitives_u64, keyswitch_gemm_64_32) {
  if (!cuda_all_gpus_support_sm80()) {
    GTEST_SKIP() << "GEMM keyswitch requires compute capability 8.0.";
  }
  run_and_check_keyswitch<uint32_t>(
      d_ksk_array_u32, d_lwe_ct_out_array_u32,
      [&](uint64_t *d_lwe_ct_in, const uint32_t *d_ksk, uint32_t *d_out,
          int eff_inputs) {
        cuda_keyswitch_gemm_64_32_async(
            stream, gpu_index, (void *)d_out, (void *)lwe_output_indexes,
            (void *)d_lwe_ct_in, (void *)lwe_input_indexes, (void *)d_ksk,
            input_lwe_dimension, output_lwe_dimension, ksk_base_log, ksk_level,
            eff_inputs, false);
      });
}

TEST_P(KeyswitchTestPrimitives_u64, keyswitch_gemm_64_32_trivial_indexes) {
  if (!cuda_all_gpus_support_sm80()) {
    GTEST_SKIP() << "GEMM keyswitch requires compute capability 8.0.";
  }
  run_and_check_keyswitch<uint32_t>(
      d_ksk_array_u32, d_lwe_ct_out_array_u32,
      [&](uint64_t *d_lwe_ct_in, const uint32_t *d_ksk, uint32_t *d_out,
          int eff_inputs) {
        cuda_keyswitch_gemm_64_32_async(
            stream, gpu_index, (void *)d_out, (void *)lwe_output_indexes,
            (void *)d_lwe_ct_in, (void *)lwe_input_indexes, (void *)d_ksk,
            input_lwe_dimension, output_lwe_dimension, ksk_base_log, ksk_level,
            eff_inputs, true);
      });
}

// Defines for which parameters set the PBS will be tested.
// It executes each src for all pairs on phis X qs (Cartesian product)
::testing::internal::ParamGenerator<KeyswitchTestParams> ksk_params_u64 =
    ::testing::Values(
        // n, k*N, noise_distribution, ks_base_log, ks_level,
        // message_modulus, carry_modulus, number_of_inputs
        (KeyswitchTestParams){
            1280, 567, new_gaussian_from_std_dev(sqrt(2.9802322387695312e-18)),
            3, 3, 2, 1, 10},
        (KeyswitchTestParams){
            1536, 694, new_gaussian_from_std_dev(sqrt(2.9802322387695312e-18)),
            4, 3, 2, 1, 10},
        (KeyswitchTestParams){
            2048, 769, new_gaussian_from_std_dev(sqrt(2.9802322387695312e-18)),
            4, 3, 2, 1, 10},
        (KeyswitchTestParams){
            2048, 754, new_gaussian_from_std_dev(sqrt(2.9802322387695312e-18)),
            3, 5, 2, 1, 10},
        (KeyswitchTestParams){2048, 742,
                              new_gaussian_from_std_dev(sqrt(4.9982771e-11)), 3,
                              5, 4, 1, 10},
        (KeyswitchTestParams){
            4096, 847, new_gaussian_from_std_dev(sqrt(2.9802322387695312e-18)),
            4, 4, 2, 1, 10},
        // Level count outside the usual 3..5 range.
        (KeyswitchTestParams){
            2048, 754, new_gaussian_from_std_dev(sqrt(2.9802322387695312e-18)),
            6, 2, 2, 1, 10},
        // Batch above the tiny-batch threshold of the GEMM split-K dispatch.
        (KeyswitchTestParams){
            1280, 567, new_gaussian_from_std_dev(sqrt(2.9802322387695312e-18)),
            3, 3, 2, 1, 100});

std::string printParamName(::testing::TestParamInfo<KeyswitchTestParams> p) {
  KeyswitchTestParams params = p.param;

  return "na_" + std::to_string(params.input_lwe_dimension) + "_nb_" +
         std::to_string(params.output_lwe_dimension) + "_baselog_" +
         std::to_string(params.ksk_base_log) + "_ksk_level_" +
         std::to_string(params.ksk_level) + "_inputs_" +
         std::to_string(params.number_of_inputs);
}

INSTANTIATE_TEST_CASE_P(KeyswitchInstantiation, KeyswitchTestPrimitives_u64,
                        ksk_params_u64, printParamName);
