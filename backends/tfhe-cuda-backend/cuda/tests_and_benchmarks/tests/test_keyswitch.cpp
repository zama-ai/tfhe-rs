#include "checked_arithmetic.h"
#include "device.h"
#include "helper_multi_gpu.h"
#include <cmath>
#include <cstdint>
#include <gtest/gtest.h>
#include <setup_and_teardown.h>
#include <stdio.h>
#include <stdlib.h>

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

class KeyswitchMultiGPUTestPrimitives_u64
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
  std::vector<cudaStream_t> streams;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  uint64_t *d_ksk_array;
  uint64_t *d_lwe_ct_out_array;
  uint64_t *d_lwe_ct_in_array;
  uint64_t *lwe_in_ct;
  uint64_t *lwe_out_ct;
  uint64_t *lwe_input_indexes;
  uint64_t *lwe_output_indexes;
  void *ks_tmp_buffer;

  // Data stays at gpu 0
  uint32_t gpu_index = 0;
  uint gpu_count = 0;
  uint active_gpu_count = 0;
  uint base_num_inputs_on_gpu = 0;

public:
  // Test arithmetic functions
  void SetUp() {
    // TestParams
    input_lwe_dimension = (int)GetParam().input_lwe_dimension;
    output_lwe_dimension = (int)GetParam().output_lwe_dimension;
    noise_distribution = (DynamicDistribution)GetParam().noise_distribution;
    ksk_base_log = (int)GetParam().ksk_base_log;
    ksk_level = (int)GetParam().ksk_level;
    message_modulus = (int)GetParam().message_modulus;
    carry_modulus = (int)GetParam().carry_modulus;
    number_of_inputs = (int)GetParam().number_of_inputs;

    // Enable Multi-GPU logic
    gpu_count = cuda_get_number_of_gpus();
    active_gpu_count = std::min((uint)number_of_inputs, gpu_count);
    for (uint gpu_i = 0; gpu_i < active_gpu_count; gpu_i++) {
      streams.push_back(cuda_create_stream(gpu_i));
    }

    Seed seed;
    init_seed(&seed);

    base_num_inputs_on_gpu =
        number_of_inputs / gpu_count + (number_of_inputs % gpu_count != 0);
    lwe_out_ct = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
        (size_t)(output_lwe_dimension + 1), (size_t)number_of_inputs));

    keyswitch_setup(streams[0], gpu_index, &seed, &lwe_sk_in_array,
                    &lwe_sk_out_array, &d_ksk_array, &plaintexts,
                    &d_lwe_ct_in_array, &lwe_input_indexes, &d_lwe_ct_out_array,
                    &lwe_output_indexes, &ks_tmp_buffer, input_lwe_dimension,
                    output_lwe_dimension, noise_distribution, ksk_base_log,
                    ksk_level, message_modulus, carry_modulus, &payload_modulus,
                    &delta, number_of_inputs, REPETITIONS, SAMPLES);
    cuda_synchronize_stream(streams[0], gpu_index);
  }

  void TearDown() {
    keyswitch_teardown(streams[0], gpu_index, lwe_sk_in_array, lwe_sk_out_array,
                       d_ksk_array, plaintexts, d_lwe_ct_in_array,
                       lwe_input_indexes, d_lwe_ct_out_array,
                       lwe_output_indexes, &ks_tmp_buffer);
    if (active_gpu_count > 1) {
      for (uint gpu_i = 1; gpu_i < active_gpu_count; gpu_i++) {
        cuda_destroy_stream(streams[gpu_i], gpu_i);
      }
    }
    free(lwe_out_ct);
  }
};

TEST_P(KeyswitchMultiGPUTestPrimitives_u64, keyswitch) {
  for (uint r = 0; r < REPETITIONS; r++) {
    uint64_t *lwe_out_sk =
        lwe_sk_out_array + (ptrdiff_t)(r * output_lwe_dimension);
    int ksk_size = ksk_level * (output_lwe_dimension + 1) * input_lwe_dimension;
    uint64_t *d_ksk = d_ksk_array + (ptrdiff_t)(ksk_size * r);
    for (uint s = 0; s < SAMPLES; s++) {
      uint64_t *d_lwe_ct_in =
          d_lwe_ct_in_array +
          (ptrdiff_t)((r * SAMPLES * number_of_inputs + s * number_of_inputs) *
                      (input_lwe_dimension + 1));

#pragma omp parallel for num_threads(active_gpu_count)
      for (uint gpu_i = 0; gpu_i < active_gpu_count; gpu_i++) {
        auto num_inputs = base_num_inputs_on_gpu;
        /// If the index reaches the last GPU, add the remainder of inputs/gpus
        /// to the number of inputs on the last GPU
        if (gpu_i == gpu_count - 1)
          num_inputs =
              number_of_inputs - base_num_inputs_on_gpu * (gpu_count - 1);

        auto input_lwe_start_index =
            gpu_i * base_num_inputs_on_gpu * (input_lwe_dimension + 1);
        auto output_lwe_start_index =
            gpu_i * base_num_inputs_on_gpu * (output_lwe_dimension + 1);

        auto d_lwe_ct_in_slice =
            d_lwe_ct_in + (ptrdiff_t)(input_lwe_start_index);
        auto d_lwe_ct_out =
            d_lwe_ct_out_array + (ptrdiff_t)(output_lwe_start_index);

        // Execute keyswitch
        cuda_keyswitch_gemm_lwe_ciphertext_vector_64_64(
            streams[gpu_i], gpu_i, d_lwe_ct_out, lwe_output_indexes,
            d_lwe_ct_in_slice, lwe_input_indexes, d_ksk, input_lwe_dimension,
            output_lwe_dimension, ksk_base_log, ksk_level, num_inputs,
            ks_tmp_buffer, false);
      }
      for (uint gpu_i = 0; gpu_i < active_gpu_count; gpu_i++) {
        cuda_synchronize_stream(streams[gpu_i], gpu_i);
      }
      // Copy result back
      cuda_memcpy_async_to_cpu(
          lwe_out_ct, d_lwe_ct_out_array,
          safe_mul_sizeof<uint64_t>((size_t)number_of_inputs,
                                    (size_t)(output_lwe_dimension + 1)),
          streams[0], 0);
      cuda_synchronize_stream(streams[0], 0);

      for (int i = 0; i < number_of_inputs; i++) {
        uint64_t plaintext = plaintexts[r * SAMPLES * number_of_inputs +
                                        s * number_of_inputs + i];
        uint64_t decrypted = 0;
        core_crypto_lwe_decrypt(&decrypted,
                                lwe_out_ct + i * (output_lwe_dimension + 1),
                                lwe_out_sk, output_lwe_dimension);
        ASSERT_NE(decrypted, plaintext);
        // The bit before the message
        uint64_t rounding_bit = delta >> 1;
        // Compute the rounding bit
        uint64_t rounding = (decrypted & rounding_bit) << 1;
        uint64_t decoded = (decrypted + rounding) / delta;
        ASSERT_EQ(decoded, plaintext / delta) << "Index " << i << " is wrong";
      }
    }
  }
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
  uint64_t *lwe_in_ct;
  uint64_t *lwe_out_ct;
  uint64_t *lwe_input_indexes;
  uint64_t *lwe_output_indexes;
  void *ks_tmp_buffer;

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
                    &lwe_output_indexes, &ks_tmp_buffer, input_lwe_dimension,
                    output_lwe_dimension, noise_distribution, ksk_base_log,
                    ksk_level, message_modulus, carry_modulus, &payload_modulus,
                    &delta, number_of_inputs, REPETITIONS, SAMPLES);
  }

  void TearDown() {
    keyswitch_teardown(stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array,
                       d_ksk_array, plaintexts, d_lwe_ct_in_array,
                       lwe_input_indexes, d_lwe_ct_out_array,
                       lwe_output_indexes, &ks_tmp_buffer);
  }
};

TEST_P(KeyswitchTestPrimitives_u64, keyswitch) {
  uint64_t *lwe_out_ct = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
      (size_t)(output_lwe_dimension + 1), (size_t)number_of_inputs));
  for (uint r = 0; r < REPETITIONS; r++) {
    uint64_t *lwe_out_sk =
        lwe_sk_out_array + (ptrdiff_t)(r * output_lwe_dimension);
    int ksk_size = ksk_level * (output_lwe_dimension + 1) * input_lwe_dimension;
    uint64_t *d_ksk = d_ksk_array + (ptrdiff_t)(ksk_size * r);
    for (uint s = 0; s < SAMPLES; s++) {
      uint64_t *d_lwe_ct_in =
          d_lwe_ct_in_array +
          (ptrdiff_t)((r * SAMPLES * number_of_inputs + s * number_of_inputs) *
                      (input_lwe_dimension + 1));
      // Execute keyswitch
      cuda_keyswitch_gemm_lwe_ciphertext_vector_64_64(
          stream, gpu_index, (void *)d_lwe_ct_out_array,
          (void *)lwe_output_indexes, (void *)d_lwe_ct_in,
          (void *)lwe_input_indexes, (void *)d_ksk, input_lwe_dimension,
          output_lwe_dimension, ksk_base_log, ksk_level, number_of_inputs,
          ks_tmp_buffer, false);

      // Copy result back
      cuda_memcpy_async_to_cpu(
          lwe_out_ct, d_lwe_ct_out_array,
          safe_mul_sizeof<uint64_t>((size_t)number_of_inputs,
                                    (size_t)(output_lwe_dimension + 1)),
          stream, gpu_index);
      for (int i = 0; i < number_of_inputs; i++) {
        uint64_t plaintext = plaintexts[r * SAMPLES * number_of_inputs +
                                        s * number_of_inputs + i];
        uint64_t decrypted = 0;
        core_crypto_lwe_decrypt(&decrypted,
                                lwe_out_ct + i * (output_lwe_dimension + 1),
                                lwe_out_sk, output_lwe_dimension);
        EXPECT_NE(decrypted, plaintext);
        // The bit before the message
        uint64_t rounding_bit = delta >> 1;
        // Compute the rounding bit
        uint64_t rounding = (decrypted & rounding_bit) << 1;
        uint64_t decoded = (decrypted + rounding) / delta;
        EXPECT_EQ(decoded, plaintext / delta);
      }
    }
  }
  free(lwe_out_ct);
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
            4, 4, 2, 1, 10});

std::string printParamName(::testing::TestParamInfo<KeyswitchTestParams> p) {
  KeyswitchTestParams params = p.param;

  return "na_" + std::to_string(params.input_lwe_dimension) + "_nb_" +
         std::to_string(params.output_lwe_dimension) + "_baselog_" +
         std::to_string(params.ksk_base_log) + "_ksk_level_" +
         std::to_string(params.ksk_level);
}

INSTANTIATE_TEST_CASE_P(KeyswitchInstantiation, KeyswitchTestPrimitives_u64,
                        ksk_params_u64, printParamName);
INSTANTIATE_TEST_CASE_P(KeyswitchInstantiation,
                        KeyswitchMultiGPUTestPrimitives_u64, ksk_params_u64,
                        printParamName);
