#include "checked_arithmetic.h"
#include "device.h"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <gtest/gtest.h>
#include <setup_and_teardown.h>
#include <utils.h>

typedef struct {
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  DynamicDistribution lwe_noise_distribution;
  DynamicDistribution glwe_noise_distribution;
  int pbs_base_log;
  int pbs_level;
  int message_modulus;
  int carry_modulus;
  int number_of_inputs;
  int grouping_factor;
  int repetitions;
  int samples;
} MultiBitProgrammableBootstrapTestParams;

class MultiBitProgrammableBootstrapTestPrimitives_u64
    : public ::testing::TestWithParam<MultiBitProgrammableBootstrapTestParams> {
protected:
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  DynamicDistribution lwe_noise_distribution;
  DynamicDistribution glwe_noise_distribution;
  int pbs_base_log;
  int pbs_level;
  int message_modulus;
  int carry_modulus;
  int payload_modulus;
  int number_of_inputs;
  int grouping_factor;
  uint64_t delta;
  cudaStream_t stream;
  uint32_t gpu_index = 0;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  uint64_t *d_bsk_array;
  uint64_t *d_lut_pbs_identity;
  uint64_t *d_lut_pbs_indexes;
  uint64_t *d_lwe_ct_in_array;
  uint64_t *d_lwe_ct_out_array;
  uint64_t *lwe_ct_out_array;
  uint64_t *d_lwe_input_indexes;
  uint64_t *d_lwe_output_indexes;
  int8_t *pbs_buffer;

  int repetitions;
  int samples;

public:
  void SetUp() {
    stream = cuda_create_stream(gpu_index);

    // TestParams
    lwe_dimension = (int)GetParam().lwe_dimension;
    glwe_dimension = (int)GetParam().glwe_dimension;
    polynomial_size = (int)GetParam().polynomial_size;
    grouping_factor = (int)GetParam().grouping_factor;
    lwe_noise_distribution =
        (DynamicDistribution)GetParam().lwe_noise_distribution;
    glwe_noise_distribution =
        (DynamicDistribution)GetParam().glwe_noise_distribution;
    pbs_base_log = (int)GetParam().pbs_base_log;
    pbs_level = (int)GetParam().pbs_level;
    message_modulus = (int)GetParam().message_modulus;
    carry_modulus = (int)GetParam().carry_modulus;
    number_of_inputs = (int)GetParam().number_of_inputs;

    Seed seed;
    init_seed(&seed);

    repetitions = (int)GetParam().repetitions;
    samples = (int)GetParam().samples;

    programmable_bootstrap_multibit_setup(
        stream, gpu_index, &seed, &lwe_sk_in_array, &lwe_sk_out_array,
        &d_bsk_array, &plaintexts, &d_lut_pbs_identity, &d_lut_pbs_indexes,
        &d_lwe_ct_in_array, &d_lwe_input_indexes, &d_lwe_ct_out_array,
        &d_lwe_output_indexes, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, lwe_noise_distribution, glwe_noise_distribution,
        pbs_base_log, pbs_level, message_modulus, carry_modulus,
        &payload_modulus, &delta, number_of_inputs, repetitions, samples);

    scratch_cuda_multi_bit_programmable_bootstrap_64_async(
        stream, gpu_index, &pbs_buffer, glwe_dimension, polynomial_size,
        pbs_level, number_of_inputs, true);

    lwe_ct_out_array = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
        safe_mul((size_t)glwe_dimension, (size_t)polynomial_size) + 1,
        (size_t)number_of_inputs));
  }

  void TearDown() {
    free(lwe_ct_out_array);

    cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                     &pbs_buffer);
    programmable_bootstrap_multibit_teardown(
        stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array, d_bsk_array,
        plaintexts, d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_lwe_ct_out_array, d_lwe_output_indexes);
  }
};

TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64,
       multi_bit_programmable_bootstrap) {

  int bsk_size = (lwe_dimension / grouping_factor) * pbs_level *
                 (glwe_dimension + 1) * (glwe_dimension + 1) * polynomial_size *
                 (1 << grouping_factor);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (int r = 0; r < repetitions; r++) {
    uint64_t *d_bsk = d_bsk_array + (ptrdiff_t)(bsk_size * r);
    uint64_t *lwe_sk_out =
        lwe_sk_out_array + (ptrdiff_t)(r * glwe_dimension * polynomial_size);
    for (int s = 0; s < samples; s++) {
      uint64_t *d_lwe_ct_in =
          d_lwe_ct_in_array +
          (ptrdiff_t)((r * samples * number_of_inputs + s * number_of_inputs) *
                      (lwe_dimension + 1));
      // Execute PBS
      cuda_multi_bit_programmable_bootstrap_64_async(
          stream, gpu_index, (void *)d_lwe_ct_out_array,
          (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
          (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in,
          (void *)d_lwe_input_indexes, (void *)d_bsk, pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
          pbs_level, number_of_inputs, num_many_lut, lut_stride);

      // Copy result to the host memory
      cuda_memcpy_async_to_cpu(
          lwe_ct_out_array, d_lwe_ct_out_array,
          safe_mul_sizeof<uint64_t>(
              safe_mul((size_t)glwe_dimension, (size_t)polynomial_size) + 1,
              (size_t)number_of_inputs),
          stream, gpu_index);

      for (int j = 0; j < number_of_inputs; j++) {
        uint64_t *result =
            lwe_ct_out_array +
            (ptrdiff_t)(j * (glwe_dimension * polynomial_size + 1));
        uint64_t plaintext = plaintexts[r * samples * number_of_inputs +
                                        s * number_of_inputs + j];
        uint64_t decrypted = 0;
        core_crypto_lwe_decrypt(&decrypted, result, lwe_sk_out,
                                glwe_dimension * polynomial_size);

        EXPECT_NE(decrypted, plaintext)
            << "Repetition: " << r << ", sample: " << s << ", input: " << j;

        // The bit before the message
        uint64_t rounding_bit = delta >> 1;

        // Compute the rounding bit
        uint64_t rounding = (decrypted & rounding_bit) << 1;
        uint64_t decoded = (decrypted + rounding) / delta;
        EXPECT_EQ(decoded, plaintext / delta)
            << "Repetition: " << r << ", sample: " << s << ", input: " << j;
      }
    }
  }
}

/**
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  DynamicDistribution lwe_noise_distribution;
  DynamicDistribution glwe_noise_distribution;
  int pbs_base_log;
  int pbs_level;
  int message_modulus;
  int carry_modulus;
  int number_of_inputs;
  int grouping_factor;
  int repetitions;
  int samples;
 */
// Defines for which parameters set the PBS will be tested.
// It executes each src for all pairs on phis X qs (Cartesian product)
::testing::internal::ParamGenerator<MultiBitProgrammableBootstrapTestParams>
    multipbs_params_u64 = ::testing::Values(
        // V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        (MultiBitProgrammableBootstrapTestParams){
            918, 1, 4096, new_t_uniform(45), new_t_uniform(3), 21, 1, 4, 4, 100,
            2, 1, 1},
        // V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        (MultiBitProgrammableBootstrapTestParams){
            879, 1, 2048, new_t_uniform(46), new_t_uniform(17), 14, 2, 4, 4,
            100, 3, 1, 1},
        // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        (MultiBitProgrammableBootstrapTestParams){
            920, 1, 2048, new_t_uniform(45), new_t_uniform(17), 22, 1, 4, 4,
            100, 4, 1, 1},
        // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128
        // This test is here only to be sure we don't break support to
        // 8192-degree polynomials
        (MultiBitProgrammableBootstrapTestParams){
            1040, 1, 8192, new_t_uniform(42), new_t_uniform(3), 14, 2, 4, 4,
            100, 4, 1, 1});

std::string printParamName(
    ::testing::TestParamInfo<MultiBitProgrammableBootstrapTestParams> p) {
  MultiBitProgrammableBootstrapTestParams params = p.param;

  return "n_" + std::to_string(params.lwe_dimension) + "_k_" +
         std::to_string(params.glwe_dimension) + "_N_" +
         std::to_string(params.polynomial_size) + "_pbs_base_log_" +
         std::to_string(params.pbs_base_log) + "_pbs_level_" +
         std::to_string(params.pbs_level) + "_grouping_factor_" +
         std::to_string(params.grouping_factor) + "_number_of_inputs_" +
         std::to_string(params.number_of_inputs);
}

INSTANTIATE_TEST_CASE_P(MultiBitProgrammableBootstrapInstantiation,
                        MultiBitProgrammableBootstrapTestPrimitives_u64,
                        multipbs_params_u64, printParamName);
