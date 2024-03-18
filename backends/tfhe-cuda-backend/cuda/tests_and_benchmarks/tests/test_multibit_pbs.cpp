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
  cuda_stream_t *stream;
  int gpu_index = 0;
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
        stream, &seed, &lwe_sk_in_array, &lwe_sk_out_array, &d_bsk_array,
        &plaintexts, &d_lut_pbs_identity, &d_lut_pbs_indexes,
        &d_lwe_ct_in_array, &d_lwe_input_indexes, &d_lwe_ct_out_array,
        &d_lwe_output_indexes, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, lwe_noise_distribution, glwe_noise_distribution,
        pbs_base_log, pbs_level, message_modulus, carry_modulus,
        &payload_modulus, &delta, number_of_inputs, repetitions, samples);

    scratch_cuda_multi_bit_programmable_bootstrap_64(
        stream, &pbs_buffer, lwe_dimension, glwe_dimension, polynomial_size,
        pbs_level, grouping_factor, number_of_inputs,
        cuda_get_max_shared_memory(stream->gpu_index), true);

    lwe_ct_out_array =
        (uint64_t *)malloc((glwe_dimension * polynomial_size + 1) *
                           number_of_inputs * sizeof(uint64_t));
  }

  void TearDown() {
    free(lwe_ct_out_array);

    cleanup_cuda_multi_bit_programmable_bootstrap(stream, &pbs_buffer);
    programmable_bootstrap_multibit_teardown(
        stream, lwe_sk_in_array, lwe_sk_out_array, d_bsk_array, plaintexts,
        d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_lwe_ct_out_array, d_lwe_output_indexes);
  }
};

TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64,
       multi_bit_programmable_bootstrap) {

  int bsk_size = (lwe_dimension / grouping_factor) * pbs_level *
                 (glwe_dimension + 1) * (glwe_dimension + 1) * polynomial_size *
                 (1 << grouping_factor);

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
      cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
          stream, (void *)d_lwe_ct_out_array, (void *)d_lwe_output_indexes,
          (void *)d_lut_pbs_identity, (void *)d_lut_pbs_indexes,
          (void *)d_lwe_ct_in, (void *)d_lwe_input_indexes, (void *)d_bsk,
          pbs_buffer, lwe_dimension, glwe_dimension, polynomial_size,
          grouping_factor, pbs_base_log, pbs_level, number_of_inputs, 1, 0,
          cuda_get_max_shared_memory(gpu_index));

      // Copy result to the host memory
      cuda_memcpy_async_to_cpu(lwe_ct_out_array, d_lwe_ct_out_array,
                               (glwe_dimension * polynomial_size + 1) *
                                   number_of_inputs * sizeof(uint64_t),
                               stream);

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

// Defines for which parameters set the PBS will be tested.
// It executes each src for all pairs on phis X qs (Cartesian product)
::testing::internal::ParamGenerator<MultiBitProgrammableBootstrapTestParams>
    multipbs_params_u64 = ::testing::Values(
        // fast src
        (MultiBitProgrammableBootstrapTestParams){
            16, 1, 256, new_gaussian_from_std_dev(sqrt(1.3880686109937e-11)),
            new_gaussian_from_std_dev(sqrt(1.1919984450689246e-23)), 23, 1, 2,
            2, 1, 2, 1, 10},
        (MultiBitProgrammableBootstrapTestParams){
            16, 1, 256, new_gaussian_from_std_dev(sqrt(1.3880686109937e-11)),
            new_gaussian_from_std_dev(sqrt(1.1919984450689246e-23)), 23, 1, 2,
            2, 128, 2, 1, 10},
        // 4_bits_multi_bit_group_2
        (MultiBitProgrammableBootstrapTestParams){
            818, 1, 2048, new_gaussian_from_std_dev(sqrt(1.3880686109937e-11)),
            new_gaussian_from_std_dev(sqrt(1.1919984450689246e-23)), 22, 1, 2,
            2, 1, 2, 1, 10},
        (MultiBitProgrammableBootstrapTestParams){
            818, 1, 2048, new_gaussian_from_std_dev(sqrt(1.3880686109937e-15)),
            new_gaussian_from_std_dev(sqrt(1.1919984450689246e-24)), 22, 1, 2,
            2, 128, 2, 1, 10},
        // 4_bits_multi_bit_group_3
        (MultiBitProgrammableBootstrapTestParams){
            888, 1, 2048,
            new_gaussian_from_std_dev(sqrt(4.9571231961752025e-12)),
            new_gaussian_from_std_dev(sqrt(9.9409770026944e-32)), 21, 1, 2, 2,
            1, 3, 1, 10},
        (MultiBitProgrammableBootstrapTestParams){
            888, 1, 16384,
            new_gaussian_from_std_dev(sqrt(4.9571231961752025e-12)),
            new_gaussian_from_std_dev(sqrt(9.9409770026944e-32)), 21, 1, 2, 2,
            1, 3, 1, 10},

        (MultiBitProgrammableBootstrapTestParams){
            888, 1, 1024,
            new_gaussian_from_std_dev(sqrt(4.9571231961752025e-12)),
            new_gaussian_from_std_dev(sqrt(9.9409770026944e-32)), 21, 1, 2, 2,
            128, 3, 1, 10},
        (MultiBitProgrammableBootstrapTestParams){
            888, 1, 2048,
            new_gaussian_from_std_dev(sqrt(4.9571231961752025e-12)),
            new_gaussian_from_std_dev(sqrt(9.9409770026944e-32)), 21, 1, 2, 2,
            128, 3, 1, 10},
        (MultiBitProgrammableBootstrapTestParams){
            888, 1, 4096,
            new_gaussian_from_std_dev(sqrt(4.9571231961752025e-12)),
            new_gaussian_from_std_dev(sqrt(9.9409770026944e-32)), 21, 1, 2, 2,
            128, 3, 1, 10},
        (MultiBitProgrammableBootstrapTestParams){
            888, 1, 8192,
            new_gaussian_from_std_dev(sqrt(4.9571231961752025e-12)),
            new_gaussian_from_std_dev(sqrt(9.9409770026944e-32)), 21, 1, 2, 2,
            128, 3, 1, 10},
        (MultiBitProgrammableBootstrapTestParams){
            888, 1, 16384,
            new_gaussian_from_std_dev(sqrt(4.9571231961752025e-12)),
            new_gaussian_from_std_dev(sqrt(9.9409770026944e-32)), 21, 1, 2, 2,
            128, 3, 1, 10});
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
