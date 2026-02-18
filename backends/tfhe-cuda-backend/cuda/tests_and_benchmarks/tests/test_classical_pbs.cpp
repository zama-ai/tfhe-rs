#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <gtest/gtest.h>
#include <pbs/pbs_utilities.h>
#include <setup_and_teardown.h>
#include <utils.h>

#include "checked_arithmetic.h"

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
  int repetitions;
  int samples;
} ClassicalProgrammableBootstrapTestParams;

class ClassicalProgrammableBootstrapTestPrimitives_u64
    : public ::testing::TestWithParam<
          ClassicalProgrammableBootstrapTestParams> {
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
  int repetitions;
  int samples;
  uint64_t delta;
  cudaStream_t stream;
  uint32_t gpu_index = 0;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  double *d_fourier_bsk_array;
  uint64_t *d_lut_pbs_identity;
  uint64_t *d_lut_pbs_indexes;
  uint64_t *d_lwe_ct_in_array;
  uint64_t *d_lwe_ct_out_array;
  uint64_t *d_lwe_input_indexes;
  uint64_t *d_lwe_output_indexes;
  uint64_t *lwe_ct_out_array;

  void run_and_check_pbs(
      const std::function<void(uint64_t *d_lwe_ct_in, double *d_fourier_bsk,
                               int8_t *pbs_buffer)> &run_pbs,
      int8_t *pbs_buffer) {
    int bsk_size = (glwe_dimension + 1) * (glwe_dimension + 1) * pbs_level *
                   polynomial_size * (lwe_dimension + 1);

    for (int r = 0; r < repetitions; r++) {
      double *d_fourier_bsk = d_fourier_bsk_array + (ptrdiff_t)(bsk_size * r);
      uint64_t *lwe_sk_out =
          lwe_sk_out_array + (ptrdiff_t)(r * glwe_dimension * polynomial_size);
      for (int s = 0; s < samples; s++) {
        uint64_t *d_lwe_ct_in =
            d_lwe_ct_in_array + (ptrdiff_t)((r * samples * number_of_inputs +
                                             s * number_of_inputs) *
                                            (lwe_dimension + 1));

        run_pbs(d_lwe_ct_in, d_fourier_bsk, pbs_buffer);

        cuda_memcpy_async_to_cpu(lwe_ct_out_array, d_lwe_ct_out_array,
                                 (glwe_dimension * polynomial_size + 1) *
                                     number_of_inputs * sizeof(uint64_t),
                                 stream, gpu_index);
        cuda_synchronize_stream(stream, gpu_index);

        for (int j = 0; j < number_of_inputs; j++) {
          uint64_t *result =
              lwe_ct_out_array +
              (ptrdiff_t)(j * (glwe_dimension * polynomial_size + 1));
          uint64_t plaintext = plaintexts[r * samples * number_of_inputs +
                                          s * number_of_inputs + j];
          uint64_t decrypted = 0;
          core_crypto_lwe_decrypt(&decrypted, result, lwe_sk_out,
                                  glwe_dimension * polynomial_size);
          ASSERT_NE(decrypted, plaintext);

          uint64_t rounding_bit = delta >> 1;
          uint64_t rounding = (decrypted & rounding_bit) << 1;
          uint64_t decoded = (decrypted + rounding) / delta;
          ASSERT_EQ(decoded, plaintext / delta);
        }
      }
    }
  }

  bool supports_classical_cg() const {
    return has_support_to_cuda_programmable_bootstrap_cg<uint64_t>(
        glwe_dimension, polynomial_size, pbs_level, number_of_inputs,
        cuda_get_max_shared_memory(gpu_index));
  }

  bool supports_classical_tbc() const {
    return has_support_to_cuda_programmable_bootstrap_tbc<uint64_t>(
        number_of_inputs, glwe_dimension, polynomial_size, pbs_level,
        cuda_get_max_shared_memory(gpu_index));
  }

public:
  // Test arithmetic functions
  void SetUp() {
    stream = cuda_create_stream(gpu_index);

    // TestParams
    lwe_dimension = (int)GetParam().lwe_dimension;
    glwe_dimension = (int)GetParam().glwe_dimension;
    polynomial_size = (int)GetParam().polynomial_size;
    lwe_noise_distribution =
        (DynamicDistribution)GetParam().lwe_noise_distribution;
    glwe_noise_distribution =
        (DynamicDistribution)GetParam().glwe_noise_distribution;
    pbs_base_log = (int)GetParam().pbs_base_log;
    pbs_level = (int)GetParam().pbs_level;
    message_modulus = (int)GetParam().message_modulus;
    carry_modulus = (int)GetParam().carry_modulus;
    number_of_inputs = (int)GetParam().number_of_inputs;
    repetitions = (int)GetParam().repetitions;
    samples = (int)GetParam().samples;

    Seed seed;
    init_seed(&seed);

    programmable_bootstrap_classical_setup(
        stream, gpu_index, &seed, &lwe_sk_in_array, &lwe_sk_out_array,
        &d_fourier_bsk_array, &plaintexts, &d_lut_pbs_identity,
        &d_lut_pbs_indexes, &d_lwe_ct_in_array, &d_lwe_input_indexes,
        &d_lwe_ct_out_array, &d_lwe_output_indexes, lwe_dimension,
        glwe_dimension, polynomial_size, lwe_noise_distribution,
        glwe_noise_distribution, pbs_base_log, pbs_level, message_modulus,
        carry_modulus, &payload_modulus, &delta, number_of_inputs, repetitions,
        samples);

    lwe_ct_out_array = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
        safe_mul((size_t)glwe_dimension, (size_t)polynomial_size) + 1,
        (size_t)number_of_inputs));
  }

  void TearDown() {
    free(lwe_ct_out_array);
    programmable_bootstrap_classical_teardown(
        stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array,
        d_fourier_bsk_array, plaintexts, d_lut_pbs_identity, d_lut_pbs_indexes,
        d_lwe_ct_in_array, d_lwe_input_indexes, d_lwe_ct_out_array,
        d_lwe_output_indexes);
  }
};

TEST_P(ClassicalProgrammableBootstrapTestPrimitives_u64,
       classical_auto_dispatch) {
  pbs_buffer<uint64_t, CLASSICAL> *typed_buffer = nullptr;
  scratch_cuda_programmable_bootstrap<uint64_t>(
      stream, gpu_index, &typed_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, number_of_inputs, true,
      PBS_MS_REDUCTION_T::NO_REDUCTION);
  int8_t *pbs_buffer = reinterpret_cast<int8_t *>(typed_buffer);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, double *d_fourier_bsk, int8_t *buffer) {
        cuda_programmable_bootstrap_64_async(
            stream, gpu_index, (void *)d_lwe_ct_out_array,
            (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
            (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in,
            (void *)d_lwe_input_indexes, (void *)d_fourier_bsk, buffer,
            lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log,
            pbs_level, number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &pbs_buffer);
}

TEST_P(ClassicalProgrammableBootstrapTestPrimitives_u64, classical_cg) {
  if (!supports_classical_cg()) {
    GTEST_SKIP() << "CG classical PBS is not supported on this architecture.";
  }

  pbs_buffer<uint64_t, CLASSICAL> *typed_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_cg<uint64_t>(
      stream, gpu_index, &typed_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, number_of_inputs, true,
      PBS_MS_REDUCTION_T::NO_REDUCTION);
  int8_t *pbs_buffer = reinterpret_cast<int8_t *>(typed_buffer);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, double *d_fourier_bsk, int8_t *buffer) {
        auto *typed =
            reinterpret_cast<::pbs_buffer<uint64_t, CLASSICAL> *>(buffer);
        cuda_programmable_bootstrap_cg_lwe_ciphertext_vector<uint64_t>(
            stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
            d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in,
            d_lwe_input_indexes,
            reinterpret_cast<const double2 *>(d_fourier_bsk), typed,
            lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log,
            pbs_level, number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &pbs_buffer);
}

TEST_P(ClassicalProgrammableBootstrapTestPrimitives_u64, classical_tbc) {
  if (!supports_classical_tbc()) {
    GTEST_SKIP() << "TBC classical PBS is not supported on this architecture.";
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_tbc_generic_64_async(
      stream, gpu_index, &pbs_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, number_of_inputs, true,
      PBS_MS_REDUCTION_T::NO_REDUCTION);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, double *d_fourier_bsk, int8_t *buffer) {
        cuda_programmable_bootstrap_tbc_64_generic_async(
            stream, gpu_index, (void *)d_lwe_ct_out_array,
            (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
            (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in,
            (void *)d_lwe_input_indexes, (void *)d_fourier_bsk, buffer,
            lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log,
            pbs_level, number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &pbs_buffer);
}

TEST_P(ClassicalProgrammableBootstrapTestPrimitives_u64, classical_tbc_2_2) {
  if (!supports_classical_tbc()) {
    GTEST_SKIP() << "TBC classical PBS is not supported on this architecture.";
  }
  if (!(polynomial_size == 2048 && pbs_level == 1 && glwe_dimension == 1 &&
        pbs_base_log == 23)) {
    GTEST_SKIP()
        << "TBC specialized 2_2 requires N=2048, glwe=1, level=1, base_log=23.";
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_tbc_2_2_64_async(
      stream, gpu_index, &pbs_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, number_of_inputs, true,
      PBS_MS_REDUCTION_T::NO_REDUCTION);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, double *d_fourier_bsk, int8_t *buffer) {
        cuda_programmable_bootstrap_tbc_64_2_2_async(
            stream, gpu_index, (void *)d_lwe_ct_out_array,
            (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
            (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in,
            (void *)d_lwe_input_indexes, (void *)d_fourier_bsk, buffer,
            lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log,
            pbs_level, number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &pbs_buffer);
}

// Defines for which parameters set the PBS will be tested.
// It executes each src for all pairs on phis X qs (Cartesian product)
::testing::internal::ParamGenerator<ClassicalProgrammableBootstrapTestParams>
    pbs_params_u64 = ::testing::Values(
        // n, k, N, lwe_variance, glwe_variance, pbs_base_log, pbs_level,
        // message_modulus, carry_modulus, number_of_inputs, repetitions,
        // samples

        // V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128
        (ClassicalProgrammableBootstrapTestParams){
            879, 4, 512, new_t_uniform(46), new_t_uniform(17), 23, 1, 2, 2, 10,
            1, 1},
        // V1_6_PARAM_GPU_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128
        (ClassicalProgrammableBootstrapTestParams){
            759, 1, 2048, new_t_uniform(50), new_t_uniform(17), 23, 1, 2, 2, 10,
            1, 1},
        // V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        (ClassicalProgrammableBootstrapTestParams){
            918, 1, 2048, new_t_uniform(45), new_t_uniform(17), 23, 1, 4, 4, 10,
            1, 1});
std::string printParamName(
    ::testing::TestParamInfo<ClassicalProgrammableBootstrapTestParams> p) {
  ClassicalProgrammableBootstrapTestParams params = p.param;

  return "n_" + std::to_string(params.lwe_dimension) + "_k_" +
         std::to_string(params.glwe_dimension) + "_N_" +
         std::to_string(params.polynomial_size) + "_pbs_base_log_" +
         std::to_string(params.pbs_base_log) + "_pbs_level_" +
         std::to_string(params.pbs_level) + "_number_of_inputs_" +
         std::to_string(params.number_of_inputs);
}

INSTANTIATE_TEST_CASE_P(ClassicalProgrammableBootstrapInstantiation,
                        ClassicalProgrammableBootstrapTestPrimitives_u64,
                        pbs_params_u64, printParamName);
