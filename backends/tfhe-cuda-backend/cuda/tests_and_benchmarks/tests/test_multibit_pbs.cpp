#include "checked_arithmetic.h"
#include "device.h"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <gtest/gtest.h>
#include <pbs/pbs_multibit_utilities.h>
#include <pbs/programmable_bootstrap_multibit.h>
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

  int repetitions;
  int samples;

  void run_and_check_pbs(
      const std::function<void(uint64_t *d_lwe_ct_in, uint64_t *d_bsk,
                               int8_t *pbs_buffer)> &run_pbs,
      int8_t *pbs_buffer) {
    int bsk_size = (lwe_dimension / grouping_factor) * pbs_level *
                   (glwe_dimension + 1) * (glwe_dimension + 1) *
                   polynomial_size * (1 << grouping_factor);

    for (int r = 0; r < repetitions; r++) {
      uint64_t *d_bsk = d_bsk_array + (ptrdiff_t)(bsk_size * r);
      uint64_t *lwe_sk_out =
          lwe_sk_out_array + (ptrdiff_t)(r * glwe_dimension * polynomial_size);
      for (int s = 0; s < samples; s++) {
        uint64_t *d_lwe_ct_in =
            d_lwe_ct_in_array + (ptrdiff_t)((r * samples * number_of_inputs +
                                             s * number_of_inputs) *
                                            (lwe_dimension + 1));

        run_pbs(d_lwe_ct_in, d_bsk, pbs_buffer);

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

          EXPECT_NE(decrypted, plaintext)
              << "Repetition: " << r << ", sample: " << s << ", input: " << j;

          uint64_t rounding_bit = delta >> 1;
          uint64_t rounding = (decrypted & rounding_bit) << 1;
          uint64_t decoded = (decrypted + rounding) / delta;
          EXPECT_EQ(decoded, plaintext / delta)
              << "Repetition: " << r << ", sample: " << s << ", input: " << j;
        }
      }
    }
  }

  bool supports_multibit_cg() const {
    return has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
        glwe_dimension, polynomial_size, pbs_level, number_of_inputs,
        cuda_get_max_shared_memory(gpu_index));
  }

  bool supports_multibit_tbc() const {
    return has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
        number_of_inputs, glwe_dimension, polynomial_size, pbs_level,
        cuda_get_max_shared_memory(gpu_index));
  }

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

    lwe_ct_out_array =
        (uint64_t *)malloc((glwe_dimension * polynomial_size + 1) *
                           number_of_inputs * sizeof(uint64_t));
  }

  void TearDown() {
    free(lwe_ct_out_array);

    programmable_bootstrap_multibit_teardown(
        stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array, d_bsk_array,
        plaintexts, d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_lwe_ct_out_array, d_lwe_output_indexes);
  }
};

TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64, multi_bit_default) {
  int8_t *pbs_buffer = nullptr;
  scratch_cuda_multi_bit_programmable_bootstrap_64_async(
      stream, gpu_index, &pbs_buffer, glwe_dimension, polynomial_size,
      pbs_level, number_of_inputs, true);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, uint64_t *d_bsk, int8_t *buffer) {
        auto *typed =
            reinterpret_cast<::pbs_buffer<uint64_t, MULTI_BIT> *>(buffer);
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
            stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
            d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in,
            d_lwe_input_indexes, d_bsk, typed, lwe_dimension, glwe_dimension,
            polynomial_size, grouping_factor, pbs_base_log, pbs_level,
            number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                   &pbs_buffer);
}

TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64, multi_bit_cg) {
  if (!supports_multibit_cg()) {
    GTEST_SKIP() << "CG multibit PBS is not supported on this architecture.";
  }

  pbs_buffer<uint64_t, MULTI_BIT> *typed_buffer = nullptr;
  scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t>(
      stream, gpu_index, &typed_buffer, glwe_dimension, polynomial_size,
      pbs_level, number_of_inputs, true);
  int8_t *pbs_buffer = reinterpret_cast<int8_t *>(typed_buffer);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, uint64_t *d_bsk, int8_t *buffer) {
        auto *typed =
            reinterpret_cast<::pbs_buffer<uint64_t, MULTI_BIT> *>(buffer);
        cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<
            uint64_t>(stream, gpu_index, d_lwe_ct_out_array,
                      d_lwe_output_indexes, d_lut_pbs_identity,
                      d_lut_pbs_indexes, d_lwe_ct_in, d_lwe_input_indexes,
                      d_bsk, typed, lwe_dimension, glwe_dimension,
                      polynomial_size, grouping_factor, pbs_base_log, pbs_level,
                      number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                   &pbs_buffer);
}

TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64, multi_bit_tbc) {
  if (!supports_multibit_tbc()) {
    GTEST_SKIP() << "TBC multibit PBS is not supported on this architecture.";
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_multi_bit_programmable_bootstrap_tbc_generic_64_async(
      stream, gpu_index, &pbs_buffer, glwe_dimension, polynomial_size,
      pbs_level, number_of_inputs, true);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, uint64_t *d_bsk, int8_t *buffer) {
        cuda_multi_bit_programmable_bootstrap_tbc_64_generic_async(
            stream, gpu_index, (void *)d_lwe_ct_out_array,
            (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
            (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in,
            (void *)d_lwe_input_indexes, (void *)d_bsk, buffer, lwe_dimension,
            glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
            pbs_level, number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                   &pbs_buffer);
}

TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64,
       multi_bit_coexistent_cg) {
  // COEXISTENT_CG uses its own scratch/launch/cleanup API. When the GPU
  // cannot fit both persistent kernels simultaneously, the scratch function
  // marks the buffer as infeasible and the host launch transparently falls
  // back to the regular CG path.
  pbs_buffer<uint64_t, MULTI_BIT> *typed_buffer = nullptr;
  scratch_cuda_coexistent_cg_multi_bit_programmable_bootstrap<uint64_t>(
      stream, gpu_index, &typed_buffer, glwe_dimension, polynomial_size,
      pbs_level, number_of_inputs, true);
  int8_t *pbs_buffer = reinterpret_cast<int8_t *>(typed_buffer);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, uint64_t *d_bsk, int8_t *buffer) {
        auto *typed =
            reinterpret_cast<::pbs_buffer<uint64_t, MULTI_BIT> *>(buffer);
        cuda_coexistent_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<
            uint64_t>(stream, gpu_index, d_lwe_ct_out_array,
                      d_lwe_output_indexes, d_lut_pbs_identity,
                      d_lut_pbs_indexes, d_lwe_ct_in, d_lwe_input_indexes,
                      d_bsk, typed, lwe_dimension, glwe_dimension,
                      polynomial_size, grouping_factor, pbs_base_log, pbs_level,
                      number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_coexistent_cg_multi_bit_programmable_bootstrap_64(
      stream, gpu_index, &pbs_buffer);
}

// Verifies that COEXISTENT_CG and CG produce bit-identical outputs for the
// same inputs, keys, and LUT.  Both variants implement the same mathematical
// function; any divergence indicates a bug in the producer-consumer protocol.
TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64,
       multi_bit_coexistent_cg_matches_cg) {
  if (!supports_multibit_cg()) {
    GTEST_SKIP() << "CG multibit PBS is not supported on this architecture.";
  }

  // CG reference buffer
  pbs_buffer<uint64_t, MULTI_BIT> *cg_buffer = nullptr;
  scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t>(
      stream, gpu_index, &cg_buffer, glwe_dimension, polynomial_size, pbs_level,
      number_of_inputs, true);

  // COEXISTENT_CG buffer
  pbs_buffer<uint64_t, MULTI_BIT> *coex_buffer = nullptr;
  scratch_cuda_coexistent_cg_multi_bit_programmable_bootstrap<uint64_t>(
      stream, gpu_index, &coex_buffer, glwe_dimension, polynomial_size,
      pbs_level, number_of_inputs, true);

  int bsk_size = (lwe_dimension / grouping_factor) * pbs_level *
                 (glwe_dimension + 1) * (glwe_dimension + 1) * polynomial_size *
                 (1 << grouping_factor);
  size_t out_size = (glwe_dimension * polynomial_size + 1) * number_of_inputs *
                    sizeof(uint64_t);

  // Allocate a second output array to hold the CG results for comparison
  uint64_t *d_lwe_ct_out_cg =
      (uint64_t *)cuda_malloc_async(out_size, stream, gpu_index);
  uint64_t *lwe_ct_out_cg = (uint64_t *)malloc(out_size);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;

  for (int r = 0; r < repetitions; r++) {
    uint64_t *d_bsk = d_bsk_array + (ptrdiff_t)(bsk_size * r);
    for (int s = 0; s < samples; s++) {
      uint64_t *d_lwe_ct_in =
          d_lwe_ct_in_array +
          (ptrdiff_t)((r * samples * number_of_inputs + s * number_of_inputs) *
                      (lwe_dimension + 1));

      // Run CG
      cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
          stream, gpu_index, d_lwe_ct_out_cg, d_lwe_output_indexes,
          d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in,
          d_lwe_input_indexes, d_bsk, cg_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, grouping_factor, pbs_base_log, pbs_level,
          number_of_inputs, num_many_lut, lut_stride);
      cuda_synchronize_stream(stream, gpu_index);

      // Run COEXISTENT_CG
      cuda_coexistent_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<
          uint64_t>(stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
                    d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in,
                    d_lwe_input_indexes, d_bsk, coex_buffer, lwe_dimension,
                    glwe_dimension, polynomial_size, grouping_factor,
                    pbs_base_log, pbs_level, number_of_inputs, num_many_lut,
                    lut_stride);
      cuda_synchronize_stream(stream, gpu_index);

      // Copy both outputs to host
      cuda_memcpy_async_to_cpu(lwe_ct_out_array, d_lwe_ct_out_array, out_size,
                               stream, gpu_index);
      cuda_memcpy_async_to_cpu(lwe_ct_out_cg, d_lwe_ct_out_cg, out_size, stream,
                               gpu_index);
      cuda_synchronize_stream(stream, gpu_index);

      // Bit-exact comparison: same math must produce identical results
      for (size_t i = 0; i < out_size / sizeof(uint64_t); i++) {
        EXPECT_EQ(lwe_ct_out_array[i], lwe_ct_out_cg[i])
            << "Output mismatch between COEXISTENT_CG and CG at word " << i
            << " (repetition=" << r << ", sample=" << s << ")";
      }
    }
  }

  free(lwe_ct_out_cg);
  cuda_drop_async(d_lwe_ct_out_cg, stream, gpu_index);

  int8_t *cg_buf_ptr = reinterpret_cast<int8_t *>(cg_buffer);
  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                   &cg_buf_ptr);
  int8_t *coex_buf_ptr = reinterpret_cast<int8_t *>(coex_buffer);
  cleanup_cuda_coexistent_cg_multi_bit_programmable_bootstrap_64(
      stream, gpu_index, &coex_buf_ptr);
}

TEST_P(MultiBitProgrammableBootstrapTestPrimitives_u64, multi_bit_tbc_2_2) {
  if (!supports_multibit_tbc()) {
    GTEST_SKIP() << "TBC multibit PBS is not supported on this architecture.";
  }
  if (!(polynomial_size == 2048 && grouping_factor == 4 && pbs_level == 1 &&
        glwe_dimension == 1 && pbs_base_log == 22)) {
    GTEST_SKIP() << "TBC specialized 2_2 requires N=2048, grouping_factor=4, "
                    "glwe=1, level=1, base_log=22.";
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_multi_bit_programmable_bootstrap_tbc_2_2_64_async(
      stream, gpu_index, &pbs_buffer, glwe_dimension, polynomial_size,
      pbs_level, number_of_inputs, true);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, uint64_t *d_bsk, int8_t *buffer) {
        cuda_multi_bit_programmable_bootstrap_tbc_64_2_2_async(
            stream, gpu_index, (void *)d_lwe_ct_out_array,
            (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
            (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in,
            (void *)d_lwe_input_indexes, (void *)d_bsk, buffer, lwe_dimension,
            glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
            pbs_level, number_of_inputs, num_many_lut, lut_stride);
      },
      pbs_buffer);

  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                   &pbs_buffer);
}

// Defines for which parameters set the PBS will be tested.
// It executes each src for all pairs on phis X qs (Cartesian product)
::testing::internal::ParamGenerator<MultiBitProgrammableBootstrapTestParams>
    multipbs_params_u64 = ::testing::Values(
        // V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128
        (MultiBitProgrammableBootstrapTestParams){
            760, 1, 2048, new_t_uniform(49), new_t_uniform(17), 22, 1, 2, 2, 10,
            4, 1, 1},
        // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        (MultiBitProgrammableBootstrapTestParams){
            920, 1, 2048, new_t_uniform(45), new_t_uniform(17), 22, 1, 4, 4, 10,
            4, 1, 1},
        // Single-sample edge case for the COEXISTENT_CG producer-consumer
        // protocol: number_of_inputs=1 minimises the accumulator grid, making
        // the coexistent_chunk_size calculation as tight as possible and
        // exercising the "only one sample, single-block accumulator" path.
        (MultiBitProgrammableBootstrapTestParams){
            760, 1, 2048, new_t_uniform(49), new_t_uniform(17), 22, 1, 2, 2, 1,
            4, 1, 1},
        // Many-sample stress test: 64 simultaneous inputs force the
        // accumulator grid to occupy many SMs, shrinking sms_for_kb and thus
        // coexistent_chunk_size. On large GPUs (>=80 SMs) this maximises the
        // number of producer-consumer handshake iterations (total_chunks) and
        // exercises the CountdownBarrier reuse path across multiple chunks.
        // On smaller GPUs the coexistent variant is infeasible and the launch
        // transparently falls back to regular CG.
        (MultiBitProgrammableBootstrapTestParams){
            760, 1, 2048, new_t_uniform(49), new_t_uniform(17), 22, 1, 2, 2, 64,
            4, 1, 1});

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
