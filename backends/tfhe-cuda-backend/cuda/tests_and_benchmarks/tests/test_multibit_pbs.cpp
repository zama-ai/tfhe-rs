#include "checked_arithmetic.h"
#include "device.h"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <pbs/pbs_multibit_utilities.h>
#include <pbs/programmable_bootstrap_multibit.h>
#include <setup_and_teardown.h>
#include <utils.h>
#include <vector>

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
    const int eff_inputs =
        is_sanitizer_run() ? std::min(number_of_inputs, 2) : number_of_inputs;

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
                                     eff_inputs * sizeof(uint64_t),
                                 stream, gpu_index);
        cuda_synchronize_stream(stream, gpu_index);

        for (int j = 0; j < eff_inputs; j++) {
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

  virtual Seed setup_seed() {
    Seed seed;
    init_seed(&seed);
    return seed;
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

  void run_and_check_default_pbs() {
    int8_t *pbs_buffer = nullptr;
    scratch_cuda_multi_bit_programmable_bootstrap_64_async(
        stream, gpu_index, &pbs_buffer, glwe_dimension, polynomial_size,
        pbs_level, number_of_inputs, true);
    expect_h100_specialized_chunk_size(
        reinterpret_cast<::pbs_buffer<uint64_t, MULTI_BIT> *>(pbs_buffer));

    uint32_t num_many_lut = 1;
    uint32_t lut_stride = 0;
    run_and_check_pbs(
        [&](uint64_t *d_lwe_ct_in, uint64_t *d_bsk, int8_t *buffer) {
          auto *typed =
              reinterpret_cast<::pbs_buffer<uint64_t, MULTI_BIT> *>(buffer);
          cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<
              uint64_t>(stream, gpu_index, d_lwe_ct_out_array,
                        d_lwe_output_indexes, d_lut_pbs_identity,
                        d_lut_pbs_indexes, d_lwe_ct_in, d_lwe_input_indexes,
                        d_bsk, typed, lwe_dimension, glwe_dimension,
                        polynomial_size, grouping_factor, pbs_base_log,
                        pbs_level, number_of_inputs, num_many_lut, lut_stride);
        },
        pbs_buffer);

    cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                     &pbs_buffer);
  }

  void expect_h100_specialized_chunk_size(
      const ::pbs_buffer<uint64_t, MULTI_BIT> *buffer) const {
    int num_sms = 0;
    check_cuda_error(cudaDeviceGetAttribute(
        &num_sms, cudaDevAttrMultiProcessorCount, gpu_index));
    const bool specialized_keybundle =
        polynomial_size == 2048 && pbs_level == 1 && glwe_dimension == 1;
    if (num_sms != 132 || buffer->pbs_variant != TBC ||
        !specialized_keybundle ||
        std::getenv("TFHE_RS_GPU_MULTIBIT_LWE_CHUNK") != nullptr)
      return;
    const uint64_t expected = number_of_inputs <= 5    ? 16
                              : number_of_inputs == 6  ? 13
                              : number_of_inputs == 7  ? 11
                              : number_of_inputs <= 23 ? 10
                                                       : 32;
    EXPECT_EQ(buffer->lwe_chunk_size, expected)
        << "number_of_inputs: " << number_of_inputs;
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

    Seed seed = setup_seed();

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
  run_and_check_default_pbs();
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
        cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<
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

class MultiBitPersistentScratchTest_u64
    : public MultiBitProgrammableBootstrapTestPrimitives_u64 {};

TEST_P(MultiBitPersistentScratchTest_u64,
       caller_stream_orders_repeated_async_pbs) {
  if (!supports_multibit_tbc()) {
    GTEST_SKIP() << "TBC multibit PBS is not supported on this architecture.";
  }
  constexpr size_t call_count = 3;
  ASSERT_EQ(samples, call_count);
  ASSERT_EQ(repetitions, 1);
  const size_t input_words =
      static_cast<size_t>(lwe_dimension + 1) * number_of_inputs;
  const size_t output_words =
      static_cast<size_t>(glwe_dimension * polynomial_size + 1) *
      number_of_inputs;
  const size_t input_bytes = input_words * sizeof(uint64_t);
  const size_t output_bytes = output_words * sizeof(uint64_t);

  // Different known messages make a stale input or previous output observable.
  std::vector<uint64_t> input(call_count * input_words);
  for (size_t c = 0; c < call_count; ++c) {
    for (int lane = 0; lane < number_of_inputs; ++lane) {
      const uint64_t message = (c + lane) % payload_modulus;
      core_crypto_lwe_encrypt(
          input.data() + c * input_words +
              static_cast<size_t>(lane) * (lwe_dimension + 1),
          message * delta, lwe_sk_in_array, lwe_dimension,
          lwe_noise_distribution, uint64_t{1234} + c * number_of_inputs + lane,
          uint64_t{5678});
    }
  }
  cuda_memcpy_async_to_gpu(d_lwe_ct_in_array, input.data(),
                           call_count * input_bytes, stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  enum class Launch { GENERIC, SPECIALIZED, AUTO };
  for (Launch mode : {Launch::GENERIC, Launch::SPECIALIZED, Launch::AUTO}) {
    SCOPED_TRACE(static_cast<int>(mode));
    auto scratch = [&](int8_t **buffer) {
      if (mode == Launch::GENERIC)
        scratch_cuda_multi_bit_programmable_bootstrap_tbc_generic_64_async(
            stream, gpu_index, buffer, glwe_dimension, polynomial_size,
            pbs_level, number_of_inputs, true);
      else if (mode == Launch::SPECIALIZED)
        scratch_cuda_multi_bit_programmable_bootstrap_tbc_2_2_64_async(
            stream, gpu_index, buffer, glwe_dimension, polynomial_size,
            pbs_level, number_of_inputs, true);
      else
        scratch_cuda_multi_bit_programmable_bootstrap_64_async(
            stream, gpu_index, buffer, glwe_dimension, polynomial_size,
            pbs_level, number_of_inputs, true);
    };
    auto launch = [&](uint64_t *device_input, int8_t *buffer) {
      auto *typed =
          reinterpret_cast<::pbs_buffer<uint64_t, MULTI_BIT> *>(buffer);
      if (mode == Launch::GENERIC)
        cuda_multi_bit_programmable_bootstrap_tbc_64_generic_async(
            stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
            d_lut_pbs_identity, d_lut_pbs_indexes, device_input,
            d_lwe_input_indexes, d_bsk_array, buffer, lwe_dimension,
            glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
            pbs_level, number_of_inputs, 1, 0);
      else if (mode == Launch::SPECIALIZED)
        cuda_multi_bit_programmable_bootstrap_tbc_64_2_2_async(
            stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
            d_lut_pbs_identity, d_lut_pbs_indexes, device_input,
            d_lwe_input_indexes, d_bsk_array, buffer, lwe_dimension,
            glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
            pbs_level, number_of_inputs, 1, 0);
      else
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<
            uint64_t>(stream, gpu_index, d_lwe_ct_out_array,
                      d_lwe_output_indexes, d_lut_pbs_identity,
                      d_lut_pbs_indexes, device_input, d_lwe_input_indexes,
                      d_bsk_array, typed, lwe_dimension, glwe_dimension,
                      polynomial_size, grouping_factor, pbs_base_log, pbs_level,
                      number_of_inputs, 1, 0);
    };

    int8_t *buffer = nullptr;
    scratch(&buffer);
    std::vector<uint64_t> expected(call_count * output_words);
    for (size_t c = 0; c < call_count; ++c) {
      launch(d_lwe_ct_in_array + c * input_words, buffer);
      cuda_memcpy_async_to_cpu(expected.data() + c * output_words,
                               d_lwe_ct_out_array, output_bytes, stream,
                               gpu_index);
      cuda_synchronize_stream(stream, gpu_index);
      for (int lane = 0; lane < number_of_inputs; ++lane) {
        uint64_t decrypted = 0;
        core_crypto_lwe_decrypt(&decrypted,
                                expected.data() + c * output_words +
                                    static_cast<size_t>(lane) *
                                        (glwe_dimension * polynomial_size + 1),
                                lwe_sk_out_array,
                                glwe_dimension * polynomial_size);
        const uint64_t rounded = decrypted + ((decrypted & (delta >> 1)) << 1);
        EXPECT_EQ(rounded / delta, (c + lane) % payload_modulus);
      }
    }
    cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                     &buffer);

    // Fresh async allocations and scratch must be ready before the second
    // stream reads them; no explicit synchronization is inserted here.
    auto *device_input = static_cast<uint64_t *>(
        cuda_malloc_async(input_bytes, stream, gpu_index));
    auto *snapshots = static_cast<uint64_t *>(
        cuda_malloc_async(call_count * output_bytes, stream, gpu_index));
    scratch(&buffer);
    auto *typed = reinterpret_cast<::pbs_buffer<uint64_t, MULTI_BIT> *>(buffer);
    EXPECT_EQ(typed->pbs_variant, TBC);
    std::cout << "persistent async PBS: batch=" << number_of_inputs
              << " chunk=" << typed->lwe_chunk_size
              << " mode=" << static_cast<int>(mode) << std::endl;
    for (size_t c = 0; c < call_count; ++c) {
      cuda_memcpy_async_gpu_to_gpu(device_input,
                                   d_lwe_ct_in_array + c * input_words,
                                   input_bytes, stream, gpu_index);
      launch(device_input, buffer);
      cuda_memcpy_async_gpu_to_gpu(snapshots + c * output_words,
                                   d_lwe_ct_out_array, output_bytes, stream,
                                   gpu_index);
    }
    // Cleanup is called before the final queued PBS and consumer are drained.
    cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index,
                                                     &buffer);
    std::vector<uint64_t> actual(call_count * output_words);
    cuda_memcpy_async_to_cpu(actual.data(), snapshots,
                             call_count * output_bytes, stream, gpu_index);
    cuda_drop_async(device_input, stream, gpu_index);
    cuda_drop_async(snapshots, stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    for (size_t c = 0; c < call_count; ++c) {
      for (size_t word = 0; word < output_words; ++word) {
        EXPECT_EQ(actual[c * output_words + word],
                  expected[c * output_words + word])
            << "call=" << c << " word=" << word;
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(AsyncOrdering, MultiBitPersistentScratchTest_u64,
                         ::testing::Values(
                             MultiBitProgrammableBootstrapTestParams{
                                 920, 1, 2048, new_t_uniform(45),
                                 new_t_uniform(17), 22, 1, 4, 4, 8, 4, 1, 3},
                             MultiBitProgrammableBootstrapTestParams{
                                 920, 1, 2048, new_t_uniform(45),
                                 new_t_uniform(17), 22, 1, 4, 4, 9, 4, 1, 3}));

class MultiBitChunkSelectorTest_u64
    : public MultiBitProgrammableBootstrapTestPrimitives_u64 {};

TEST_P(MultiBitChunkSelectorTest_u64, default_chunk) {
  run_and_check_default_pbs();
}

static std::vector<MultiBitProgrammableBootstrapTestParams>
chunk_selector_params() {
  std::vector<MultiBitProgrammableBootstrapTestParams> params;
  for (int batch : {1, 5, 6, 7, 8, 23, 24, 512, 1024, 2048, 4096}) {
    // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    params.push_back({920, 1, 2048, new_t_uniform(45), new_t_uniform(17), 22, 1,
                      4, 4, batch, 4, 1, 1});
    // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
    params.push_back({872, 1, 2048,
                      new_gaussian_from_std_dev(1.844927811696596e-06),
                      new_gaussian_from_std_dev(2.845267479601915e-15), 22, 1,
                      4, 4, batch, 4, 1, 1});
  }
  return params;
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

INSTANTIATE_TEST_SUITE_P(ChunkSelectorRanges, MultiBitChunkSelectorTest_u64,
                         ::testing::ValuesIn(chunk_selector_params()),
                         printParamName);
