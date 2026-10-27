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
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<
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

class MultiBitPbsBufferReuseTest_u64
    : public MultiBitProgrammableBootstrapTestPrimitives_u64 {
protected:
  pbs_buffer<uint64_t, MULTI_BIT> *scratch(uint32_t num_inputs) {
    int8_t *buffer = nullptr;
    scratch_cuda_multi_bit_programmable_bootstrap_64_async(
        stream, gpu_index, &buffer, glwe_dimension, polynomial_size, pbs_level,
        num_inputs, true);
    return reinterpret_cast<pbs_buffer<uint64_t, MULTI_BIT> *>(buffer);
  }

  std::vector<uint64_t> run_pbs(pbs_buffer<uint64_t, MULTI_BIT> *buffer,
                                uint32_t num_inputs) {
    size_t output_size =
        (size_t)(glwe_dimension * polynomial_size + 1) * num_inputs;
    cuda_memset_async(d_lwe_ct_out_array, 0, output_size * sizeof(uint64_t),
                      stream, gpu_index);
    cuda_multi_bit_programmable_bootstrap_64_async(
        stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
        d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_bsk_array, reinterpret_cast<int8_t *>(buffer),
        lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
        pbs_base_log, pbs_level, num_inputs, 1, 0);
    std::vector<uint64_t> output(output_size);
    cuda_memcpy_async_to_cpu(output.data(), d_lwe_ct_out_array,
                             output_size * sizeof(uint64_t), stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    return output;
  }

  void release(pbs_buffer<uint64_t, MULTI_BIT> *buffer) {
    buffer->release(stream, gpu_index);
    delete buffer;
  }
};

TEST_P(MultiBitPbsBufferReuseTest_u64, borrowed_buffer_matches_own_buffer) {
  auto *owner = scratch(number_of_inputs);
  std::vector<pbs_buffer<uint64_t, MULTI_BIT> *> borrowers;

  // Calls of different sizes, one after the other, on the same owner
  const uint32_t n = number_of_inputs;
  for (uint32_t num_inputs : {n, n / 10, n / 2, n}) {
    auto *own = scratch(num_inputs);
    uint64_t own_chunk_size = own->lwe_chunk_size;
    bool expected_reuse =
        own->pbs_variant == owner->pbs_variant &&
        (uint64_t)num_inputs * own_chunk_size <=
            (uint64_t)owner->input_lwe_ciphertext_count * owner->lwe_chunk_size;
    auto *borrower = owner->try_borrow(num_inputs);
    EXPECT_EQ(borrower != nullptr, expected_reuse)
        << "num_inputs: " << num_inputs;
    if (borrower == nullptr) {
      release(own);
      continue;
    }
    auto expected = run_pbs(own, num_inputs);
    release(own);

    EXPECT_EQ(borrower->keybundle_fft, owner->keybundle_fft);
    EXPECT_EQ(borrower->lwe_chunk_size, own_chunk_size);
    EXPECT_LE((uint64_t)borrower->input_lwe_ciphertext_count *
                  borrower->lwe_chunk_size,
              (uint64_t)owner->input_lwe_ciphertext_count *
                  owner->lwe_chunk_size);
    EXPECT_EQ(borrower->global_accumulator, owner->global_accumulator);
    EXPECT_EQ(expected, run_pbs(borrower, num_inputs))
        << "num_inputs: " << num_inputs;
    borrowers.push_back(borrower);
  }

  EXPECT_EQ(owner->try_borrow(n + 1), nullptr);
  ASSERT_FALSE(borrowers.empty());
  EXPECT_EQ(borrowers[0]->try_borrow(1), nullptr);

  release(owner);
  for (auto *borrower : borrowers) {
    EXPECT_EQ(borrower->owner, nullptr);
    EXPECT_EQ(borrower->keybundle_fft, nullptr);
    release(borrower);
  }
}

TEST_P(MultiBitPbsBufferReuseTest_u64, borrower_can_be_released_before_owner) {
  auto *owner = scratch(number_of_inputs);
  auto *borrower0 = owner->try_borrow(number_of_inputs);
  auto *borrower1 = owner->try_borrow(number_of_inputs);
  ASSERT_NE(borrower0, nullptr);
  ASSERT_NE(borrower1, nullptr);

  borrower0->release(stream, gpu_index);
  EXPECT_EQ(owner->borrowers.size(), 1u);
  EXPECT_EQ(borrower0->keybundle_fft, nullptr);

  owner->release(stream, gpu_index);
  EXPECT_EQ(borrower1->keybundle_fft, nullptr);
  EXPECT_EQ(borrower1->owner, nullptr);

  borrower1->release(stream, gpu_index);
  delete borrower0;
  delete borrower1;
  delete owner;
}

::testing::internal::ParamGenerator<MultiBitProgrammableBootstrapTestParams>
    multipbs_reuse_params_u64 = ::testing::Values(
        // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        (MultiBitProgrammableBootstrapTestParams){
            920, 1, 2048, new_t_uniform(45), new_t_uniform(17), 22, 1, 4, 4,
            520, 4, 1, 1});

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

INSTANTIATE_TEST_CASE_P(MultiBitPbsBufferReuseInstantiation,
                        MultiBitPbsBufferReuseTest_u64,
                        multipbs_reuse_params_u64, printParamName);
