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
    const int eff_inputs =
        is_sanitizer_run() ? std::min(number_of_inputs, 2) : number_of_inputs;

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

  bool supports_classical_specialized_2_2() const {
    return specialized_2_2_params_checker<uint64_t>(
        polynomial_size, glwe_dimension, pbs_level,
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
        cuda_programmable_bootstrap_cg_lwe_ciphertext_vector_async<uint64_t>(
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

  // We want to force the vanilla layout of the bsk.
  cuda_drop_async(d_fourier_bsk_array, stream, gpu_index);
  Seed bsk_seed;
  init_seed(&bsk_seed);
  generate_lwe_programmable_bootstrap_keys_standard(
      stream, gpu_index, &d_fourier_bsk_array, lwe_sk_in_array,
      lwe_sk_out_array, lwe_dimension, glwe_dimension, polynomial_size,
      pbs_level, pbs_base_log, &bsk_seed, glwe_noise_distribution, repetitions);

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
  if (!supports_classical_specialized_2_2()) {
    GTEST_SKIP()
        << "TBC classical specialized 2_2 PBS is not supported on this "
           "params.";
  }
  if (!(pbs_base_log == 23)) {
    GTEST_SKIP() << "Specialized 2_2 requires base_log == 23.";
  }
  // We need to change the layout of the bsk to match the specialized kernel.
  cuda_drop_async(d_fourier_bsk_array, stream, gpu_index);
  Seed bsk_seed;
  init_seed(&bsk_seed);
  generate_lwe_programmable_bootstrap_keys_specialized_2_2(
      stream, gpu_index, &d_fourier_bsk_array, lwe_sk_in_array,
      lwe_sk_out_array, lwe_dimension, glwe_dimension, polynomial_size,
      pbs_level, pbs_base_log, &bsk_seed, glwe_noise_distribution, repetitions);
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

TEST_P(ClassicalProgrammableBootstrapTestPrimitives_u64,
       classical_specialized_2_2) {
  if (!supports_classical_specialized_2_2()) {
    GTEST_SKIP() << "Specialized 2_2 classical PBS is not supported on this "
                    "params.";
  }
  if (!(pbs_base_log >= 21 && pbs_base_log <= 25)) {
    GTEST_SKIP() << "Specialized 2_2 requires base_log in [21, 25].";
  }
  // We need to change the layout of the bsk to match the specialized kernel.
  cuda_drop_async(d_fourier_bsk_array, stream, gpu_index);
  Seed bsk_seed;
  init_seed(&bsk_seed);
  generate_lwe_programmable_bootstrap_keys_specialized_2_2(
      stream, gpu_index, &d_fourier_bsk_array, lwe_sk_in_array,
      lwe_sk_out_array, lwe_dimension, glwe_dimension, polynomial_size,
      pbs_level, pbs_base_log, &bsk_seed, glwe_noise_distribution, repetitions);

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_specialized_2_2_64_async(
      stream, gpu_index, &pbs_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, number_of_inputs, true,
      PBS_MS_REDUCTION_T::NO_REDUCTION);

  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  run_and_check_pbs(
      [&](uint64_t *d_lwe_ct_in, double *d_fourier_bsk, int8_t *buffer) {
        cuda_programmable_bootstrap_specialized_2_2_64_async(
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

class ClassicalPbsBufferReuseTest_u64
    : public ClassicalProgrammableBootstrapTestPrimitives_u64 {
protected:
  pbs_buffer<uint64_t, CLASSICAL> *scratch(uint32_t num_inputs) {
    int8_t *buffer = nullptr;
    scratch_cuda_programmable_bootstrap_64_async(
        stream, gpu_index, &buffer, lwe_dimension, glwe_dimension,
        polynomial_size, pbs_level, num_inputs, true,
        PBS_MS_REDUCTION_T::NO_REDUCTION);
    return reinterpret_cast<pbs_buffer<uint64_t, CLASSICAL> *>(buffer);
  }

  std::vector<uint64_t> run_pbs(pbs_buffer<uint64_t, CLASSICAL> *buffer,
                                uint32_t num_inputs) {
    size_t output_size =
        (size_t)(glwe_dimension * polynomial_size + 1) * num_inputs;
    cuda_memset_async(d_lwe_ct_out_array, 0, output_size * sizeof(uint64_t),
                      stream, gpu_index);
    cuda_programmable_bootstrap_64_async(
        stream, gpu_index, (void *)d_lwe_ct_out_array,
        (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
        (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in_array,
        (void *)d_lwe_input_indexes, (void *)d_fourier_bsk_array,
        reinterpret_cast<int8_t *>(buffer), lwe_dimension, glwe_dimension,
        polynomial_size, pbs_base_log, pbs_level, num_inputs, 1, 0);
    std::vector<uint64_t> output(output_size);
    cuda_memcpy_async_to_cpu(output.data(), d_lwe_ct_out_array,
                             output_size * sizeof(uint64_t), stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    return output;
  }

  void release(pbs_buffer<uint64_t, CLASSICAL> *buffer) {
    buffer->release(stream, gpu_index);
    delete buffer;
  }
};

TEST_P(ClassicalPbsBufferReuseTest_u64, borrowed_buffer_matches_own_buffer) {
  auto *owner = scratch(number_of_inputs);
  std::vector<pbs_buffer<uint64_t, CLASSICAL> *> borrowers;

  // Calls of different sizes, one after the other, on the same owner
  const uint32_t n = number_of_inputs;
  for (uint32_t num_inputs : {n, n / 10, n / 2, n}) {
    auto *own = scratch(num_inputs);
    bool same_variant = own->pbs_variant == owner->pbs_variant;
    auto *borrower = owner->try_borrow(num_inputs);
    EXPECT_EQ(borrower != nullptr, same_variant)
        << "num_inputs: " << num_inputs;
    if (borrower == nullptr) {
      release(own);
      continue;
    }
    auto expected = run_pbs(own, num_inputs);
    release(own);

    EXPECT_EQ(borrower->d_mem, owner->d_mem);
    EXPECT_EQ(borrower->global_join_buffer, owner->global_join_buffer);
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
    EXPECT_EQ(borrower->global_join_buffer, nullptr);
    release(borrower);
  }
}

TEST_P(ClassicalPbsBufferReuseTest_u64, borrower_can_be_released_before_owner) {
  auto *owner = scratch(number_of_inputs);
  auto *borrower0 = owner->try_borrow(number_of_inputs);
  auto *borrower1 = owner->try_borrow(number_of_inputs);
  ASSERT_NE(borrower0, nullptr);
  ASSERT_NE(borrower1, nullptr);

  borrower0->release(stream, gpu_index);
  EXPECT_EQ(owner->borrowers.size(), 1u);
  EXPECT_EQ(borrower0->global_join_buffer, nullptr);

  owner->release(stream, gpu_index);
  EXPECT_EQ(borrower1->global_join_buffer, nullptr);
  EXPECT_EQ(borrower1->owner, nullptr);

  borrower1->release(stream, gpu_index);
  delete borrower0;
  delete borrower1;
  delete owner;
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

::testing::internal::ParamGenerator<ClassicalProgrammableBootstrapTestParams>
    pbs_reuse_params_u64 = ::testing::Values(
        // V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        (ClassicalProgrammableBootstrapTestParams){
            918, 1, 2048, new_t_uniform(45), new_t_uniform(17), 23, 1, 4, 4, 10,
            1, 1});

INSTANTIATE_TEST_CASE_P(ClassicalPbsBufferReuseInstantiation,
                        ClassicalPbsBufferReuseTest_u64, pbs_reuse_params_u64,
                        printParamName);
