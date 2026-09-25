#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <gtest/gtest.h>
#include <pbs/pbs_utilities.h>
#include <pbs/programmable_bootstrap.h>
#include <pbs/programmable_bootstrap_testing_128.h>
#include <utils.h>

#include "checked_arithmetic.h"

// Correctness test for the halfhalf (HP+HR) 128-bit programmable bootstrap
// (noise squashing with generalized BSK). The kernel takes u64 input LWE
// ciphertexts and produces u128 output LWE ciphertexts.
// Belorgey et al., ePrint 2023/771; Bernard & Joye, ePrint 2025/163.
class ClassicalProgrammableBootstrap128HalfhalfTest : public ::testing::Test {
protected:
  static constexpr int input_lwe_dimension = 918;
  static constexpr int glwe_dimension = 2;
  static constexpr int polynomial_size = 2048;
  static constexpr int payload_modulus = 16;
  static constexpr int output_lwe_dimension = glwe_dimension * polynomial_size;
  static constexpr int nb_tests = 5;
  static constexpr int num_samples = payload_modulus * nb_tests;

  static constexpr int split_index = 286;
  static constexpr int base_log_1_mask = 32;
  static constexpr int level_count_1_mask = 2;
  static constexpr int base_log_1_body = 31;
  static constexpr int level_count_1_body = 2;
  static constexpr int base_log_2_mask = 24;
  static constexpr int level_count_2_mask = 3;
  static constexpr int base_log_2_body = 31;
  static constexpr int level_count_2_body = 2;

  cudaStream_t stream;
  uint32_t gpu_index = 0;
  __uint128_t delta_128;
  uint64_t delta_64;
  CudaHalfhalfPbsParamsFFI halfhalf_params;

  __uint128_t *lwe_sk_in_u128 = nullptr;
  uint64_t *lwe_sk_in_u64 = nullptr;
  __uint128_t *glwe_sk_out = nullptr;
  __uint128_t *bsk_group1_mask = nullptr;
  __uint128_t *bsk_group1_body = nullptr;
  __uint128_t *bsk_group2_mask = nullptr;
  __uint128_t *bsk_group2_body = nullptr;
  __uint128_t *halfhalf_bsk = nullptr;
  double *d_fourier_bsk = nullptr;
  __uint128_t *lut_pbs = nullptr;
  __uint128_t *d_lut_pbs = nullptr;
  uint64_t *ct_in = nullptr;
  uint64_t *d_ct_in = nullptr;
  __uint128_t *d_ct_out = nullptr;
  __uint128_t *ct_out = nullptr;

  void SetUp() override {
    stream = cuda_create_stream(gpu_index);

    halfhalf_params.input_lwe_dimension = input_lwe_dimension;
    halfhalf_params.glwe_dimension = glwe_dimension;
    halfhalf_params.polynomial_size = polynomial_size;
    halfhalf_params.base_log_1_mask = base_log_1_mask;
    halfhalf_params.level_count_1_mask = level_count_1_mask;
    halfhalf_params.base_log_1_body = base_log_1_body;
    halfhalf_params.level_count_1_body = level_count_1_body;
    halfhalf_params.base_log_2_mask = base_log_2_mask;
    halfhalf_params.level_count_2_mask = level_count_2_mask;
    halfhalf_params.base_log_2_body = base_log_2_body;
    halfhalf_params.level_count_2_body = level_count_2_body;
    halfhalf_params.split_index = split_index;

    Seed seed;
    init_seed(&seed);

    generate_lwe_secret_keys_u128(&lwe_sk_in_u128, input_lwe_dimension, &seed);
    generate_glwe_secret_keys_u128(&glwe_sk_out, glwe_dimension,
                                   polynomial_size, &seed);

    // u64 copy of the binary LWE key for u64 encryption
    lwe_sk_in_u64 =
        (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(input_lwe_dimension));
    for (int i = 0; i < input_lwe_dimension; i++)
      lwe_sk_in_u64[i] = (uint64_t)lwe_sk_in_u128[i];

    generate_lwe_bootstrapping_key_u128(
        &bsk_group1_mask, lwe_sk_in_u128, glwe_sk_out, input_lwe_dimension,
        glwe_dimension, polynomial_size, level_count_1_mask, base_log_1_mask,
        &seed, new_t_uniform(30));
    shuffle_seed(&seed);
    generate_lwe_bootstrapping_key_u128(
        &bsk_group1_body, lwe_sk_in_u128, glwe_sk_out, input_lwe_dimension,
        glwe_dimension, polynomial_size, level_count_1_body, base_log_1_body,
        &seed, new_t_uniform(30));
    shuffle_seed(&seed);
    generate_lwe_bootstrapping_key_u128(
        &bsk_group2_mask, lwe_sk_in_u128, glwe_sk_out, input_lwe_dimension,
        glwe_dimension, polynomial_size, level_count_2_mask, base_log_2_mask,
        &seed, new_t_uniform(30));
    shuffle_seed(&seed);
    generate_lwe_bootstrapping_key_u128(
        &bsk_group2_body, lwe_sk_in_u128, glwe_sk_out, input_lwe_dimension,
        glwe_dimension, polynomial_size, level_count_2_body, base_log_2_body,
        &seed, new_t_uniform(30));
    shuffle_seed(&seed);

    size_t glwe_size = glwe_dimension + 1;
    size_t group1_polys = safe_mul(
        (size_t)split_index, glwe_size,
        (size_t)(glwe_dimension * level_count_1_mask + level_count_1_body));
    size_t group2_polys = safe_mul(
        (size_t)(input_lwe_dimension - split_index), glwe_size,
        (size_t)(glwe_dimension * level_count_2_mask + level_count_2_body));
    size_t halfhalf_bsk_elements =
        safe_mul(group1_polys + group2_polys, (size_t)polynomial_size);
    halfhalf_bsk = (__uint128_t *)malloc(
        safe_mul_sizeof<__uint128_t>(halfhalf_bsk_elements));

    assemble_halfhalf_bsk_u128(
        halfhalf_bsk, bsk_group1_mask, level_count_1_mask, bsk_group1_body,
        level_count_1_body, bsk_group2_mask, level_count_2_mask,
        bsk_group2_body, level_count_2_body, input_lwe_dimension,
        glwe_dimension, polynomial_size, split_index);

    ASSERT_EQ(group1_polys + group2_polys, 20316u);

    size_t fourier_bsk_size = safe_mul(
        group1_polys + group2_polys, (size_t)(polynomial_size / 2), (size_t)4);
    d_fourier_bsk = (double *)cuda_malloc_async(
        safe_mul_sizeof<double>(fourier_bsk_size), stream, gpu_index);
    cuda_convert_lwe_programmable_bootstrap_key_128_halfhalf_async(
        stream, gpu_index, (void *)d_fourier_bsk, (void *)halfhalf_bsk,
        halfhalf_params);

    delta_128 = (((__uint128_t)1) << 127) / (__uint128_t)payload_modulus;
    delta_64 = ((uint64_t)1 << 63) / (uint64_t)payload_modulus;

    lut_pbs = generate_identity_lut_pbs_u128(polynomial_size, glwe_dimension,
                                             payload_modulus, delta_128);
    size_t lut_size =
        safe_mul_sizeof<__uint128_t>(polynomial_size, glwe_dimension + 1);
    d_lut_pbs = (__uint128_t *)cuda_malloc_async(lut_size, stream, gpu_index);
    cuda_memcpy_async_to_gpu(d_lut_pbs, lut_pbs, lut_size, stream, gpu_index);

    // Input ciphertexts are u64 (noise squashing: u64 in -> u128 out)
    ct_in = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
        (size_t)num_samples, (size_t)(input_lwe_dimension + 1)));
    for (int i = 0; i < num_samples; i++) {
      int message = i % payload_modulus;
      uint64_t plaintext = (uint64_t)message * delta_64;
      uint64_t *lwe_ct_in =
          ct_in + (ptrdiff_t)((size_t)i * (input_lwe_dimension + 1));
      core_crypto_lwe_encrypt(lwe_ct_in, plaintext, lwe_sk_in_u64,
                              input_lwe_dimension, new_t_uniform(46), seed.lo,
                              seed.hi);
      shuffle_seed(&seed);
    }

    size_t ct_in_size = safe_mul_sizeof<uint64_t>(
        (size_t)num_samples, (size_t)(input_lwe_dimension + 1));
    d_ct_in = (uint64_t *)cuda_malloc_async(ct_in_size, stream, gpu_index);
    cuda_memcpy_async_to_gpu(d_ct_in, ct_in, ct_in_size, stream, gpu_index);

    size_t ct_out_size = safe_mul_sizeof<__uint128_t>(
        (size_t)num_samples, (size_t)(output_lwe_dimension + 1));
    d_ct_out = (__uint128_t *)cuda_malloc_async(ct_out_size, stream, gpu_index);
    ct_out = (__uint128_t *)malloc(ct_out_size);

    cuda_synchronize_stream(stream, gpu_index);
  }

  void TearDown() override {
    cuda_drop_async(d_fourier_bsk, stream, gpu_index);
    cuda_drop_async(d_lut_pbs, stream, gpu_index);
    cuda_drop_async(d_ct_in, stream, gpu_index);
    cuda_drop_async(d_ct_out, stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    cuda_destroy_stream(stream, gpu_index);
    free(lwe_sk_in_u128);
    free(lwe_sk_in_u64);
    free(glwe_sk_out);
    free(bsk_group1_mask);
    free(bsk_group1_body);
    free(bsk_group2_mask);
    free(bsk_group2_body);
    free(halfhalf_bsk);
    free(lut_pbs);
    free(ct_in);
    free(ct_out);
  }

  void run_and_check(const std::function<void(int8_t *buffer)> &run_pbs,
                     int8_t *buffer, uint32_t check_num_samples = 0) {
    if (check_num_samples == 0)
      check_num_samples = num_samples;

    run_pbs(buffer);

    size_t ct_out_size = safe_mul_sizeof<__uint128_t>(
        (size_t)check_num_samples, (size_t)(output_lwe_dimension + 1));
    cuda_memcpy_async_to_cpu(ct_out, d_ct_out, ct_out_size, stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    for (uint32_t i = 0; i < check_num_samples; i++) {
      int expected_message = i % payload_modulus;
      __uint128_t *result =
          ct_out + (ptrdiff_t)((size_t)i * (output_lwe_dimension + 1));

      uint64_t decrypted_low = 0, decrypted_high = 0;
      int status = core_crypto_lwe_decrypt_u128(
          &decrypted_low, &decrypted_high, (const void *)result,
          (const void *)glwe_sk_out, output_lwe_dimension);
      ASSERT_EQ(status, 0);
      __uint128_t decrypted =
          (((__uint128_t)decrypted_high) << 64) | (__uint128_t)decrypted_low;

      __uint128_t rounding_bit = delta_128 >> 1;
      __uint128_t rounding = (decrypted & rounding_bit) << 1;
      __uint128_t decoded = (decrypted + rounding) / delta_128;

      ASSERT_EQ((uint64_t)decoded, (uint64_t)expected_message);
    }
  }
};

TEST_F(ClassicalProgrammableBootstrap128HalfhalfTest, default_variant) {
  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_halfhalf_default_async(
      stream, gpu_index, &pbs_buffer, halfhalf_params, num_samples, true,
      PBS_MS_REDUCTION_T::CENTERED);

  run_and_check(
      [&](int8_t *buffer) {
        cuda_programmable_bootstrap_128_halfhalf_default_async(
            stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs,
            (void *)d_ct_in, (void *)d_fourier_bsk, buffer, halfhalf_params,
            num_samples);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                   &pbs_buffer);
}

TEST_F(ClassicalProgrammableBootstrap128HalfhalfTest, auto_dispatch) {
  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_halfhalf_async(
      stream, gpu_index, &pbs_buffer, halfhalf_params, num_samples, true,
      PBS_MS_REDUCTION_T::CENTERED);

  run_and_check(
      [&](int8_t *buffer) {
        cuda_programmable_bootstrap_128_halfhalf_async(
            stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs,
            (void *)d_ct_in, (void *)d_fourier_bsk, buffer, halfhalf_params,
            num_samples);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                   &pbs_buffer);
}

// auto_dispatch above runs at num_samples, which is past the measured bound
// that favors CG, so it only ever exercises the DEFAULT branch of the chain.
// Both batches here are at or below that bound, so both select CG, the second
// one sitting exactly on it. Both have to decrypt correctly.
TEST_F(ClassicalProgrammableBootstrap128HalfhalfTest,
       auto_dispatch_small_batch) {
  for (uint32_t batch_num_samples : {4u, 8u}) {
    SCOPED_TRACE("batch_num_samples=" + std::to_string(batch_num_samples));
    ASSERT_LE(batch_num_samples, (uint32_t)num_samples)
        << "the fixture only encrypts num_samples inputs";

    int8_t *pbs_buffer = nullptr;
    scratch_cuda_programmable_bootstrap_128_halfhalf_async(
        stream, gpu_index, &pbs_buffer, halfhalf_params, batch_num_samples,
        true, PBS_MS_REDUCTION_T::CENTERED);

    run_and_check(
        [&](int8_t *buffer) {
          cuda_programmable_bootstrap_128_halfhalf_async(
              stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs,
              (void *)d_ct_in, (void *)d_fourier_bsk, buffer, halfhalf_params,
              batch_num_samples);
        },
        pbs_buffer, batch_num_samples);

    cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                     &pbs_buffer);
  }
}

TEST_F(ClassicalProgrammableBootstrap128HalfhalfTest, cg_variant) {
  int max_level = std::max({level_count_1_mask, level_count_1_body,
                            level_count_2_mask, level_count_2_body});
  uint32_t cg_num_samples = num_samples;
  while (cg_num_samples > 0 &&
         !supports_cooperative_groups_on_programmable_bootstrap_128_halfhalf(
             glwe_dimension, polynomial_size, max_level, cg_num_samples,
             cuda_get_max_shared_memory(gpu_index))) {
    cg_num_samples /= 2;
  }
  if (cg_num_samples == 0) {
    GTEST_SKIP()
        << "CG 128-bit halfhalf PBS is not supported on this architecture.";
  }
  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_halfhalf_cg_async(
      stream, gpu_index, &pbs_buffer, halfhalf_params, cg_num_samples, true,
      PBS_MS_REDUCTION_T::CENTERED);

  uint32_t total_checked = 0;
  while (total_checked < (uint32_t)num_samples) {
    uint32_t batch =
        std::min(cg_num_samples, (uint32_t)num_samples - total_checked);
    auto *batch_ct_in = d_ct_in + (ptrdiff_t)((size_t)total_checked *
                                              (input_lwe_dimension + 1));
    auto *batch_ct_out = d_ct_out + (ptrdiff_t)((size_t)total_checked *
                                                (output_lwe_dimension + 1));

    cuda_programmable_bootstrap_128_halfhalf_cg_async(
        stream, gpu_index, (void *)batch_ct_out, (void *)d_lut_pbs,
        (void *)batch_ct_in, (void *)d_fourier_bsk, pbs_buffer, halfhalf_params,
        batch);

    size_t ct_out_bytes = safe_mul_sizeof<__uint128_t>(
        (size_t)batch, (size_t)(output_lwe_dimension + 1));
    cuda_memcpy_async_to_cpu(ct_out, batch_ct_out, ct_out_bytes, stream,
                             gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    for (uint32_t i = 0; i < batch; i++) {
      int expected_message = (total_checked + i) % payload_modulus;
      __uint128_t *result =
          ct_out + (ptrdiff_t)((size_t)i * (output_lwe_dimension + 1));

      uint64_t decrypted_low = 0, decrypted_high = 0;
      int status = core_crypto_lwe_decrypt_u128(
          &decrypted_low, &decrypted_high, (const void *)result,
          (const void *)glwe_sk_out, output_lwe_dimension);
      ASSERT_EQ(status, 0);
      __uint128_t decrypted =
          (((__uint128_t)decrypted_high) << 64) | (__uint128_t)decrypted_low;

      __uint128_t rounding_bit = delta_128 >> 1;
      __uint128_t rounding = (decrypted & rounding_bit) << 1;
      __uint128_t decoded = (decrypted + rounding) / delta_128;

      ASSERT_EQ((uint64_t)decoded, (uint64_t)expected_message);
    }
    total_checked += batch;
  }

  cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                   &pbs_buffer);
}

// Relaxed arithmetic, host-driven thread block cluster flavor. It needs
// distributed shared memory, so compute capability 9.0, and is only compiled
// for the fixture's parameters; the support check covers both conditions.
//
// The flavor drops error-correction terms in the Fourier-domain products, so
// this asserts the same exact decryption as the other variants: the relaxed
// error has to stay well inside the noise-squashing padding at these
// parameters, and a result that only decrypts "close enough" is a failure.
TEST_F(ClassicalProgrammableBootstrap128HalfhalfTest, relaxed_variant) {
  if (!supports_relaxed_on_programmable_bootstrap_128_halfhalf(
          halfhalf_params, cuda_get_max_shared_memory(gpu_index))) {
    GTEST_SKIP() << "the relaxed 128-bit halfhalf PBS is not supported on this "
                    "architecture or at these parameters.";
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
      stream, gpu_index, &pbs_buffer, halfhalf_params, num_samples, true,
      PBS_MS_REDUCTION_T::CENTERED);

  run_and_check(
      [&](int8_t *buffer) {
        cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
            stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs,
            (void *)d_ct_in, (void *)d_fourier_bsk, buffer, halfhalf_params,
            num_samples);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                   &pbs_buffer);
}

// On architectures without distributed shared memory (compute capability < 9.0)
// the test-only relaxed entry point panics immediately rather than silently
// falling back to the DEFAULT variant. This verifies that behavior on such
// devices. The test skips on devices where the flavor is supported, because
// there the panic path does not apply.
TEST_F(ClassicalProgrammableBootstrap128HalfhalfTest,
       relaxed_entry_panics_on_unsupported_architecture) {
  if (supports_relaxed_on_programmable_bootstrap_128_halfhalf(
          halfhalf_params, cuda_get_max_shared_memory(gpu_index))) {
    GTEST_SKIP() << "relaxed flavor is supported on this architecture; "
                    "the architecture-gate panic does not apply.";
  }
  // The fixture holds a live CUDA context and a stream. The default "fast"
  // death-test style forks without re-execing, which leaves the child sharing
  // driver state it does not own; "threadsafe" re-execs the test binary so the
  // child builds its own context.
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  ASSERT_DEATH(
      {
        int8_t *pbs_buffer = nullptr;
        scratch_cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
            stream, gpu_index, &pbs_buffer, halfhalf_params, num_samples, true,
            PBS_MS_REDUCTION_T::CENTERED);
      },
      "distributed shared memory");
}

// The blind rotation walks one launch per key entry with the accumulator living
// in global memory between them, so a batch that does not fill the device
// exercises a different residency than the full batch above. Both must decrypt.
TEST_F(ClassicalProgrammableBootstrap128HalfhalfTest,
       relaxed_variant_small_batch) {
  if (!supports_relaxed_on_programmable_bootstrap_128_halfhalf(
          halfhalf_params, cuda_get_max_shared_memory(gpu_index))) {
    GTEST_SKIP() << "the relaxed 128-bit halfhalf PBS is not supported on this "
                    "architecture or at these parameters.";
  }

  for (uint32_t batch_num_samples : {1u, 8u}) {
    SCOPED_TRACE("batch_num_samples=" + std::to_string(batch_num_samples));
    ASSERT_LE(batch_num_samples, (uint32_t)num_samples)
        << "the fixture only encrypts num_samples inputs";

    int8_t *pbs_buffer = nullptr;
    scratch_cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
        stream, gpu_index, &pbs_buffer, halfhalf_params, batch_num_samples,
        true, PBS_MS_REDUCTION_T::CENTERED);

    run_and_check(
        [&](int8_t *buffer) {
          cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
              stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs,
              (void *)d_ct_in, (void *)d_fourier_bsk, buffer, halfhalf_params,
              batch_num_samples);
        },
        pbs_buffer, batch_num_samples);

    cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                     &pbs_buffer);
  }
}
