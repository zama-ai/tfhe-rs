#include <cstdint>
#include <cstdlib>
#include <functional>
#include <gtest/gtest.h>
#include <pbs/pbs_utilities.h>
#include <pbs/programmable_bootstrap.h>
#include <pbs/programmable_bootstrap_testing_128.h>
#include <utils.h>

#include "checked_arithmetic.h"

// Correctness test for the classical (vanilla) 128-bit programmable
// bootstrap (noise squashing). The kernel takes u64 input LWE ciphertexts
// and produces u128 output LWE ciphertexts via a u128 BSK and LUT.
class ClassicalProgrammableBootstrap128Test : public ::testing::Test {
protected:
  static constexpr int input_lwe_dimension = 918;
  static constexpr int glwe_dimension = 2;
  static constexpr int polynomial_size = 2048;
  static constexpr int pbs_base_log = 24;
  static constexpr int pbs_level = 3;
  static constexpr int payload_modulus = 16;
  static constexpr int output_lwe_dimension = glwe_dimension * polynomial_size;
  static constexpr int nb_tests = 5;
  static constexpr int num_samples = payload_modulus * nb_tests;

  cudaStream_t stream;
  uint32_t gpu_index = 0;
  __uint128_t delta_128;
  uint64_t delta_64;

  __uint128_t *lwe_sk_in_u128 = nullptr;
  uint64_t *lwe_sk_in_u64 = nullptr;
  __uint128_t *glwe_sk_out = nullptr;
  __uint128_t *bsk = nullptr;
  double *d_fourier_bsk = nullptr;
  __uint128_t *lut_pbs = nullptr;
  __uint128_t *d_lut_pbs = nullptr;
  uint64_t *ct_in = nullptr;
  uint64_t *d_ct_in = nullptr;
  __uint128_t *d_ct_out = nullptr;
  __uint128_t *ct_out = nullptr;

  void SetUp() override {
    stream = cuda_create_stream(gpu_index);

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
        &bsk, lwe_sk_in_u128, glwe_sk_out, input_lwe_dimension, glwe_dimension,
        polynomial_size, pbs_level, pbs_base_log, &seed, new_t_uniform(30));

    size_t total_polynomials =
        safe_mul((size_t)input_lwe_dimension, (size_t)(glwe_dimension + 1),
                 (size_t)(glwe_dimension + 1), (size_t)pbs_level);
    size_t fourier_bsk_size =
        safe_mul(total_polynomials, (size_t)(polynomial_size / 2), (size_t)4);
    d_fourier_bsk = (double *)cuda_malloc_async(
        safe_mul_sizeof<double>(fourier_bsk_size), stream, gpu_index);
    cuda_convert_lwe_programmable_bootstrap_key_128_async(
        stream, gpu_index, (void *)d_fourier_bsk, (void *)bsk,
        input_lwe_dimension, glwe_dimension, pbs_level, polynomial_size);

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
    free(bsk);
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

TEST_F(ClassicalProgrammableBootstrap128Test, default_variant) {
  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_default_async(
      stream, gpu_index, &pbs_buffer, input_lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, num_samples, true,
      PBS_MS_REDUCTION_T::CENTERED);

  run_and_check(
      [&](int8_t *buffer) {
        cuda_programmable_bootstrap_128_default_async(
            stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs,
            (void *)d_ct_in, (void *)d_fourier_bsk, buffer, input_lwe_dimension,
            glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
            num_samples);
      },
      pbs_buffer);

  cleanup_cuda_programmable_bootstrap_128(stream, gpu_index, &pbs_buffer);
}

TEST_F(ClassicalProgrammableBootstrap128Test, cg_variant) {
  uint32_t cg_num_samples = num_samples;
  while (cg_num_samples > 0 &&
         !has_support_to_cuda_programmable_bootstrap_128_cg(
             glwe_dimension, polynomial_size, pbs_level, cg_num_samples,
             cuda_get_max_shared_memory(gpu_index))) {
    cg_num_samples /= 2;
  }
  if (cg_num_samples == 0) {
    GTEST_SKIP() << "CG 128-bit PBS is not supported on this architecture.";
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_cg_async(
      stream, gpu_index, &pbs_buffer, input_lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, cg_num_samples, true,
      PBS_MS_REDUCTION_T::CENTERED);

  run_and_check(
      [&](int8_t *buffer) {
        cuda_programmable_bootstrap_128_cg_async(
            stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs,
            (void *)d_ct_in, (void *)d_fourier_bsk, buffer, input_lwe_dimension,
            glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
            cg_num_samples);
      },
      pbs_buffer, cg_num_samples);

  cleanup_cuda_programmable_bootstrap_128(stream, gpu_index, &pbs_buffer);
}
