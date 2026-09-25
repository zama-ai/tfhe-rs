#include <algorithm>
#include <benchmark/benchmark.h>
#include <cstdint>
#include <pbs/pbs_utilities.h>
#include <pbs/programmable_bootstrap.h>
#include <pbs/programmable_bootstrap_testing_128.h>
#include <utils.h>

#include "checked_arithmetic.h"

class ClassicalBootstrap128_vanilla : public benchmark::Fixture {
protected:
  static constexpr int input_lwe_dimension = 918;
  static constexpr int glwe_dimension = 2;
  static constexpr int polynomial_size = 2048;
  static constexpr int pbs_base_log = 24;
  static constexpr int pbs_level = 3;
  static constexpr int payload_modulus = 16;
  static constexpr int output_lwe_dimension = glwe_dimension * polynomial_size;

  int input_lwe_ciphertext_count;
  __uint128_t delta_128;
  uint64_t delta_64;
  cudaStream_t stream;
  uint32_t gpu_index = 0;

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

public:
  void SetUp(const ::benchmark::State &state) {
    input_lwe_ciphertext_count = state.range(0);
    stream = cuda_create_stream(gpu_index);

    Seed seed;
    init_seed(&seed);

    generate_lwe_secret_keys_u128(&lwe_sk_in_u128, input_lwe_dimension, &seed);
    generate_glwe_secret_keys_u128(&glwe_sk_out, glwe_dimension,
                                   polynomial_size, &seed);

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

    ct_in = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
        (size_t)input_lwe_ciphertext_count, (size_t)(input_lwe_dimension + 1)));
    for (int i = 0; i < input_lwe_ciphertext_count; i++) {
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
        (size_t)input_lwe_ciphertext_count, (size_t)(input_lwe_dimension + 1));
    d_ct_in = (uint64_t *)cuda_malloc_async(ct_in_size, stream, gpu_index);
    cuda_memcpy_async_to_gpu(d_ct_in, ct_in, ct_in_size, stream, gpu_index);

    size_t ct_out_size = safe_mul_sizeof<__uint128_t>(
        (size_t)input_lwe_ciphertext_count, (size_t)(output_lwe_dimension + 1));
    d_ct_out = (__uint128_t *)cuda_malloc_async(ct_out_size, stream, gpu_index);

    cuda_synchronize_stream(stream, gpu_index);
  }

  void TearDown(const ::benchmark::State &state) {
    (void)state;
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
    cudaDeviceReset();
  }
};

class ClassicalBootstrap128_halfhalf : public benchmark::Fixture {
protected:
  static constexpr int input_lwe_dimension = 918;
  static constexpr int glwe_dimension = 2;
  static constexpr int polynomial_size = 2048;
  static constexpr int payload_modulus = 16;
  static constexpr int output_lwe_dimension = glwe_dimension * polynomial_size;

  static constexpr int split_index = 286;
  static constexpr int base_log_1_mask = 32;
  static constexpr int level_count_1_mask = 2;
  static constexpr int base_log_1_body = 31;
  static constexpr int level_count_1_body = 2;
  static constexpr int base_log_2_mask = 24;
  static constexpr int level_count_2_mask = 3;
  static constexpr int base_log_2_body = 31;
  static constexpr int level_count_2_body = 2;

  int input_lwe_ciphertext_count;
  __uint128_t delta_128;
  uint64_t delta_64;
  CudaHalfhalfPbsParamsFFI halfhalf_params;
  cudaStream_t stream;
  uint32_t gpu_index = 0;

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

public:
  void SetUp(const ::benchmark::State &state) {
    input_lwe_ciphertext_count = state.range(0);
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

    ct_in = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
        (size_t)input_lwe_ciphertext_count, (size_t)(input_lwe_dimension + 1)));
    for (int i = 0; i < input_lwe_ciphertext_count; i++) {
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
        (size_t)input_lwe_ciphertext_count, (size_t)(input_lwe_dimension + 1));
    d_ct_in = (uint64_t *)cuda_malloc_async(ct_in_size, stream, gpu_index);
    cuda_memcpy_async_to_gpu(d_ct_in, ct_in, ct_in_size, stream, gpu_index);

    size_t ct_out_size = safe_mul_sizeof<__uint128_t>(
        (size_t)input_lwe_ciphertext_count, (size_t)(output_lwe_dimension + 1));
    d_ct_out = (__uint128_t *)cuda_malloc_async(ct_out_size, stream, gpu_index);

    cuda_synchronize_stream(stream, gpu_index);
  }

  void TearDown(const ::benchmark::State &state) {
    (void)state;
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
    cudaDeviceReset();
  }
};

// --- Vanilla PBS-128 benchmarks ---

BENCHMARK_DEFINE_F(ClassicalBootstrap128_vanilla, DefaultPBS128)
(benchmark::State &st) {
  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_default_async(
      stream, gpu_index, &pbs_buffer, input_lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, input_lwe_ciphertext_count, true,
      PBS_MS_REDUCTION_T::CENTERED);

  for (auto _ : st) {
    cuda_programmable_bootstrap_128_default_async(
        stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs, (void *)d_ct_in,
        (void *)d_fourier_bsk, pbs_buffer, input_lwe_dimension, glwe_dimension,
        polynomial_size, pbs_base_log, pbs_level, input_lwe_ciphertext_count);
    cuda_synchronize_stream(stream, gpu_index);
  }

  st.counters["batch/s"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate);
  cleanup_cuda_programmable_bootstrap_128(stream, gpu_index, &pbs_buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap128_vanilla, CgPBS128)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_128_cg(
          glwe_dimension, polynomial_size, pbs_level,
          input_lwe_ciphertext_count, cuda_get_max_shared_memory(gpu_index))) {
    st.SkipWithError("CG 128-bit PBS not supported on this configuration");
    return;
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_cg_async(
      stream, gpu_index, &pbs_buffer, input_lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, input_lwe_ciphertext_count, true,
      PBS_MS_REDUCTION_T::CENTERED);

  for (auto _ : st) {
    cuda_programmable_bootstrap_128_cg_async(
        stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs, (void *)d_ct_in,
        (void *)d_fourier_bsk, pbs_buffer, input_lwe_dimension, glwe_dimension,
        polynomial_size, pbs_base_log, pbs_level, input_lwe_ciphertext_count);
    cuda_synchronize_stream(stream, gpu_index);
  }

  st.counters["batch/s"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate);
  cleanup_cuda_programmable_bootstrap_128(stream, gpu_index, &pbs_buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap128_vanilla, TbcPBS128)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_128_tbc(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          pbs_level, cuda_get_max_shared_memory(gpu_index))) {
    st.SkipWithError("TBC 128-bit PBS not supported on this configuration");
    return;
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_tbc_async(
      stream, gpu_index, &pbs_buffer, input_lwe_dimension, glwe_dimension,
      polynomial_size, pbs_level, input_lwe_ciphertext_count, true,
      PBS_MS_REDUCTION_T::CENTERED);

  for (auto _ : st) {
    cuda_programmable_bootstrap_128_tbc_async(
        stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs, (void *)d_ct_in,
        (void *)d_fourier_bsk, pbs_buffer, input_lwe_dimension, glwe_dimension,
        polynomial_size, pbs_base_log, pbs_level, input_lwe_ciphertext_count);
    cuda_synchronize_stream(stream, gpu_index);
  }

  st.counters["batch/s"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate);
  cleanup_cuda_programmable_bootstrap_128(stream, gpu_index, &pbs_buffer);
}

// --- Halfhalf PBS-128 benchmarks ---

BENCHMARK_DEFINE_F(ClassicalBootstrap128_halfhalf, DefaultPBS128Halfhalf)
(benchmark::State &st) {
  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_halfhalf_default_async(
      stream, gpu_index, &pbs_buffer, halfhalf_params,
      input_lwe_ciphertext_count, true, PBS_MS_REDUCTION_T::CENTERED);

  for (auto _ : st) {
    cuda_programmable_bootstrap_128_halfhalf_default_async(
        stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs, (void *)d_ct_in,
        (void *)d_fourier_bsk, pbs_buffer, halfhalf_params,
        input_lwe_ciphertext_count);
    cuda_synchronize_stream(stream, gpu_index);
  }

  st.counters["batch/s"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate);
  cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                   &pbs_buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap128_halfhalf, CgPBS128Halfhalf)
(benchmark::State &st) {
  int max_level = std::max({level_count_1_mask, level_count_1_body,
                            level_count_2_mask, level_count_2_body});
  if (!supports_cooperative_groups_on_programmable_bootstrap_128_halfhalf(
          glwe_dimension, polynomial_size, max_level,
          input_lwe_ciphertext_count, cuda_get_max_shared_memory(gpu_index))) {
    st.SkipWithError(
        "CG 128-bit halfhalf PBS not supported on this configuration");
    return;
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_halfhalf_cg_async(
      stream, gpu_index, &pbs_buffer, halfhalf_params,
      input_lwe_ciphertext_count, true, PBS_MS_REDUCTION_T::CENTERED);

  for (auto _ : st) {
    cuda_programmable_bootstrap_128_halfhalf_cg_async(
        stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs, (void *)d_ct_in,
        (void *)d_fourier_bsk, pbs_buffer, halfhalf_params,
        input_lwe_ciphertext_count);
    cuda_synchronize_stream(stream, gpu_index);
  }

  st.counters["batch/s"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate);
  cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                   &pbs_buffer);
}

// Relaxed arithmetic, host-driven thread block cluster flavor. It uses the
// explicit entry point rather than the TFHE_RS_GPU_PBS128_RELAXED_TBC
// dispatcher, so the flavor under measurement is unambiguous, the way every
// other variant here is selected explicitly. Needs distributed shared memory
// and the noise-squashing shape, both covered by the support check.
BENCHMARK_DEFINE_F(ClassicalBootstrap128_halfhalf, RelaxedPBS128Halfhalf)
(benchmark::State &st) {
  if (!supports_relaxed_on_programmable_bootstrap_128_halfhalf(
          halfhalf_params, cuda_get_max_shared_memory(gpu_index))) {
    st.SkipWithError("relaxed 128-bit halfhalf PBS not supported on this "
                     "architecture or at these parameters");
    return;
  }

  int8_t *pbs_buffer = nullptr;
  scratch_cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
      stream, gpu_index, &pbs_buffer, halfhalf_params,
      input_lwe_ciphertext_count, true, PBS_MS_REDUCTION_T::CENTERED);

  for (auto _ : st) {
    cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
        stream, gpu_index, (void *)d_ct_out, (void *)d_lut_pbs, (void *)d_ct_in,
        (void *)d_fourier_bsk, pbs_buffer, halfhalf_params,
        input_lwe_ciphertext_count);
    cuda_synchronize_stream(stream, gpu_index);
  }

  st.counters["batch/s"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate);
  cleanup_cuda_programmable_bootstrap_128_halfhalf(stream, gpu_index,
                                                   &pbs_buffer);
}

// --- Parameter sweep ---

static void PBS128BenchmarkGenerateParams(benchmark::internal::Benchmark *b) {
  for (int num_samples = 1; num_samples <= 128; num_samples *= 2)
    b->Args({num_samples});
}

// --- Registration ---

BENCHMARK_REGISTER_F(ClassicalBootstrap128_vanilla, DefaultPBS128)
    ->Apply(PBS128BenchmarkGenerateParams)
    ->ArgNames({"input_lwe_ciphertext_count"})
    ->UseRealTime();

BENCHMARK_REGISTER_F(ClassicalBootstrap128_vanilla, CgPBS128)
    ->Apply(PBS128BenchmarkGenerateParams)
    ->ArgNames({"input_lwe_ciphertext_count"})
    ->UseRealTime();

BENCHMARK_REGISTER_F(ClassicalBootstrap128_vanilla, TbcPBS128)
    ->Apply(PBS128BenchmarkGenerateParams)
    ->ArgNames({"input_lwe_ciphertext_count"})
    ->UseRealTime();

BENCHMARK_REGISTER_F(ClassicalBootstrap128_halfhalf, DefaultPBS128Halfhalf)
    ->Apply(PBS128BenchmarkGenerateParams)
    ->ArgNames({"input_lwe_ciphertext_count"})
    ->UseRealTime();

BENCHMARK_REGISTER_F(ClassicalBootstrap128_halfhalf, CgPBS128Halfhalf)
    ->Apply(PBS128BenchmarkGenerateParams)
    ->ArgNames({"input_lwe_ciphertext_count"})
    ->UseRealTime();

BENCHMARK_REGISTER_F(ClassicalBootstrap128_halfhalf, RelaxedPBS128Halfhalf)
    ->Apply(PBS128BenchmarkGenerateParams)
    ->ArgNames({"input_lwe_ciphertext_count"})
    ->UseRealTime();
