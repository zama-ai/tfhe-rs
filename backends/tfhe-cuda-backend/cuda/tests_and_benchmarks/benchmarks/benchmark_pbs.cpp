#include <benchmark/benchmark.h>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <omp.h>
#include <setup_and_teardown.h>

typedef struct {
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  int pbs_base_log;
  int pbs_level;
  int input_lwe_ciphertext_count;
  int grouping_factor;
  int chunk_size;
} MultiBitPBSBenchmarkParams;

typedef struct {
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  int pbs_base_log;
  int pbs_level;
  int input_lwe_ciphertext_count;
} BootstrapBenchmarkParams;

class MultiBitBootstrap_u64 : public benchmark::Fixture {
protected:
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  int input_lwe_ciphertext_count;
  int grouping_factor;
  DynamicDistribution lwe_modular_variance;
  DynamicDistribution glwe_modular_variance;
  int pbs_base_log;
  int pbs_level;
  int message_modulus = 4;
  int carry_modulus = 4;
  int payload_modulus;
  uint64_t delta;
  cuda_stream_t *stream;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  uint64_t *d_bsk;
  uint64_t *d_lut_pbs_identity;
  uint64_t *d_lut_pbs_indexes;
  uint64_t *d_lwe_ct_in_array;
  uint64_t *d_lwe_ct_out_array;
  uint64_t *lwe_ct_out_array;
  uint64_t *d_lwe_input_indexes;
  uint64_t *d_lwe_output_indexes;
  int8_t *buffer;

  int chunk_size;

public:
  void SetUp(const ::benchmark::State &state) {
    int gpu_index = 0;
    stream = cuda_create_stream(gpu_index);

    lwe_dimension = state.range(0);
    glwe_dimension = state.range(1);
    polynomial_size = state.range(2);
    pbs_base_log = state.range(3);
    pbs_level = state.range(4);
    input_lwe_ciphertext_count = state.range(5);
    grouping_factor = state.range(6);
    chunk_size = state.range(7);

    DynamicDistribution lwe_modular_variance =
        new_gaussian_from_std_dev(sqrt(0.000007069849454709433));
    DynamicDistribution glwe_modular_variance =
        new_gaussian_from_std_dev(sqrt(0.00000000000000029403601535432533));

    Seed seed;
    init_seed(&seed);

    programmable_bootstrap_multibit_setup(
        stream, &seed, &lwe_sk_in_array, &lwe_sk_out_array, &d_bsk, &plaintexts,
        &d_lut_pbs_identity, &d_lut_pbs_indexes, &d_lwe_ct_in_array,
        &d_lwe_input_indexes, &d_lwe_ct_out_array, &d_lwe_output_indexes,
        lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
        lwe_modular_variance, glwe_modular_variance, pbs_base_log, pbs_level,
        message_modulus, carry_modulus, &payload_modulus, &delta,
        input_lwe_ciphertext_count, 1, 1);
  }

  void TearDown(const ::benchmark::State &state) {
    programmable_bootstrap_multibit_teardown(
        stream, lwe_sk_in_array, lwe_sk_out_array, d_bsk, plaintexts,
        d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_lwe_ct_out_array, d_lwe_output_indexes);
    cudaDeviceReset();
  }
};

class ClassicalBootstrap_u64 : public benchmark::Fixture {
protected:
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  int input_lwe_ciphertext_count;
  DynamicDistribution lwe_modular_variance;
  DynamicDistribution glwe_modular_variance;
  int pbs_base_log;
  int pbs_level;
  int message_modulus = 4;
  int carry_modulus = 4;
  int payload_modulus;
  uint64_t delta;
  double *d_fourier_bsk;
  uint64_t *d_lut_pbs_identity;
  uint64_t *d_lut_pbs_indexes;
  uint64_t *d_lwe_input_indexes;
  uint64_t *d_lwe_output_indexes;
  uint64_t *d_lwe_ct_in_array;
  uint64_t *d_lwe_ct_out_array;
  uint64_t *lwe_ct_array;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  int8_t *buffer;

  cuda_stream_t *stream;

public:
  void SetUp(const ::benchmark::State &state) {
    int gpu_index = 0;
    stream = cuda_create_stream(gpu_index);

    lwe_dimension = state.range(0);
    glwe_dimension = state.range(1);
    polynomial_size = state.range(2);
    pbs_base_log = state.range(3);
    pbs_level = state.range(4);
    input_lwe_ciphertext_count = state.range(5);

    DynamicDistribution lwe_modular_variance =
        new_gaussian_from_std_dev(sqrt(0.000007069849454709433));
    DynamicDistribution glwe_modular_variance =
        new_gaussian_from_std_dev(sqrt(0.00000000000000029403601535432533));

    Seed seed;
    init_seed(&seed);

    programmable_bootstrap_classical_setup(
        stream, &seed, &lwe_sk_in_array, &lwe_sk_out_array, &d_fourier_bsk,
        &plaintexts, &d_lut_pbs_identity, &d_lut_pbs_indexes,
        &d_lwe_ct_in_array, &d_lwe_input_indexes, &d_lwe_ct_out_array,
        &d_lwe_output_indexes, lwe_dimension, glwe_dimension, polynomial_size,
        lwe_modular_variance, glwe_modular_variance, pbs_base_log, pbs_level,
        message_modulus, carry_modulus, &payload_modulus, &delta,
        input_lwe_ciphertext_count, 1, 1);
  }

  void TearDown(const ::benchmark::State &state) {
    programmable_bootstrap_classical_teardown(
        stream, lwe_sk_in_array, lwe_sk_out_array, d_fourier_bsk, plaintexts,
        d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_lwe_ct_out_array, d_lwe_output_indexes);

    cudaDeviceReset();
  }
};

BENCHMARK_DEFINE_F(MultiBitBootstrap_u64, CgMultiBit)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
          glwe_dimension, polynomial_size, pbs_level,
          input_lwe_ciphertext_count,
          cuda_get_max_shared_memory(stream->gpu_index))) {
    st.SkipWithError("Configuration not supported for fast operation");
    return;
  }

  scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
      stream, (pbs_buffer<uint64_t, MULTI_BIT> **)&buffer, lwe_dimension,
      glwe_dimension, polynomial_size, pbs_level, grouping_factor,
      input_lwe_ciphertext_count, cuda_get_max_shared_memory(stream->gpu_index),
      true, chunk_size);

  for (auto _ : st) {
    // Execute PBS
    cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
        stream, d_lwe_ct_out_array, d_lwe_output_indexes, d_lut_pbs_identity,
        d_lut_pbs_indexes, d_lwe_ct_in_array, d_lwe_input_indexes, d_bsk,
        (pbs_buffer<uint64_t, MULTI_BIT> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
        pbs_level, input_lwe_ciphertext_count, 1, 0,
        cuda_get_max_shared_memory(stream->gpu_index), chunk_size);
    cuda_synchronize_stream(stream);
  }

  cleanup_cuda_multi_bit_programmable_bootstrap(stream, &buffer);
}

BENCHMARK_DEFINE_F(MultiBitBootstrap_u64, DefaultMultiBit)
(benchmark::State &st) {
  scratch_cuda_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
      stream, (pbs_buffer<uint64_t, MULTI_BIT> **)&buffer, lwe_dimension,
      glwe_dimension, polynomial_size, pbs_level, grouping_factor,
      input_lwe_ciphertext_count, cuda_get_max_shared_memory(stream->gpu_index),
      true, chunk_size);

  for (auto _ : st) {
    // Execute PBS
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
        stream, d_lwe_ct_out_array, d_lwe_output_indexes, d_lut_pbs_identity,
        d_lut_pbs_indexes, d_lwe_ct_in_array, d_lwe_input_indexes, d_bsk,
        (pbs_buffer<uint64_t, MULTI_BIT> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
        pbs_level, input_lwe_ciphertext_count, 1, 0,
        cuda_get_max_shared_memory(stream->gpu_index), chunk_size);
    cuda_synchronize_stream(stream);
  }

  cleanup_cuda_multi_bit_programmable_bootstrap(stream, &buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap_u64, CgPBS)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_cg<uint64_t>(
          glwe_dimension, polynomial_size, pbs_level,
          input_lwe_ciphertext_count,
          cuda_get_max_shared_memory(stream->gpu_index))) {
    st.SkipWithError("Configuration not supported for fast operation");
    return;
  }

  scratch_cuda_programmable_bootstrap_cg<uint64_t, int64_t>(
      stream, (pbs_buffer<uint64_t, CLASSICAL> **)&buffer, glwe_dimension,
      polynomial_size, pbs_level, input_lwe_ciphertext_count,
      cuda_get_max_shared_memory(stream->gpu_index), true);

  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_cg_lwe_ciphertext_vector<uint64_t>(
        stream, (uint64_t *)d_lwe_ct_out_array,
        (uint64_t *)d_lwe_output_indexes, (uint64_t *)d_lut_pbs_identity,
        (uint64_t *)d_lut_pbs_indexes, (uint64_t *)d_lwe_ct_in_array,
        (uint64_t *)d_lwe_input_indexes, (double2 *)d_fourier_bsk,
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        input_lwe_ciphertext_count, 1, 0,
        cuda_get_max_shared_memory(stream->gpu_index));
    cuda_synchronize_stream(stream);
  }

  cleanup_cuda_programmable_bootstrap(stream, &buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap_u64, DefaultPBS)
(benchmark::State &st) {

  scratch_cuda_programmable_bootstrap<uint64_t, int64_t>(
      stream, (pbs_buffer<uint64_t, CLASSICAL> **)&buffer, glwe_dimension,
      polynomial_size, pbs_level, input_lwe_ciphertext_count,
      cuda_get_max_shared_memory(stream->gpu_index), true);

  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, (uint64_t *)d_lwe_ct_out_array,
        (uint64_t *)d_lwe_output_indexes, (uint64_t *)d_lut_pbs_identity,
        (uint64_t *)d_lut_pbs_indexes, (uint64_t *)d_lwe_ct_in_array,
        (uint64_t *)d_lwe_input_indexes, (double2 *)d_fourier_bsk,
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        input_lwe_ciphertext_count, 1, 0,
        cuda_get_max_shared_memory(stream->gpu_index));
    cuda_synchronize_stream(stream);
  }

  cleanup_cuda_programmable_bootstrap(stream, &buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap_u64, AmortizedPBS)
(benchmark::State &st) {

  scratch_cuda_programmable_bootstrap_amortized_64(
      stream, &buffer, glwe_dimension, polynomial_size,
      input_lwe_ciphertext_count, cuda_get_max_shared_memory(stream->gpu_index),
      true);

  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_amortized_lwe_ciphertext_vector_64(
        stream, (void *)d_lwe_ct_out_array, (void *)d_lwe_output_indexes,
        (void *)d_lut_pbs_identity, (void *)d_lut_pbs_indexes,
        (void *)d_lwe_ct_in_array, (void *)d_lwe_input_indexes,
        (void *)d_fourier_bsk, buffer, lwe_dimension, glwe_dimension,
        polynomial_size, pbs_base_log, pbs_level, input_lwe_ciphertext_count, 1,
        0, cuda_get_max_shared_memory(stream->gpu_index));
    cuda_synchronize_stream(stream);
  }

  cleanup_cuda_programmable_bootstrap_amortized(stream, &buffer);
}

static void
MultiBitPBSBenchmarkGenerateParams(benchmark::internal::Benchmark *b) {
  // Define the parameters to benchmark
  // lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
  // input_lwe_ciphertext_count
  std::vector<MultiBitPBSBenchmarkParams> params = {
      // 4_bits_multi_bit_group_2
      (MultiBitPBSBenchmarkParams){818, 1, 2048, 22, 1, 1, 2, 0},
      // 4_bits_multi_bit_group_3
      (MultiBitPBSBenchmarkParams){888, 1, 2048, 21, 1, 1, 3, 0},
  };

  // Add to the list of parameters to benchmark
  for (auto x : params) {
    for (int input_lwe_ciphertext_count = 1; input_lwe_ciphertext_count <= 4096;
         input_lwe_ciphertext_count *= 2) {
      for (int lwe_chunk_size = 1;
           lwe_chunk_size <= x.lwe_dimension / x.grouping_factor;
           lwe_chunk_size *= 2)
        b->Args({x.lwe_dimension, x.glwe_dimension, x.polynomial_size,
                 x.pbs_base_log, x.pbs_level, input_lwe_ciphertext_count,
                 x.grouping_factor, lwe_chunk_size});

      int lwe_chunk_size = x.lwe_dimension / x.grouping_factor;
      b->Args({x.lwe_dimension, x.glwe_dimension, x.polynomial_size,
               x.pbs_base_log, x.pbs_level, input_lwe_ciphertext_count,
               x.grouping_factor, lwe_chunk_size});
    }
  }
}

static void
BootstrapBenchmarkGenerateParams(benchmark::internal::Benchmark *b) {
  // Define the parameters to benchmark
  // lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
  // input_lwe_ciphertext_count

  // PARAM_MESSAGE_2_CARRY_2_KS_PBS
  std::vector<BootstrapBenchmarkParams> params = {
      (BootstrapBenchmarkParams){742, 1, 2048, 23, 1, 1},
  };

  // Add to the list of parameters to benchmark
  for (int num_samples = 1; num_samples <= 4096; num_samples *= 2)
    for (auto x : params) {
      b->Args({x.lwe_dimension, x.glwe_dimension, x.polynomial_size,
               x.pbs_base_log, x.pbs_level, num_samples});
    }
}

BENCHMARK_REGISTER_F(MultiBitBootstrap_u64, CgMultiBit)
    ->Apply(MultiBitPBSBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count",
                "grouping_factor", "chunk_size"});

BENCHMARK_REGISTER_F(MultiBitBootstrap_u64, DefaultMultiBit)
    ->Apply(MultiBitPBSBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count",
                "grouping_factor", "chunk_size"});

BENCHMARK_REGISTER_F(ClassicalBootstrap_u64, DefaultPBS)
    ->Apply(BootstrapBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count"});

BENCHMARK_REGISTER_F(ClassicalBootstrap_u64, AmortizedPBS)
    ->Apply(BootstrapBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count"});
