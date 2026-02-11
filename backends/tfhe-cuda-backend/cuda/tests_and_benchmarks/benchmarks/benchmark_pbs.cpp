#include "pbs/pbs_multibit_utilities.h"
#include "pbs/pbs_utilities.h"
#include <benchmark/benchmark.h>
#include <cmath>
#include <cstdint>
#include <setup_and_teardown.h>

typedef struct {
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  int pbs_base_log;
  int pbs_level;
  int input_lwe_ciphertext_count;
  int grouping_factor;
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
  cudaStream_t stream;
  uint32_t gpu_index = 0;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  uint64_t *d_bsk;
  uint64_t *d_lut_pbs_identity;
  uint64_t *d_lut_pbs_indexes;
  uint64_t *d_lwe_ct_in_array;
  uint64_t *d_lwe_ct_out_array;
  uint64_t *d_lwe_input_indexes;
  uint64_t *d_lwe_output_indexes;
  int8_t *buffer;

public:
  void SetUp(const ::benchmark::State &state) {
    stream = cuda_create_stream(gpu_index);

    lwe_dimension = state.range(0);
    glwe_dimension = state.range(1);
    polynomial_size = state.range(2);
    pbs_base_log = state.range(3);
    pbs_level = state.range(4);
    input_lwe_ciphertext_count = state.range(5);
    grouping_factor = state.range(6);

    DynamicDistribution lwe_modular_variance =
        new_gaussian_from_std_dev(sqrt(0.000007069849454709433));
    DynamicDistribution glwe_modular_variance =
        new_gaussian_from_std_dev(sqrt(0.00000000000000029403601535432533));

    Seed seed;
    init_seed(&seed);

    programmable_bootstrap_multibit_setup(
        stream, gpu_index, &seed, &lwe_sk_in_array, &lwe_sk_out_array, &d_bsk,
        &plaintexts, &d_lut_pbs_identity, &d_lut_pbs_indexes,
        &d_lwe_ct_in_array, &d_lwe_input_indexes, &d_lwe_ct_out_array,
        &d_lwe_output_indexes, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, lwe_modular_variance, glwe_modular_variance,
        pbs_base_log, pbs_level, message_modulus, carry_modulus,
        &payload_modulus, &delta, input_lwe_ciphertext_count, 1, 1);
  }

  void TearDown(const ::benchmark::State &state) {
    (void)state;
    programmable_bootstrap_multibit_teardown(
        stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array, d_bsk, plaintexts,
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

  cudaStream_t stream;
  uint32_t gpu_index = 0;

public:
  void SetUp(const ::benchmark::State &state) {
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
        stream, gpu_index, &seed, &lwe_sk_in_array, &lwe_sk_out_array,
        &d_fourier_bsk, &plaintexts, &d_lut_pbs_identity, &d_lut_pbs_indexes,
        &d_lwe_ct_in_array, &d_lwe_input_indexes, &d_lwe_ct_out_array,
        &d_lwe_output_indexes, lwe_dimension, glwe_dimension, polynomial_size,
        lwe_modular_variance, glwe_modular_variance, pbs_base_log, pbs_level,
        message_modulus, carry_modulus, &payload_modulus, &delta,
        input_lwe_ciphertext_count, 1, 1);
  }

  void TearDown(const ::benchmark::State &state) {
    (void)state;
    programmable_bootstrap_classical_teardown(
        stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array, d_fourier_bsk,
        plaintexts, d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_lwe_ct_out_array, d_lwe_output_indexes);

    cudaDeviceReset();
  }
};

#if CUDA_ARCH >= 900
BENCHMARK_DEFINE_F(MultiBitBootstrap_u64, TbcMultiBit)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          pbs_level, cuda_get_max_shared_memory(0))) {
    st.SkipWithError("Configuration not supported for tbc operation");
    return;
  }

  scratch_cuda_tbc_multi_bit_programmable_bootstrap<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)&buffer,
      glwe_dimension, polynomial_size, pbs_level, input_lwe_ciphertext_count,
      true);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (auto _ : st) {
    // Execute PBS
    cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
        d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_bsk, (pbs_buffer<uint64_t, MULTI_BIT> *)buffer,
        lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
        pbs_base_log, pbs_level, input_lwe_ciphertext_count, num_many_lut,
        lut_stride);
    cuda_synchronize_stream(stream, gpu_index);
  }

  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index, &buffer);
}
#endif

BENCHMARK_DEFINE_F(MultiBitBootstrap_u64, CgMultiBit)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
          glwe_dimension, polynomial_size, pbs_level,
          input_lwe_ciphertext_count, cuda_get_max_shared_memory(gpu_index))) {
    st.SkipWithError("Configuration not supported for fast operation");
    return;
  }

  scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)&buffer,
      glwe_dimension, polynomial_size, pbs_level, input_lwe_ciphertext_count,
      true);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (auto _ : st) {
    // Execute PBS
    cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, d_lwe_ct_out_array,
        (const uint64_t *)d_lwe_output_indexes,
        (const uint64_t *)d_lut_pbs_identity,
        (const uint64_t *)d_lut_pbs_indexes,
        (const uint64_t *)d_lwe_ct_in_array,
        (const uint64_t *)d_lwe_input_indexes, (const uint64_t *)d_bsk,
        (pbs_buffer<uint64_t, MULTI_BIT> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, pbs_base_log,
        pbs_level, input_lwe_ciphertext_count, num_many_lut, lut_stride);
    cuda_synchronize_stream(stream, gpu_index);
  }

  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index, &buffer);
}

BENCHMARK_DEFINE_F(MultiBitBootstrap_u64, DefaultMultiBit)
(benchmark::State &st) {
  scratch_cuda_multi_bit_programmable_bootstrap<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)&buffer,
      glwe_dimension, polynomial_size, pbs_level, input_lwe_ciphertext_count,
      true);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (auto _ : st) {
    // Execute PBS
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
        d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
        d_lwe_input_indexes, d_bsk, (pbs_buffer<uint64_t, MULTI_BIT> *)buffer,
        lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
        pbs_base_log, pbs_level, input_lwe_ciphertext_count, num_many_lut,
        lut_stride);
    cuda_synchronize_stream(stream, gpu_index);
  }

  cleanup_cuda_multi_bit_programmable_bootstrap_64(stream, gpu_index, &buffer);
}

#if CUDA_ARCH >= 900
BENCHMARK_DEFINE_F(ClassicalBootstrap_u64, TbcPBC)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_tbc<uint64_t>(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          pbs_level, cuda_get_max_shared_memory(0))) {
    st.SkipWithError("Configuration not supported for tbc operation");
    return;
  }

  scratch_cuda_programmable_bootstrap_tbc<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)&buffer,
      lwe_dimension, glwe_dimension, polynomial_size, pbs_level,
      input_lwe_ciphertext_count, true, false);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, (uint64_t *)d_lwe_ct_out_array,
        (uint64_t *)d_lwe_output_indexes, (uint64_t *)d_lut_pbs_identity,
        (uint64_t *)d_lut_pbs_indexes, (uint64_t *)d_lwe_ct_in_array,
        (uint64_t *)d_lwe_input_indexes, (double2 *)d_fourier_bsk,
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        input_lwe_ciphertext_count, num_many_lut, lut_stride);
    cuda_synchronize_stream(stream, gpu_index);
  }

  cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &buffer);
}
#endif

BENCHMARK_DEFINE_F(ClassicalBootstrap_u64, CgPBS)
(benchmark::State &st) {
  if (!has_support_to_cuda_programmable_bootstrap_cg<uint64_t>(
          glwe_dimension, polynomial_size, pbs_level,
          input_lwe_ciphertext_count, cuda_get_max_shared_memory(gpu_index))) {
    st.SkipWithError("Configuration not supported for fast operation");
    return;
  }

  scratch_cuda_programmable_bootstrap_cg<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)&buffer,
      lwe_dimension, glwe_dimension, polynomial_size, pbs_level,
      input_lwe_ciphertext_count, true, PBS_MS_REDUCTION_T::NO_REDUCTION);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_cg_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, (uint64_t *)d_lwe_ct_out_array,
        (uint64_t *)d_lwe_output_indexes, (uint64_t *)d_lut_pbs_identity,
        (uint64_t *)d_lut_pbs_indexes, (uint64_t *)d_lwe_ct_in_array,
        (uint64_t *)d_lwe_input_indexes, (double2 *)d_fourier_bsk,
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        input_lwe_ciphertext_count, num_many_lut, lut_stride);
    cuda_synchronize_stream(stream, gpu_index);
  }

  cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap_u64, DefaultPBS)
(benchmark::State &st) {

  scratch_cuda_programmable_bootstrap<uint64_t>(
      stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)&buffer,
      lwe_dimension, glwe_dimension, polynomial_size, pbs_level,
      input_lwe_ciphertext_count, true, PBS_MS_REDUCTION_T::NO_REDUCTION);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, (uint64_t *)d_lwe_ct_out_array,
        (uint64_t *)d_lwe_output_indexes, (uint64_t *)d_lut_pbs_identity,
        (uint64_t *)d_lut_pbs_indexes, (uint64_t *)d_lwe_ct_in_array,
        (uint64_t *)d_lwe_input_indexes, (double2 *)d_fourier_bsk,
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        input_lwe_ciphertext_count, num_many_lut, lut_stride);
    cuda_synchronize_stream(stream, gpu_index);
  }

  cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &buffer);
}

BENCHMARK_DEFINE_F(ClassicalBootstrap_u64, AmortizedPBS)
(benchmark::State &st) {

  scratch_cuda_programmable_bootstrap_amortized_64_async(
      stream, gpu_index, &buffer, glwe_dimension, polynomial_size,
      input_lwe_ciphertext_count, true);

  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_amortized_64_async(
        stream, gpu_index, (void *)d_lwe_ct_out_array,
        (void *)d_lwe_output_indexes, (void *)d_lut_pbs_identity,
        (void *)d_lut_pbs_indexes, (void *)d_lwe_ct_in_array,
        (void *)d_lwe_input_indexes, (void *)d_fourier_bsk, buffer,
        lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        input_lwe_ciphertext_count);
    cuda_synchronize_stream(stream, gpu_index);
  }

  cleanup_cuda_programmable_bootstrap_amortized_64(stream, gpu_index, &buffer);
}

static void
MultiBitPBSBenchmarkGenerateParams(benchmark::internal::Benchmark *b) {
  // Define the parameters to benchmark
  // lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
  // input_lwe_ciphertext_count, grouping_factor
  std::vector<MultiBitPBSBenchmarkParams> params = {
      // V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
      (MultiBitPBSBenchmarkParams){918, 1, 4096, 21, 1, 1, 2},
      // V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
      (MultiBitPBSBenchmarkParams){879, 1, 2048, 14, 2, 1, 3},
      // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
      (MultiBitPBSBenchmarkParams){920, 1, 2048, 22, 1, 1, 4},
      // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128
      (MultiBitPBSBenchmarkParams){1040, 1, 8192, 14, 2, 1, 4},
  };

  // Add to the list of parameters to benchmark
  for (auto x : params) {
    for (int input_lwe_ciphertext_count = 1; input_lwe_ciphertext_count <= 4096;
         input_lwe_ciphertext_count *= 2) {
      b->Args({x.lwe_dimension, x.glwe_dimension, x.polynomial_size,
               x.pbs_base_log, x.pbs_level, input_lwe_ciphertext_count,
               x.grouping_factor});
    }
  }
}

static void
BootstrapBenchmarkGenerateParams(benchmark::internal::Benchmark *b) {
  // Define the parameters to benchmark
  // lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
  // input_lwe_ciphertext_count

  std::vector<BootstrapBenchmarkParams> params = {
      // V1_1_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
      (BootstrapBenchmarkParams){918, 1, 2048, 23, 1, 1},
      // V1_1_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128
      (BootstrapBenchmarkParams){1077, 1, 8192, 15, 2, 1},
  };

  // Add to the list of parameters to benchmark
  for (int num_samples = 1; num_samples <= 4096; num_samples *= 2)
    for (auto x : params) {
      b->Args({x.lwe_dimension, x.glwe_dimension, x.polynomial_size,
               x.pbs_base_log, x.pbs_level, num_samples});
    }
}

#if CUDA_ARCH >= 900
BENCHMARK_REGISTER_F(MultiBitBootstrap_u64, TbcMultiBit)
    ->Apply(MultiBitPBSBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count",
                "grouping_factor"});
#endif

BENCHMARK_REGISTER_F(MultiBitBootstrap_u64, CgMultiBit)
    ->Apply(MultiBitPBSBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count",
                "grouping_factor"});

BENCHMARK_REGISTER_F(MultiBitBootstrap_u64, DefaultMultiBit)
    ->Apply(MultiBitPBSBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count",
                "grouping_factor"});

#if CUDA_ARCH >= 900
BENCHMARK_REGISTER_F(ClassicalBootstrap_u64, TbcPBC)
    ->Apply(BootstrapBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count"});
#endif

BENCHMARK_REGISTER_F(ClassicalBootstrap_u64, DefaultPBS)
    ->Apply(BootstrapBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count"});

BENCHMARK_REGISTER_F(ClassicalBootstrap_u64, CgPBS)
    ->Apply(BootstrapBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count"});

BENCHMARK_REGISTER_F(ClassicalBootstrap_u64, AmortizedPBS)
    ->Apply(BootstrapBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count"});
