#include "pbs/pbs_multibit_utilities.h"
#include "pbs/pbs_utilities.h"
#include <algorithm>
#include <benchmark/benchmark.h>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <setup_and_teardown.h>
#include <sstream>
#include <string>
#include <vector>

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
    cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<
        uint64_t>(stream, gpu_index, d_lwe_ct_out_array, d_lwe_output_indexes,
                  d_lut_pbs_identity, d_lut_pbs_indexes, d_lwe_ct_in_array,
                  d_lwe_input_indexes, d_bsk,
                  (pbs_buffer<uint64_t, MULTI_BIT> *)buffer, lwe_dimension,
                  glwe_dimension, polynomial_size, grouping_factor,
                  pbs_base_log, pbs_level, input_lwe_ciphertext_count,
                  num_many_lut, lut_stride);
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
    cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<
        uint64_t>(
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
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<uint64_t>(
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
      input_lwe_ciphertext_count, true, PBS_MS_REDUCTION_T::NO_REDUCTION);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (auto _ : st) {
    // Execute PBS
    cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector_async<uint64_t>(
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
    cuda_programmable_bootstrap_cg_lwe_ciphertext_vector_async<uint64_t>(
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
    cuda_programmable_bootstrap_lwe_ciphertext_vector_async<uint64_t>(
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

static std::optional<int> parse_positive_int(const std::string &token) {
  if (token.empty() || token.size() > 9 ||
      !std::all_of(token.begin(), token.end(),
                   [](unsigned char c) { return std::isdigit(c) != 0; }))
    return std::nullopt;
  const int value = std::stoi(token);
  if (value == 0)
    return std::nullopt;
  return value;
}

static std::vector<int> parse_positive_int_list(const char *env_name,
                                                bool allow_ranges) {
  std::vector<int> values;
  const char *env = std::getenv(env_name);
  if (env == nullptr)
    return values;

  const std::string value(env);
  bool valid = !value.empty() && value.back() != ',';
  std::stringstream stream(value);
  std::string token;
  while (valid && std::getline(stream, token, ',')) {
    const auto dash = token.find('-');
    if (allow_ranges && dash != std::string::npos) {
      const auto first = parse_positive_int(token.substr(0, dash));
      const auto last = parse_positive_int(token.substr(dash + 1));
      valid = first && last && *first <= *last;
      if (valid)
        for (int i = *first; i <= *last; i++)
          values.push_back(i);
    } else {
      const auto parsed = parse_positive_int(token);
      valid = parsed.has_value();
      if (valid)
        values.push_back(*parsed);
    }
  }
  PANIC_IF_FALSE(valid,
                 "%s must be a comma-separated list of positive integers%s, "
                 "got \"%s\"",
                 env_name, allow_ranges ? " or inclusive ranges a-b" : "", env);
  return values;
}

static std::vector<int> unique_values(const std::vector<int> &values,
                                      const std::vector<int> &excluded = {}) {
  std::vector<int> unique;
  for (int value : values) {
    if (std::find(excluded.begin(), excluded.end(), value) == excluded.end() &&
        std::find(unique.begin(), unique.end(), value) == unique.end())
      unique.push_back(value);
  }
  return unique;
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

  std::vector<int> default_counts;
  for (int input_lwe_ciphertext_count = 1; input_lwe_ciphertext_count <= 4096;
       input_lwe_ciphertext_count *= 2)
    default_counts.push_back(input_lwe_ciphertext_count);

  const std::vector<int> extra_counts = unique_values(
      parse_positive_int_list("TFHE_CUDA_BENCH_EXTRA_BATCHES", false),
      default_counts);

  // Add to the list of parameters to benchmark
  for (const auto &counts : {default_counts, extra_counts}) {
    for (auto x : params) {
      for (int input_lwe_ciphertext_count : counts) {
        b->Args({x.lwe_dimension, x.glwe_dimension, x.polynomial_size,
                 x.pbs_base_log, x.pbs_level, input_lwe_ciphertext_count,
                 x.grouping_factor});
      }
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

struct MultiBitChunkSweepInputs {
  std::vector<int64_t> args;
  cudaStream_t stream;
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
  int payload_modulus;
  uint64_t delta;
};

constexpr uint32_t chunk_sweep_gpu_index = 0;
static std::optional<MultiBitChunkSweepInputs> chunk_sweep_inputs;
static std::vector<int64_t> chunk_sweep_last_args;

static void release_chunk_sweep_inputs() {
  if (!chunk_sweep_inputs)
    return;
  auto &in = *chunk_sweep_inputs;
  programmable_bootstrap_multibit_teardown(
      in.stream, chunk_sweep_gpu_index, in.lwe_sk_in_array, in.lwe_sk_out_array,
      in.d_bsk, in.plaintexts, in.d_lut_pbs_identity, in.d_lut_pbs_indexes,
      in.d_lwe_ct_in_array, in.d_lwe_input_indexes, in.d_lwe_ct_out_array,
      in.d_lwe_output_indexes);
  chunk_sweep_inputs.reset();
}

static MultiBitChunkSweepInputs &
get_chunk_sweep_inputs(const std::vector<int64_t> &args) {
  if (chunk_sweep_inputs && chunk_sweep_inputs->args == args)
    return *chunk_sweep_inputs;
  release_chunk_sweep_inputs();

  MultiBitChunkSweepInputs in{};
  in.args = args;
  in.stream = cuda_create_stream(chunk_sweep_gpu_index);

  DynamicDistribution lwe_modular_variance =
      new_gaussian_from_std_dev(sqrt(0.000007069849454709433));
  DynamicDistribution glwe_modular_variance =
      new_gaussian_from_std_dev(sqrt(0.00000000000000029403601535432533));

  Seed seed;
  init_seed(&seed);

  programmable_bootstrap_multibit_setup(
      in.stream, chunk_sweep_gpu_index, &seed, &in.lwe_sk_in_array,
      &in.lwe_sk_out_array, &in.d_bsk, &in.plaintexts, &in.d_lut_pbs_identity,
      &in.d_lut_pbs_indexes, &in.d_lwe_ct_in_array, &in.d_lwe_input_indexes,
      &in.d_lwe_ct_out_array, &in.d_lwe_output_indexes, args[0], args[1],
      args[2], args[6], lwe_modular_variance, glwe_modular_variance, args[3],
      args[4], 4, 4, &in.payload_modulus, &in.delta, args[5], 1, 1);
  chunk_sweep_inputs = in;
  return *chunk_sweep_inputs;
}

static void TbcMultiBitChunkSweep(benchmark::State &st) {
  const int lwe_dimension = st.range(0);
  const int glwe_dimension = st.range(1);
  const int polynomial_size = st.range(2);
  const int pbs_base_log = st.range(3);
  const int pbs_level = st.range(4);
  const int input_lwe_ciphertext_count = st.range(5);
  const int grouping_factor = st.range(6);
  const std::vector<int64_t> args = {st.range(0), st.range(1), st.range(2),
                                     st.range(3), st.range(4), st.range(5),
                                     st.range(6), st.range(7)};
  struct ReleaseAfterLastCase {
    const std::vector<int64_t> &args;
    ~ReleaseAfterLastCase() {
      if (args == chunk_sweep_last_args)
        release_chunk_sweep_inputs();
    }
  } release_after_last_case{args};

  if (!has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          pbs_level, cuda_get_max_shared_memory(0))) {
    st.SkipWithError("Configuration not supported for tbc operation");
    return;
  }

  auto &in = get_chunk_sweep_inputs({args.begin(), args.end() - 1});

  setenv("TFHE_RS_GPU_MULTIBIT_LWE_CHUNK", std::to_string(args[7]).c_str(), 1);
  pbs_buffer<uint64_t, MULTI_BIT> *buffer = nullptr;
  scratch_cuda_tbc_multi_bit_programmable_bootstrap<uint64_t>(
      in.stream, chunk_sweep_gpu_index, &buffer, glwe_dimension,
      polynomial_size, pbs_level, input_lwe_ciphertext_count, true);
  st.counters["effective_lwe_chunk_size"] =
      static_cast<double>(buffer->lwe_chunk_size);
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  auto execute_pbs = [&]() {
    cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async<
        uint64_t>(in.stream, chunk_sweep_gpu_index, in.d_lwe_ct_out_array,
                  in.d_lwe_output_indexes, in.d_lut_pbs_identity,
                  in.d_lut_pbs_indexes, in.d_lwe_ct_in_array,
                  in.d_lwe_input_indexes, in.d_bsk, buffer, lwe_dimension,
                  glwe_dimension, polynomial_size, grouping_factor,
                  pbs_base_log, pbs_level, input_lwe_ciphertext_count,
                  num_many_lut, lut_stride);
    cuda_synchronize_stream(in.stream, chunk_sweep_gpu_index);
  };
  execute_pbs();
  for (auto _ : st) {
    // Execute PBS
    execute_pbs();
  }

  cleanup_cuda_multi_bit_programmable_bootstrap_64(
      in.stream, chunk_sweep_gpu_index, reinterpret_cast<int8_t **>(&buffer));
  unsetenv("TFHE_RS_GPU_MULTIBIT_LWE_CHUNK");
}

static void
MultiBitChunkSweepGenerateParams(benchmark::internal::Benchmark *b) {
  PANIC_IF_FALSE(std::getenv("TFHE_RS_GPU_MULTIBIT_LWE_CHUNK") == nullptr,
                 "TFHE_CUDA_BENCH_CHUNK_LIST sets "
                 "TFHE_RS_GPU_MULTIBIT_LWE_CHUNK for each case, unset it");
  const std::vector<int> chunks = unique_values(
      parse_positive_int_list("TFHE_CUDA_BENCH_CHUNK_LIST", true));
  std::vector<int> batches = unique_values(
      parse_positive_int_list("TFHE_CUDA_BENCH_SWEEP_BATCHES", false));
  if (batches.empty())
    for (int batch = 1; batch <= 128; batch *= 2)
      batches.push_back(batch);

  const char *lwe_dimension_env =
      std::getenv("TFHE_CUDA_BENCH_SWEEP_LWE_DIMENSION");
  const std::string lwe_dimension =
      lwe_dimension_env == nullptr ? "920" : lwe_dimension_env;
  PANIC_IF_FALSE(lwe_dimension == "920" || lwe_dimension == "872",
                 "TFHE_CUDA_BENCH_SWEEP_LWE_DIMENSION must be 920 or 872, "
                 "got \"%s\"",
                 lwe_dimension.c_str());

  // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
  // (920) or
  // V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
  // (872)
  const MultiBitPBSBenchmarkParams x = {
      std::stoi(lwe_dimension), 1, 2048, 22, 1, 1, 4};
  for (int chunk : chunks)
    PANIC_IF_FALSE(chunk <= x.lwe_dimension / x.grouping_factor,
                   "TFHE_CUDA_BENCH_CHUNK_LIST value %d is above the number "
                   "of groups %d (lwe_dimension / grouping_factor)",
                   chunk, x.lwe_dimension / x.grouping_factor);
  for (int batch : batches) {
    for (int chunk : chunks) {
      chunk_sweep_last_args = {x.lwe_dimension,   x.glwe_dimension,
                               x.polynomial_size, x.pbs_base_log,
                               x.pbs_level,       batch,
                               x.grouping_factor, chunk};
      b->Args(chunk_sweep_last_args);
    }
  }
}

[[maybe_unused]] static benchmark::internal::Benchmark
    *const multi_bit_chunk_sweep =
        std::getenv("TFHE_CUDA_BENCH_CHUNK_LIST") == nullptr
            ? nullptr
            : benchmark::RegisterBenchmark("MultiBitBootstrap_u64/TbcMultiBit",
                                           TbcMultiBitChunkSweep)
                  ->Apply(MultiBitChunkSweepGenerateParams)
                  ->ArgNames({"lwe_dimension", "glwe_dimension",
                              "polynomial_size", "pbs_base_log", "pbs_level",
                              "input_lwe_ciphertext_count", "grouping_factor",
                              "lwe_chunk_size"});
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
