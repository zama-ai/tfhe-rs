#include <benchmark/benchmark.h>
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

class MultiBitBootstrap_u64 : public benchmark::Fixture {
protected:
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  int input_lwe_ciphertext_count;
  int input_lwe_ciphertext_count_per_gpu;
  int grouping_factor;
  double lwe_modular_variance = 0.000007069849454709433;
  double glwe_modular_variance = 0.00000000000000029403601535432533;
  int pbs_base_log;
  int pbs_level;
  int message_modulus = 4;
  int carry_modulus = 4;
  int payload_modulus;
  uint64_t delta;
  std::vector<uint64_t *> d_bsk_array;
  std::vector<uint64_t *> d_lut_pbs_identity;
  std::vector<uint64_t *> d_lut_pbs_indexes;
  std::vector<uint64_t *> d_lwe_ct_in_array;
  std::vector<uint64_t *> d_lwe_ct_out_array;
  std::vector<uint64_t *> d_lwe_input_indexes;
  std::vector<uint64_t *> d_lwe_output_indexes;
  uint64_t *lwe_sk_in_array;
  uint64_t *lwe_sk_out_array;
  uint64_t *plaintexts;
  std::vector<int8_t *> pbs_buffer;

  int chunk_size;

  int num_gpus;
  std::vector<cuda_stream_t *> streams;

public:
  void SetUp(const ::benchmark::State &state) {

    lwe_dimension = state.range(0);
    glwe_dimension = state.range(1);
    polynomial_size = state.range(2);
    pbs_base_log = state.range(3);
    pbs_level = state.range(4);
    input_lwe_ciphertext_count = state.range(5);
    grouping_factor = state.range(6);
    chunk_size = state.range(7);

    num_gpus = std::min(cuda_get_number_of_gpus(), input_lwe_ciphertext_count);

    assert(input_lwe_ciphertext_count % num_gpus == 0);
    input_lwe_ciphertext_count_per_gpu =
        std::max(1, input_lwe_ciphertext_count / num_gpus);

    Seed seed;
    init_seed(&seed);

    // Create streams
    for (int device = 0; device < num_gpus; device++) {
      cudaSetDevice(device);
      cuda_stream_t *stream = cuda_create_stream(device);
      streams.push_back(stream);

      uint64_t *d_bsk_array_per_gpu;
      uint64_t *d_lut_pbs_identity_per_gpu;
      uint64_t *d_lut_pbs_indexes_per_gpu;
      uint64_t *d_lwe_ct_in_array_per_gpu;
      uint64_t *d_lwe_ct_out_array_per_gpu;
      uint64_t *d_lwe_input_indexes_per_gpu;
      uint64_t *d_lwe_output_indexes_per_gpu;
      int8_t *pbs_buffer_per_gpu;

      bootstrap_multibit_setup(
          stream, &seed, &lwe_sk_in_array, &lwe_sk_out_array,
          &d_bsk_array_per_gpu, &plaintexts, &d_lut_pbs_identity_per_gpu,
          &d_lut_pbs_indexes_per_gpu, &d_lwe_ct_in_array_per_gpu,
          &d_lwe_input_indexes_per_gpu, &d_lwe_ct_out_array_per_gpu,
          &d_lwe_output_indexes_per_gpu, &pbs_buffer_per_gpu, lwe_dimension,
          glwe_dimension, polynomial_size, grouping_factor,
          lwe_modular_variance, glwe_modular_variance, pbs_base_log, pbs_level,
          message_modulus, carry_modulus, &payload_modulus, &delta,
          input_lwe_ciphertext_count_per_gpu, 1, 1, chunk_size);

      d_bsk_array.push_back(d_bsk_array_per_gpu);
      d_lut_pbs_identity.push_back(d_lut_pbs_identity_per_gpu);
      d_lut_pbs_indexes.push_back(d_lut_pbs_indexes_per_gpu);
      d_lwe_ct_in_array.push_back(d_lwe_ct_in_array_per_gpu);
      d_lwe_ct_out_array.push_back(d_lwe_ct_out_array_per_gpu);
      d_lwe_input_indexes.push_back(d_lwe_input_indexes_per_gpu);
      d_lwe_output_indexes.push_back(d_lwe_output_indexes_per_gpu);
      pbs_buffer.push_back(pbs_buffer_per_gpu);
    }
  }

  void TearDown(const ::benchmark::State &state) {
    free(lwe_sk_in_array);
    free(lwe_sk_out_array);
    free(plaintexts);

    for (int device = 0; device < num_gpus; device++) {
      cudaSetDevice(device);
      cleanup_cuda_multi_bit_pbs(streams[device], &pbs_buffer[device]);
      cuda_drop_async(d_bsk_array[device], streams[device]);
      cuda_drop_async(d_lut_pbs_identity[device], streams[device]);
      cuda_drop_async(d_lut_pbs_indexes[device], streams[device]);
      cuda_drop_async(d_lwe_ct_in_array[device], streams[device]);
      cuda_drop_async(d_lwe_ct_out_array[device], streams[device]);
      cuda_drop_async(d_lwe_input_indexes[device], streams[device]);
      cuda_drop_async(d_lwe_output_indexes[device], streams[device]);
      cuda_synchronize_stream(streams[device]);
      cuda_destroy_stream(streams[device]);
    }
    d_bsk_array.clear();
    d_lut_pbs_identity.clear();
    d_lut_pbs_indexes.clear();
    d_lwe_ct_in_array.clear();
    d_lwe_ct_out_array.clear();
    d_lwe_input_indexes.clear();
    d_lwe_output_indexes.clear();
    pbs_buffer.clear();
    streams.clear();
    cudaDeviceReset();
  }
};

BENCHMARK_DEFINE_F(MultiBitBootstrap_u64, ConcreteCuda_MultiBit)
(benchmark::State &st) {

  for (auto _ : st) {
#pragma omp parallel for num_threads(num_gpus)
    for (int device = 0; device < num_gpus; device++) {
      cudaSetDevice(device);
      // Execute PBS
      cuda_multi_bit_pbs_lwe_ciphertext_vector_64(
          streams[device], (void *)d_lwe_ct_out_array[device],
          (void *)d_lwe_output_indexes[device],
          (void *)d_lut_pbs_identity[device], (void *)d_lut_pbs_indexes[device],
          (void *)d_lwe_ct_in_array[device],
          (void *)d_lwe_input_indexes[device], (void *)d_bsk_array[device],
          pbs_buffer[device], lwe_dimension, glwe_dimension, polynomial_size,
          grouping_factor, pbs_base_log, pbs_level,
          input_lwe_ciphertext_count_per_gpu, 1, 0,
          cuda_get_max_shared_memory(device), chunk_size);
    }

    for (int device = 0; device < num_gpus; device++) {
      cudaSetDevice(device);
      cuda_synchronize_stream(streams[device]);
    }
  }
}

static void
MultiBitPBSBenchmarkGenerateParams(benchmark::internal::Benchmark *b) {
  // Define the parameters to benchmark
  // lwe_dimension, glwe_dimension, polynomial_size, pbs_base_log, pbs_level,
  // input_lwe_ciphertext_count
  std::vector<MultiBitPBSBenchmarkParams> params = {
      // 4_bits_multi_bit_group_2
      (MultiBitPBSBenchmarkParams){818, 1, 2048, 22, 1, 1, 2},
      // 4_bits_multi_bit_group_3
      (MultiBitPBSBenchmarkParams){888, 1, 2048, 21, 1, 1, 3},
  };

  // Add to the list of parameters to benchmark
  for (auto x : params) {
      for(int lwe_chunk_size = 1; lwe_chunk_size <= x.lwe_dimension / x.grouping_factor;
      lwe_chunk_size *= 2)
    for (int input_lwe_ciphertext_count = 1;
         input_lwe_ciphertext_count <= 16384; input_lwe_ciphertext_count *= 2)
      b->Args({x.lwe_dimension, x.glwe_dimension, x.polynomial_size,
               x.pbs_base_log, x.pbs_level, input_lwe_ciphertext_count,
               x.grouping_factor, lwe_chunk_size});
  }
}

BENCHMARK_REGISTER_F(MultiBitBootstrap_u64, ConcreteCuda_MultiBit)
    ->Apply(MultiBitPBSBenchmarkGenerateParams)
    ->ArgNames({"lwe_dimension", "glwe_dimension", "polynomial_size",
                "pbs_base_log", "pbs_level", "input_lwe_ciphertext_count",
                "grouping_factor", "chunk_size"});
