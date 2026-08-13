#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <pbs/pbs_utilities.h>
#include <pbs/programmable_bootstrap_testing.h>
#include <setup_and_teardown.h>
#include <thread>
#include <utils.h>
#include <vector>

#include "checked_arithmetic.h"

// The mixprecision 2_2 kernel used to size its shared memory from the LWE
// dimension, which is not one of its template arguments. Since the opt-in is
// per-function state shared by the whole context, two concurrent bootstraps of
// different dimensions raced on it and the larger launch died with "invalid
// argument".
//
// The race is for the few microseconds between the opt-in and the launch, on
// the host, which is what dictates the shape of this test: several threads per
// dimension, bootstraps issued back to back and a single readback at the end.
// Reading the result after every bootstrap instead never reproduced it, since
// that parks each thread on the GPU for the whole kernel.

// Both dimensions must select the same kernel instantiation, so they only
// differ in n. They are the two 2_2-shaped parameter sets the PBS tests already
// use.
constexpr int CONCURRENT_LWE_DIMENSIONS[] = {759, 918};
constexpr int CONCURRENT_GLWE_DIMENSION = 1;
constexpr int CONCURRENT_POLYNOMIAL_SIZE = 2048;
constexpr int CONCURRENT_PBS_LEVEL = 1;
constexpr int CONCURRENT_PBS_BASE_LOG = 23;
constexpr int CONCURRENT_MESSAGE_MODULUS = 4;
constexpr int CONCURRENT_CARRY_MODULUS = 4;
constexpr int CONCURRENT_THREADS_PER_DIMENSION = 4;
constexpr int CONCURRENT_ITERATIONS = 2000;

namespace {

// Keys, lut and input for one LWE dimension, shared read-only by the threads
// running it.
struct ConcurrentPbsKeys {
  cudaStream_t stream;
  uint32_t gpu_index = 0;
  int lwe_dimension;
  uint64_t *lwe_sk_in_array = nullptr;
  uint64_t *lwe_sk_out_array = nullptr;
  uint64_t *plaintexts = nullptr;
  double *d_fourier_bsk_array = nullptr;
  uint64_t *d_lut_pbs_identity = nullptr;
  uint64_t *d_lut_pbs_indexes = nullptr;
  uint64_t *d_lwe_ct_in_array = nullptr;
  uint64_t *d_lwe_ct_out_array = nullptr;
  uint64_t *d_lwe_input_indexes = nullptr;
  uint64_t *d_lwe_output_indexes = nullptr;
  int payload_modulus = 0;
  uint64_t delta = 0;

  explicit ConcurrentPbsKeys(int n) : lwe_dimension(n) {
    stream = cuda_create_stream(gpu_index);
    Seed seed;
    init_seed(&seed);
    programmable_bootstrap_classical_setup(
        stream, gpu_index, &seed, &lwe_sk_in_array, &lwe_sk_out_array,
        &d_fourier_bsk_array, &plaintexts, &d_lut_pbs_identity,
        &d_lut_pbs_indexes, &d_lwe_ct_in_array, &d_lwe_input_indexes,
        &d_lwe_ct_out_array, &d_lwe_output_indexes, lwe_dimension,
        CONCURRENT_GLWE_DIMENSION, CONCURRENT_POLYNOMIAL_SIZE,
        new_t_uniform(45), new_t_uniform(17), CONCURRENT_PBS_BASE_LOG,
        CONCURRENT_PBS_LEVEL, CONCURRENT_MESSAGE_MODULUS,
        CONCURRENT_CARRY_MODULUS, &payload_modulus, &delta, 1, 1, 1);

    // The specialized kernel reads the bsk in its own layout.
    cuda_drop_async(d_fourier_bsk_array, stream, gpu_index);
    Seed bsk_seed;
    init_seed(&bsk_seed);
    generate_lwe_programmable_bootstrap_keys_specialized_2_2(
        stream, gpu_index, &d_fourier_bsk_array, lwe_sk_in_array,
        lwe_sk_out_array, lwe_dimension, CONCURRENT_GLWE_DIMENSION,
        CONCURRENT_POLYNOMIAL_SIZE, CONCURRENT_PBS_LEVEL,
        CONCURRENT_PBS_BASE_LOG, &bsk_seed, new_t_uniform(17), 1);
    cuda_synchronize_stream(stream, gpu_index);
  }

  ~ConcurrentPbsKeys() {
    programmable_bootstrap_classical_teardown(
        stream, gpu_index, lwe_sk_in_array, lwe_sk_out_array,
        d_fourier_bsk_array, plaintexts, d_lut_pbs_identity, d_lut_pbs_indexes,
        d_lwe_ct_in_array, d_lwe_input_indexes, d_lwe_ct_out_array,
        d_lwe_output_indexes);
  }
};

// One thread's own stream, scratch buffer and output ciphertext.
struct ConcurrentPbsWorker {
  cudaStream_t stream;
  uint32_t gpu_index = 0;
  int8_t *pbs_buffer = nullptr;
  uint64_t *d_lwe_ct_out = nullptr;
  size_t out_size;

  explicit ConcurrentPbsWorker(const ConcurrentPbsKeys &keys) {
    stream = cuda_create_stream(gpu_index);
    out_size =
        safe_mul_sizeof<uint64_t>(safe_mul((size_t)CONCURRENT_GLWE_DIMENSION,
                                           (size_t)CONCURRENT_POLYNOMIAL_SIZE) +
                                  1);
    d_lwe_ct_out = (uint64_t *)cuda_malloc_async(out_size, stream, gpu_index);
    scratch_cuda_programmable_bootstrap_specialized_2_2_64_async(
        stream, gpu_index, &pbs_buffer, keys.lwe_dimension,
        CONCURRENT_GLWE_DIMENSION, CONCURRENT_POLYNOMIAL_SIZE,
        CONCURRENT_PBS_LEVEL, 1, true, PBS_MS_REDUCTION_T::NO_REDUCTION);
    cuda_synchronize_stream(stream, gpu_index);
  }

  // Issues one bootstrap and returns, without reading the result back.
  void launch(const ConcurrentPbsKeys &keys) {
    cuda_programmable_bootstrap_specialized_2_2_64_async(
        stream, gpu_index, (void *)d_lwe_ct_out,
        (void *)keys.d_lwe_output_indexes, (void *)keys.d_lut_pbs_identity,
        (void *)keys.d_lut_pbs_indexes, (void *)keys.d_lwe_ct_in_array,
        (void *)keys.d_lwe_input_indexes, (void *)keys.d_fourier_bsk_array,
        pbs_buffer, keys.lwe_dimension, CONCURRENT_GLWE_DIMENSION,
        CONCURRENT_POLYNOMIAL_SIZE, CONCURRENT_PBS_BASE_LOG,
        CONCURRENT_PBS_LEVEL, 1, 1, 0);
  }

  // Checks the last result decrypts to the expected message.
  void check(const ConcurrentPbsKeys &keys) {
    std::vector<uint64_t> host(
        CONCURRENT_GLWE_DIMENSION * CONCURRENT_POLYNOMIAL_SIZE + 1);
    cuda_memcpy_async_to_cpu(host.data(), d_lwe_ct_out, out_size, stream,
                             gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    uint64_t decrypted = 0;
    core_crypto_lwe_decrypt(&decrypted, host.data(), keys.lwe_sk_out_array,
                            CONCURRENT_GLWE_DIMENSION *
                                CONCURRENT_POLYNOMIAL_SIZE);
    uint64_t rounding = (decrypted & (keys.delta >> 1)) << 1;
    ASSERT_EQ((decrypted + rounding) / keys.delta,
              keys.plaintexts[0] / keys.delta);
  }

  ~ConcurrentPbsWorker() {
    cleanup_cuda_programmable_bootstrap_64(stream, gpu_index, &pbs_buffer);
    cuda_drop_async(d_lwe_ct_out, stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    cuda_destroy_stream(stream, gpu_index);
  }
};

} // namespace

TEST(ConcurrentSpecialized2_2ProgrammableBootstrap, DistinctLweDimensions) {
  uint32_t gpu_index = 0;
  if (!specialized_2_2_params_checker<uint64_t>(
          CONCURRENT_POLYNOMIAL_SIZE, CONCURRENT_GLWE_DIMENSION,
          CONCURRENT_PBS_LEVEL, cuda_get_max_shared_memory(gpu_index))) {
    GTEST_SKIP() << "Specialized 2_2 classical PBS is not supported here.";
  }

  std::vector<std::unique_ptr<ConcurrentPbsKeys>> keys;
  for (int n : CONCURRENT_LWE_DIMENSIONS)
    keys.push_back(std::make_unique<ConcurrentPbsKeys>(n));

  std::vector<std::unique_ptr<ConcurrentPbsWorker>> workers;
  std::vector<size_t> worker_keys;
  for (size_t k = 0; k < keys.size(); k++)
    for (int t = 0; t < CONCURRENT_THREADS_PER_DIMENSION; t++) {
      workers.push_back(std::make_unique<ConcurrentPbsWorker>(*keys[k]));
      worker_keys.push_back(k);
    }

  std::vector<std::thread> threads;
  for (size_t w = 0; w < workers.size(); w++)
    threads.emplace_back([&, w] {
      for (int i = 0; i < CONCURRENT_ITERATIONS; i++)
        workers[w]->launch(*keys[worker_keys[w]]);
    });
  for (auto &t : threads)
    t.join();

  for (size_t w = 0; w < workers.size(); w++)
    workers[w]->check(*keys[worker_keys[w]]);
}
