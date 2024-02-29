#ifndef CUDA_FAST_MULTIBIT_PBS_CUH
#define CUDA_FAST_MULTIBIT_PBS_CUH

#include "bootstrap.h"
#include "bootstrap_multibit.cuh"
#include "cooperative_groups.h"
#include "crypto/gadget.cuh"
#include "crypto/ggsw.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "types/complex/operations.cuh"
#include <vector>

template <typename Torus, class params>
__global__ void device_multi_bit_bootstrap_fast_accumulate(
    Torus *lwe_array_out, Torus *lwe_output_indexes, Torus *lut_vector,
    Torus *lut_vector_indexes, Torus *lwe_array_in, Torus *lwe_input_indexes,
    double2 *keybundle_array, double2 *join_buffer, Torus *global_accumulator,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t grouping_factor,
    uint32_t lwe_offset, uint32_t lwe_chunk_size,
    uint32_t keybundle_size_per_input) {

  grid_group grid = this_grid();

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  selected_memory = sharedmem;

  // We always compute the pointer with most restrictive alignment to avoid
  // alignment issues
  double2 *accumulator_fft = (double2 *)selected_memory;
  Torus *accumulator =
      (Torus *)accumulator_fft +
      (ptrdiff_t)(sizeof(double2) * polynomial_size / 2 / sizeof(Torus));

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.z] * (lwe_dimension + 1)];

  Torus *block_lut_vector = &lut_vector[lut_vector_indexes[blockIdx.z] *
                                        params::degree * (glwe_dimension + 1)];

  double2 *block_join_buffer =
      &join_buffer[blockIdx.z * level_count * (glwe_dimension + 1) *
                   params::degree / 2];

  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.z * (glwe_dimension + 1)) * params::degree;

  double2 *keybundle = keybundle_array +
                       // select the input
                       blockIdx.z * keybundle_size_per_input;

  if (lwe_offset == 0) {
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    rescale_torus_element(block_lwe_array_in[lwe_dimension], b_hat,
                          2 * params::degree);

    divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                          params::degree / params::opt>(
        accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
        false);
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        global_slice, accumulator);
  }

  for (int i = 0; (i + lwe_offset) < lwe_dimension && i < lwe_chunk_size; i++) {
    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    round_to_closest_multiple_inplace<Torus, params::opt,
                                      params::degree / params::opt>(
        accumulator, base_log, level_count);

    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<Torus, params> gadget_acc(base_log, level_count, accumulator);
    gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.x);

    // We are using the same memory space for accumulator_fft and
    // accumulator_rotated, so we need to synchronize here to make sure they
    // don't modify the same memory space at the same time
    synchronize_threads_in_block();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe<Torus, params>(accumulator, accumulator_fft,
                                 block_join_buffer, keybundle, polynomial_size,
                                 glwe_dimension, level_count, i, grid);

    synchronize_threads_in_block();
  }

  if (lwe_offset + lwe_chunk_size >= (lwe_dimension / grouping_factor)) {
    auto block_lwe_array_out =
        &lwe_array_out[lwe_output_indexes[blockIdx.z] *
                           (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.x == 0 && blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra blocks,
      // in case they're not synchronized
      sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
    } else if (blockIdx.x == 0 && blockIdx.y == glwe_dimension) {
      sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
    }
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        accumulator, global_slice);
  }
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_fast_multibit_bootstrap(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size * 2; // accumulator
}

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_fast_multibit_bootstrap(
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t grouping_factor, uint32_t lwe_chunk_size,
    uint32_t max_shared_memory) {

  uint64_t buffer_size = 0;
  buffer_size += input_lwe_ciphertext_count * lwe_chunk_size * level_count *
                 (glwe_dimension + 1) * (glwe_dimension + 1) *
                 (polynomial_size / 2) * sizeof(double2); // keybundle fft
  buffer_size += input_lwe_ciphertext_count * (glwe_dimension + 1) *
                 level_count * (polynomial_size / 2) *
                 sizeof(double2); // join buffer
  buffer_size += input_lwe_ciphertext_count * (glwe_dimension + 1) *
                 polynomial_size * sizeof(Torus); // global_accumulator

  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus, typename STorus, typename params>
__host__ void scratch_fast_multi_bit_pbs(
    cuda_stream_t *stream, pbs_multibit_buffer<Torus> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t grouping_factor, bool allocate_gpu_memory) {

  cudaSetDevice(stream->gpu_index);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate =
      get_buffer_size_full_sm_fast_multibit_bootstrap<Torus>(polynomial_size);

  check_cuda_error(cudaFuncSetAttribute(
      device_multi_bit_bootstrap_keybundle<Torus, params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
  cudaFuncSetCacheConfig(device_multi_bit_bootstrap_keybundle<Torus, params>,
                         cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  check_cuda_error(cudaFuncSetAttribute(
      device_multi_bit_bootstrap_fast_accumulate<Torus, params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_accumulate));
  cudaFuncSetCacheConfig(
      device_multi_bit_bootstrap_fast_accumulate<Torus, params>,
      cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  (*pbs_buffer) = new pbs_multibit_buffer<Torus>(
      stream, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, allocate_gpu_memory);
}

template <typename Torus, typename STorus, class params>
void consumer_fast_thread(
    cuda_stream_t *consumer_stream, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes,
    pbs_multibit_buffer<Torus> *pbs_buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    std::vector<std::condition_variable> &cv_producers,
    std::condition_variable &cv_consumer, std::vector<std::mutex> &mtx,
    std::vector<std::queue<std::pair<uint32_t, double2 *>>> &keybundle_pool) {

  uint32_t lwe_chunk_size = pbs_buffer->lwe_chunk_size;

  //
  uint64_t full_sm_accumulate =
      get_buffer_size_full_sm_fast_multibit_bootstrap<Torus>(polynomial_size);
  uint32_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2);

  //
  dim3 grid_accumulate(level_count, glwe_dimension + 1, num_samples);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  //
  double2 *buffer_fft = pbs_buffer->global_accumulator_fft;
  Torus *global_accumulator = pbs_buffer->global_accumulator;

  //
  void *kernel_args[18];
  kernel_args[0] = &lwe_array_out;
  kernel_args[1] = &lwe_output_indexes;
  kernel_args[2] = &lut_vector;
  kernel_args[3] = &lut_vector_indexes;
  kernel_args[4] = &lwe_array_in;
  kernel_args[5] = &lwe_input_indexes;
  kernel_args[7] = &buffer_fft;
  kernel_args[8] = &global_accumulator;
  kernel_args[9] = &lwe_dimension;
  kernel_args[10] = &glwe_dimension;
  kernel_args[11] = &polynomial_size;
  kernel_args[12] = &base_log;
  kernel_args[13] = &level_count;
  kernel_args[14] = &grouping_factor;
  kernel_args[17] = &keybundle_size_per_input;

  int num_producers = keybundle_pool.size();

  for (uint32_t lwe_offset = 0; lwe_offset < (lwe_dimension / grouping_factor);
       lwe_offset += lwe_chunk_size) {

    uint32_t chunk_size = std::min(
        lwe_chunk_size, (lwe_dimension / grouping_factor) - lwe_offset);

    int producer_id = (lwe_offset / lwe_chunk_size) % num_producers;
    auto &producer_queue = keybundle_pool[producer_id];
    double2 *keybundle_fft;
    {
      std::unique_lock<std::mutex> lock(mtx[producer_id]);
      // Wait until the producer inserts the right keybundle in the pool
      //            printf("consumer - %d) Will wait (%d elements)\n",
      //            lwe_offset,
      //                   producer_queue.size());
      cv_consumer.wait(lock, [&] { return !producer_queue.empty(); });
      //            printf("consumer - %d) Consuming...(%d elements)\n",
      //            lwe_offset,
      //                   producer_queue.size());
      auto pair = producer_queue.front();
      assert(pair.first == lwe_offset);
      keybundle_fft = pair.second;
      producer_queue.pop();
      cv_producers[producer_id].notify_one();
    }

    // Accumulate
    kernel_args[6] = &keybundle_fft;
    kernel_args[15] = &lwe_offset;
    kernel_args[16] = &chunk_size;

    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_multi_bit_bootstrap_fast_accumulate<Torus, params>,
        grid_accumulate, thds, (void **)kernel_args, full_sm_accumulate,
        consumer_stream->stream));
    cuda_drop_async(keybundle_fft, consumer_stream);
  }
}

template <typename Torus, typename STorus, class params>
__host__ void host_fast_multi_bit_pbs(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, uint64_t *bootstrapping_key,
    pbs_multibit_buffer<Torus> *pbs_buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx) {
  cudaSetDevice(stream->gpu_index);

  int num_producers = pbs_buffer->num_producers;
  int max_pool_size = pbs_buffer->max_pool_size;

  //
  std::vector<std::queue<std::pair<uint32_t, double2 *>>> keybundle_pool(
      num_producers);
  std::vector<std::condition_variable> cv_producers(num_producers);
  std::condition_variable cv_consumer;
  std::vector<std::mutex> mtx(num_producers);

  std::vector<std::thread> producer_threads;

  // We have to assert everything on the main stream is done to safely launch
  // the producer streams
  cuda_synchronize_stream(stream);
  for (int producer_id = 0; producer_id < num_producers; producer_id++) {
    std::thread producer(
        [stream, producer_id, num_producers, lwe_array_in, lwe_input_indexes,
         bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
         polynomial_size, grouping_factor, base_log, level_count, num_samples,
         &cv_producers, &cv_consumer, &mtx, &keybundle_pool, max_pool_size]() {
          auto producer_stream = cuda_create_stream(stream->gpu_index);
          producer_thread<Torus, params>(
              producer_stream, producer_id, num_producers, lwe_array_in,
              lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
              lwe_dimension, polynomial_size, grouping_factor, base_log,
              level_count, num_samples, cv_producers[producer_id], cv_consumer,
              mtx[producer_id], keybundle_pool[producer_id], max_pool_size);
          cuda_synchronize_stream(producer_stream);
          cuda_destroy_stream(producer_stream);
        });

    producer_threads.emplace_back(std::move(producer));
  }

  // std::thread consumer([&]() {
  //   auto consumer_stream = cuda_create_stream(gpu_index);
  consumer_fast_thread<Torus, STorus, params>(
      stream, lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
      lwe_array_in, lwe_input_indexes, pbs_buffer, glwe_dimension,
      lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
      num_samples, cv_producers, cv_consumer, mtx, keybundle_pool);
  //  cuda_synchronize_stream(consumer_stream);
  //  cuda_destroy_stream(consumer_stream);
  //});

  for (auto &producer : producer_threads) {
    producer.join();
  }
}

// Verify if the grid size for the low latency kernel satisfies the cooperative
// group constraints
template <typename Torus, class params>
__host__ bool verify_cuda_bootstrap_fast_multi_bit_grid_size(int glwe_dimension,
                                                             int level_count,
                                                             int num_samples) {
  // If Cooperative Groups is not supported, no need to check anything else
  if (!cuda_check_support_cooperative_groups())
    return false;

  // Calculate the dimension of the kernel
  uint64_t full_sm =
      get_buffer_size_full_sm_fast_multibit_bootstrap<Torus>(params::degree);

  int thds = params::degree / params::opt;

  // Get the maximum number of active blocks per streaming multiprocessors
  int number_of_blocks = level_count * (glwe_dimension + 1) * num_samples;
  int max_active_blocks_per_sm;

  cudaOccupancyMaxActiveBlocksPerMultiprocessor(
      &max_active_blocks_per_sm,
      (void *)device_multi_bit_bootstrap_fast_accumulate<Torus, params>, thds,
      full_sm);

  // Get the number of streaming multiprocessors
  int number_of_sm = 0;
  cudaDeviceGetAttribute(&number_of_sm, cudaDevAttrMultiProcessorCount, 0);
  return number_of_blocks <= max_active_blocks_per_sm * number_of_sm;
}
#endif // FASTMULTIBIT_PBS_H
