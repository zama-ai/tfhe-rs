#ifndef CUDA_INTEGER_UTILITIES_H
#define CUDA_INTEGER_UTILITIES_H

#include "integer.h"
#include "integer/radix_ciphertext.cuh"
#include "integer/radix_ciphertext.h"
#include "keyswitch/keyswitch.h"
#include "pbs/programmable_bootstrap.cuh"
#include "utils/helper_multi_gpu.cuh"
#include <cmath>
#include <functional>
#include <optional>
#include <queue>
#include <type_traits>

#include <stdio.h>

#include "crypto/keyswitch.cuh"

/// Constant to indicate that all blocks should use LUT index 0
/// (no custom index generation needed).
/// Use this as the index_generator argument to generate_and_broadcast_lut
/// when all blocks should use the same LUT.
constexpr std::nullptr_t LUT_0_FOR_ALL_BLOCKS = nullptr;

/// Generate LUT indexes with a generator, validate them, and copy to any GPU
/// buffer.
///
/// @tparam Torus          Integer type for indexes
/// @tparam IndexGenerator Callable with signature: void(Torus* indexes,
/// uint32_t count)
/// @param streams              CUDA streams for async operations
/// @param generator            Function/lambda that fills the index buffer
/// @param d_lut_indexes        Destination GPU buffer for indexes
/// @param num_indexes          Number of indexes to generate
/// @param num_luts             Number of LUTs (for validation)
/// @param h_buffer             CPU buffer to use for staging. The caller that
/// created this buffer must sync before freeing)
template <typename Torus, typename IndexGenerator>
void generate_lut_indexes(CudaStreams streams, IndexGenerator generator,
                          Torus *d_lut_indexes, uint32_t num_indexes,
                          uint32_t num_luts, Torus *h_buffer,
                          bool gpu_memory_allocated) {
  GPU_ASSERT(h_buffer != nullptr, "h_buffer must be provided");

  // Initialize with sentinel value to detect uninitialized entries
  constexpr Torus sentinel = std::numeric_limits<Torus>::max();
  for (uint32_t i = 0; i < num_indexes; i++) {
    h_buffer[i] = sentinel;
  }

  generator(h_buffer, num_indexes);

  // Validate all indexes were initialized and are within bounds
  for (uint32_t i = 0; i < num_indexes; i++) {
    GPU_ASSERT(h_buffer[i] != sentinel,
               "LUT index not initialized: h_buffer[%u] was not set by "
               "generator",
               i);
    GPU_ASSERT(h_buffer[i] < num_luts,
               "LUT index out of bounds: h_buffer[%u] = %llu >= num_luts (%u)",
               i, (unsigned long long)h_buffer[i], num_luts);
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_lut_indexes, h_buffer, num_indexes * sizeof(Torus), streams.stream(0),
      streams.gpu_index(0), gpu_memory_allocated);
}

class NoiseLevel {
public:
  // Constants equivalent to the Rust code
  static const uint64_t NOMINAL = 1;
  static const uint64_t ZERO = 0;
  static const uint64_t UNKNOWN = std::numeric_limits<uint64_t>::max();
};

#ifdef DEBUG
#define CHECK_NOISE_LEVEL(noise_level_expr, msg_mod, carry_mod)                \
  do {                                                                         \
    if ((msg_mod) == 2 && (carry_mod) == 2) {                                  \
      constexpr int max_noise_level = 3;                                       \
      if ((noise_level_expr) > max_noise_level)                                \
        PANIC("Cuda error: noise exceeds maximum authorized value for 1_1 "    \
              "parameters");                                                   \
    } else if ((msg_mod) == 4 && (carry_mod) == 4) {                           \
      constexpr int max_noise_level = 5;                                       \
      if ((noise_level_expr) > max_noise_level)                                \
        PANIC(                                                                 \
            "Cuda error: noise %d exceeds maximum authorized value 5 for 2_2"  \
            " parameters",                                                     \
            noise_level_expr);                                                 \
    } else if ((msg_mod) == 8 && (carry_mod) == 8) {                           \
      constexpr int max_noise_level = 9;                                       \
      if ((noise_level_expr) > max_noise_level)                                \
        PANIC("Cuda error: noise exceeds maximum authorized value for 3_3 "    \
              "parameters");                                                   \
    } else if ((msg_mod) == 0 && (carry_mod) == 0) {                           \
      break;                                                                   \
    } else if ((msg_mod) == 4 && (carry_mod) == 32) {                          \
      break;                                                                   \
    } else {                                                                   \
      PANIC("Invalid message modulus or carry modulus")                        \
    }                                                                          \
  } while (0)
#else
#define CHECK_NOISE_LEVEL(noise_level_expr, message_modulus, carry_modulus)    \
  do {                                                                         \
  } while (0)
#endif

template <typename Torus>
__global__ void radix_blocks_rotate_right(Torus *dst, Torus *src,
                                          uint32_t value, uint32_t blocks_count,
                                          uint32_t lwe_size);
void generate_ids_update_degrees(uint64_t *terms_degree, size_t *h_lwe_idx_in,
                                 size_t *h_lwe_idx_out,
                                 int32_t *h_smart_copy_in,
                                 int32_t *h_smart_copy_out, size_t ch_amount,
                                 uint32_t num_radix, uint32_t num_blocks,
                                 size_t chunk_size, size_t message_max,
                                 size_t &total_count, size_t &message_count,
                                 size_t &carry_count, size_t &sm_copy_count);
/*
 *  generate bivariate accumulator (lut) for device pointer
 *    stream - cuda stream
 *    acc_bivariate - device pointer for bivariate accumulator
 *    ...
 *    f - wrapping function with two Torus inputs
 */
template <typename Torus>
void generate_device_accumulator_bivariate(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc_bivariate,
    uint64_t *degree, uint64_t *max_degree, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus, Torus)> f, bool gpu_memory_allocated);

template <typename Torus>
void generate_device_accumulator_bivariate_with_factor(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc_bivariate,
    uint64_t *degree, uint64_t *max_degree, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus, Torus)> f, int factor,
    bool gpu_memory_allocated);

template <typename Torus>
void generate_device_accumulator_with_encoding(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degree,
    uint64_t *max_degree, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_message_modulus, uint32_t input_carry_modulus,
    uint32_t output_message_modulus, uint32_t output_carry_modulus,
    std::function<Torus(Torus)> f, bool gpu_memory_allocated);

template <typename Torus>
void generate_device_accumulator_no_encoding(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degree,
    uint32_t message_modulus, uint32_t carry_modulus, uint32_t glwe_dimension,
    uint32_t polynomial_size, std::function<Torus(Torus)> f,
    bool gpu_memory_allocated);

/*
 *  generate univariate accumulator (lut) for device pointer
 *    stream - cuda stream
 *    acc - device pointer for univariate accumulator
 *    ...
 *    f - evaluating function with one Torus input
 */
template <typename Torus>
void generate_device_accumulator(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degree,
    uint64_t *max_degree, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus)> f, bool gpu_memory_allocated);

template <typename Torus>
void generate_many_lut_device_accumulator(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degrees,
    uint64_t *max_degree, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t message_modulus, uint32_t carry_modulus,
    std::vector<std::function<Torus(Torus)>> &f, bool gpu_memory_allocated);

template <typename Torus>
void generate_device_accumulator_with_encoding_with_cpu_prealloc(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degree,
    uint64_t *max_degree, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_message_modulus, uint32_t input_carry_modulus,
    uint32_t output_message_modulus, uint32_t output_carry_modulus,
    std::function<Torus(Torus)> f, bool gpu_memory_allocated,
    Torus *preallocated_h_lut);

template <typename Torus>
void generate_device_accumulator_with_cpu_prealloc(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degree,
    uint64_t *max_degree, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus)> f, bool gpu_memory_allocated,
    Torus *preallocated_h_lut);

template <typename Torus>
void generate_device_accumulator_bivariate_with_cpu_prealloc(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc_bivariate,
    uint64_t *degree, uint64_t *max_degree, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus, Torus)> f, bool gpu_memory_allocated,
    Torus *h_lut);

struct radix_columns {
  std::vector<uint32_t> columns_counter;
  uint32_t num_blocks;
  uint32_t num_radix_in_vec;
  uint32_t chunk_size;
  radix_columns(const uint64_t *const input_degrees, uint32_t num_blocks,
                uint32_t num_radix_in_vec, uint32_t chunk_size,
                bool &needs_processing)
      : num_blocks(num_blocks), num_radix_in_vec(num_radix_in_vec),
        chunk_size(chunk_size) {
    needs_processing = false;
    columns_counter.resize(num_blocks, 0);
    for (uint32_t i = 0; i < num_radix_in_vec; ++i) {
      for (uint32_t j = 0; j < num_blocks; ++j) {
        if (input_degrees[i * num_blocks + j])
          columns_counter[j] += 1;
      }
    }

    for (uint32_t i = 0; i < num_blocks; ++i) {
      if (columns_counter[i] > chunk_size) {
        needs_processing = true;
        break;
      }
    }
  }

  void next_accumulation(uint32_t &total_ciphertexts,
                         uint32_t &message_ciphertexts,
                         bool &needs_processing) {
    message_ciphertexts = 0;
    total_ciphertexts = 0;
    needs_processing = false;
    for (int i = num_blocks - 1; i > 0; --i) {
      uint32_t cur_count = columns_counter[i];
      uint32_t prev_count = columns_counter[i - 1];
      uint32_t new_count = 0;

      // accumulated_blocks from current columns
      new_count += cur_count / chunk_size;
      // all accumulated message blocks needs pbs
      message_ciphertexts += new_count;
      // carry blocks from previous columns
      new_count += prev_count / chunk_size;
      // both carry and message blocks that needs pbs
      total_ciphertexts += new_count;
      // now add remaining non accumulated blocks that does not require pbs
      new_count += cur_count % chunk_size;

      columns_counter[i] = new_count;

      if (new_count > chunk_size)
        needs_processing = true;
    }

    // now do it for 0th block
    uint32_t new_count = columns_counter[0] / chunk_size;
    message_ciphertexts += new_count;
    total_ciphertexts += new_count;
    new_count += columns_counter[0] % chunk_size;
    columns_counter[0] = new_count;

    if (new_count > chunk_size) {
      needs_processing = true;
    }
  }
};

inline void calculate_final_degrees(uint64_t *const out_degrees,
                                    const uint64_t *const input_degrees,
                                    uint32_t num_blocks,
                                    uint32_t num_radix_in_vec,
                                    uint32_t chunk_size,
                                    uint64_t message_modulus) {

  auto get_degree = [message_modulus](uint64_t degree) -> uint64_t {
    return std::min(message_modulus - 1, degree);
  };
  std::vector<std::queue<uint64_t>> columns(num_blocks);
  for (uint32_t i = 0; i < num_radix_in_vec; ++i) {
    for (uint32_t j = 0; j < num_blocks; ++j) {
      if (input_degrees[i * num_blocks + j])
        columns[j].push(input_degrees[i * num_blocks + j]);
    }
  }

  for (uint32_t i = 0; i < num_blocks; ++i) {
    auto &col = columns[i];
    while (col.size() > 1) {
      uint32_t cur_degree = 0;
      uint32_t mn = std::min(chunk_size, (uint32_t)col.size());
      for (int j = 0; j < mn; ++j) {
        cur_degree += col.front();
        col.pop();
      }
      const uint64_t new_degree = get_degree(cur_degree);
      col.push(new_degree);
      if ((i + 1) < num_blocks) {
        columns[i + 1].push(new_degree);
      }
    }
  }

  for (int i = 0; i < num_blocks; i++) {
    out_degrees[i] = (columns[i].empty()) ? 0 : columns[i].front();
  }
}

struct int_radix_params {
  PBS_TYPE pbs_type;
  uint32_t glwe_dimension;
  uint32_t polynomial_size;
  uint32_t big_lwe_dimension;
  uint32_t small_lwe_dimension;
  uint32_t ks_level;
  uint32_t ks_base_log;
  uint32_t pbs_level;
  uint32_t pbs_base_log;
  uint32_t grouping_factor;
  uint32_t message_modulus;
  uint32_t carry_modulus;
  PBS_MS_REDUCTION_T noise_reduction_type;

  int_radix_params(PBS_TYPE pbs_type, uint32_t glwe_dimension,
                   uint32_t polynomial_size, uint32_t big_lwe_dimension,
                   uint32_t small_lwe_dimension, uint32_t ks_level,
                   uint32_t ks_base_log, uint32_t pbs_level,
                   uint32_t pbs_base_log, uint32_t grouping_factor,
                   uint32_t message_modulus, uint32_t carry_modulus,
                   PBS_MS_REDUCTION_T noise_reduction_type)

      : pbs_type(pbs_type), glwe_dimension(glwe_dimension),
        polynomial_size(polynomial_size), big_lwe_dimension(big_lwe_dimension),
        small_lwe_dimension(small_lwe_dimension), ks_level(ks_level),
        ks_base_log(ks_base_log), pbs_level(pbs_level),
        pbs_base_log(pbs_base_log), grouping_factor(grouping_factor),
        message_modulus(message_modulus), carry_modulus(carry_modulus),
        noise_reduction_type(noise_reduction_type){};

  int_radix_params() = default;

  void print() {
    printf("pbs_type: %u, glwe_dimension: %u, "
           "polynomial_size: %u, "
           "big_lwe_dimension: %u, "
           "small_lwe_dimension: %u, ks_level: %u, ks_base_log: %u, pbs_level: "
           "%u, pbs_base_log: "
           "%u, grouping_factor: %u, message_modulus: %u, carry_modulus: %u\n",
           pbs_type, glwe_dimension, polynomial_size, big_lwe_dimension,
           small_lwe_dimension, ks_level, ks_base_log, pbs_level, pbs_base_log,
           grouping_factor, message_modulus, carry_modulus);
  };
};

// Store things needed to apply LUTs
template <typename InputTorus, typename OutputTorus>
struct int_radix_lut_custom_input_output {
  int_radix_params params;
  // The number of blocks to be processed by the LUT. Can be
  // smaller than the actual num_input_blocks because some LUT types
  // (like noise squashing), perform packing.
  uint32_t num_blocks = 0;
  // The number of blocks of the input ciphertext. For noise
  // squashing these blocks are packed into num_blocks
  uint32_t num_input_blocks = 0;
  // Number of LUTs to store in this structure
  uint32_t num_luts = 0;
  // ManyLUT is the mechanism to apply several LUTs in a single PBS
  uint32_t num_many_lut = 1;
  // The LWE dimension of the KS output / PBS input. Initialized
  // to the max value so that we crash if this value is set incorrectly
  // by the caller
  uint32_t input_big_lwe_dimension = (uint32_t)-1;

  // Tracks the degree of each LUT and the max degree on CPU
  // The max degree is (message_modulus * carry_modulus - 1) except for many lut
  // for which it's different
  uint64_t *degrees = nullptr;
  uint64_t *max_degrees = nullptr;

  CudaStreams active_streams;
  bool mem_reuse = false;

  // Tracking for runtime consistency checks
  uint32_t last_broadcast_num_radix_blocks = 0;
  CudaStreams last_broadcast_streams;

  // There will be one buffer on each GPU in multi-GPU computations
  // (same for tmp lwe arrays)
  std::vector<int8_t *> buffer;

  // These arrays will reside on all GPUs
  // lut could actually be allocated & initialized GPU per GPU but this is not
  // done at the moment
  std::vector<OutputTorus *> lut_vec;
  std::vector<InputTorus *> lut_indexes_vec;
  InputTorus *h_lut_indexes = nullptr;
  // All tmp lwe arrays and index arrays for lwe contain the total
  // amount of blocks to be computed on, there is no split between GPUs
  // for the moment
  InputTorus *lwe_indexes_in = nullptr;
  InputTorus *lwe_indexes_out = nullptr;
  InputTorus *h_lwe_indexes_in = nullptr;
  InputTorus *h_lwe_indexes_out = nullptr;
  // Enable optimizations if lwe_indexes_(in/out) are trivial
  bool using_trivial_lwe_indexes = true;
  // lwe_trivial_indexes is the intermediary index we need in case
  // lwe_indexes_in != lwe_indexes_out
  InputTorus *lwe_trivial_indexes = nullptr;

  // buffer to store packed message bits of a radix ciphertext
  CudaRadixCiphertextFFI *tmp_lwe_before_ks = nullptr;

  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<InputTorus *> lwe_array_in_vec;
  std::vector<InputTorus *> lwe_after_ks_vec;
  std::vector<OutputTorus *> lwe_after_pbs_vec;
  std::vector<InputTorus *> lwe_trivial_indexes_vec;
  std::vector<ks_mem<InputTorus> *>
      ks_tmp_buf_vec; // buffers on each GPU to store keyswitch temporary data

  std::vector<InputTorus *> lwe_aligned_vec;

  bool gpu_memory_allocated;

  CudaStreamsBarrier multi_gpu_scatter_barrier, multi_gpu_broadcast_barrier;
  CudaStreamsBarrier multi_gpu_gather_barrier;
  CudaEventPool event_pool;

  // Setup the LUT configuration:
  // input_big_lwe_dimension: BIG LWE dimension of the KS output / PBS input
  // params: cryptographic parameters of the PBS output
  // num_luts: number of LUTs (or many-LUT sets) in this structure
  // num_many_lut: number of LUTs to apply in a single PBS pass
  // num_radix_blocks: number of blocks in the radix integer
  void setup_config_and_degrees(CudaStreams streams,
                                uint32_t input_big_lwe_dimension,
                                int_radix_params params, uint32_t num_luts,
                                uint32_t num_many_lut,
                                uint32_t num_radix_blocks,
                                uint32_t num_input_blocks,
                                bool allocate_gpu_memory) {
    this->params = params;
    this->num_blocks = num_radix_blocks;
    this->num_luts = num_luts;
    this->num_many_lut = num_many_lut;
    this->input_big_lwe_dimension = input_big_lwe_dimension;
    this->num_input_blocks = num_input_blocks;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->last_broadcast_num_radix_blocks =
        0; // no LUTs are broadcast at construction

    if (sizeof(OutputTorus) == 16) {
      this->active_streams =
          streams.active_gpu_subset_u128(num_radix_blocks, params.pbs_type);
    } else {
      this->active_streams =
          streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    }
  }

  void setup_degrees() {
    this->degrees =
        (uint64_t *)malloc(num_many_lut * num_luts * sizeof(uint64_t));
    this->max_degrees = (uint64_t *)malloc(num_luts * sizeof(uint64_t));
  }

  void allocate_pbs_buffers(int_radix_params params, uint32_t num_radix_blocks,
                            bool allocate_gpu_memory, uint64_t &size_tracker) {

    int classical_threshold =
        sizeof(OutputTorus) == 16
            ? THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128
            : THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS;
    int threshold = (params.pbs_type == PBS_TYPE::MULTI_BIT)
                        ? THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS
                        : classical_threshold;

    for (uint i = 0; i < active_streams.count(); i++) {
      cuda_set_device(active_streams.gpu_index(i));
      int8_t *gpu_pbs_buffer;
      auto num_blocks_on_gpu = std::min(
          (int)num_radix_blocks,
          std::max(threshold, get_num_inputs_on_gpu(num_radix_blocks, i,
                                                    active_streams.count())));

      uint64_t size = 0;
      execute_scratch_pbs<OutputTorus>(
          active_streams.stream(i), active_streams.gpu_index(i),
          &gpu_pbs_buffer, params.glwe_dimension, params.small_lwe_dimension,
          params.polynomial_size, params.pbs_level, params.pbs_base_log,
          params.grouping_factor, num_blocks_on_gpu, params.pbs_type,
          allocate_gpu_memory, params.noise_reduction_type, size);
      if (i == 0) {
        size_tracker += size;
      }
      buffer.push_back(gpu_pbs_buffer);
    }

    // This buffer is created with num_input_blocks since it
    // stores the ciphertext before KS or packing.
    tmp_lwe_before_ks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<InputTorus>(
        active_streams.stream(0), active_streams.gpu_index(0),
        tmp_lwe_before_ks, num_input_blocks, input_big_lwe_dimension,
        size_tracker, allocate_gpu_memory);
  }

  void alloc_and_init_multi_gpu_buffers(int_radix_params params,
                                        uint32_t num_radix_blocks,
                                        bool allocate_gpu_memory,
                                        uint64_t &size_tracker) {
    GPU_ASSERT(lwe_array_in_vec.empty(), "Multi GPU buffers already allocated");

    /// With multiple GPUs we allocate arrays to be pushed to the vectors and
    /// copy data on each GPU then when we gather data to GPU 0 we can copy
    /// back to the original indexing
    multi_gpu_alloc_lwe_async(active_streams, lwe_array_in_vec,
                              num_radix_blocks, params.big_lwe_dimension + 1,
                              size_tracker, params.pbs_type,
                              allocate_gpu_memory);
    multi_gpu_alloc_lwe_async(active_streams, lwe_after_ks_vec,
                              num_radix_blocks, params.small_lwe_dimension + 1,
                              size_tracker, params.pbs_type,
                              allocate_gpu_memory);
    if (num_many_lut > 1) {
      multi_gpu_alloc_lwe_many_lut_output_async(
          active_streams, lwe_after_pbs_vec, num_radix_blocks, num_many_lut,
          params.big_lwe_dimension + 1, size_tracker, params.pbs_type,
          allocate_gpu_memory);
    } else {
      multi_gpu_alloc_lwe_async(active_streams, lwe_after_pbs_vec,
                                num_radix_blocks, params.big_lwe_dimension + 1,
                                size_tracker, params.pbs_type,
                                allocate_gpu_memory);
    }
    multi_gpu_alloc_array_async(active_streams, lwe_trivial_indexes_vec,
                                num_radix_blocks, size_tracker,
                                allocate_gpu_memory);
    cuda_synchronize_stream(active_streams.stream(0),
                            active_streams.gpu_index(0));

    // This call will not copy if allocate_gpu_memory is false
    // thus it's safe to call it on a null source pointer
    multi_gpu_copy_array_async(active_streams, lwe_trivial_indexes_vec,
                               lwe_trivial_indexes, num_radix_blocks,
                               allocate_gpu_memory);
  }
  void setup_gemm_batch_ks_temp_buffers(uint64_t &size_tracker) {
    int classical_threshold =
        sizeof(OutputTorus) == 16
            ? THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128
            : THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS;
    int threshold = (params.pbs_type == PBS_TYPE::MULTI_BIT)
                        ? THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS
                        : classical_threshold;

    auto inputs_on_gpu = std::min(
        (int)num_input_blocks,
        std::max(threshold, get_num_inputs_on_gpu(num_input_blocks, 0,
                                                  active_streams.count())));

    if (inputs_on_gpu >= get_threshold_ks_gemm()) {
      for (auto i = 0; i < active_streams.count(); ++i) {
        ks_mem<InputTorus> *ks_buffer;
        uint64_t sub_size_tracker = scratch_cuda_keyswitch<InputTorus>(
            active_streams.stream(i), active_streams.gpu_index(i), &ks_buffer,
            input_big_lwe_dimension, params.small_lwe_dimension, num_blocks,
            gpu_memory_allocated);

        if (i == 0) {
          size_tracker += sub_size_tracker;
        }
        ks_tmp_buf_vec.push_back(ks_buffer);
      }
    }
  }

  void setup_mem_reuse(uint32_t num_radix_blocks,
                       int_radix_lut_custom_input_output *base_lut_object) {
    // base lut object should have bigger or equal memory than current one
    if (num_radix_blocks > base_lut_object->num_blocks)
      PANIC("Cuda error: lut does not have enough blocks")
    // pbs
    buffer = base_lut_object->buffer;
    // Keyswitch
    tmp_lwe_before_ks = base_lut_object->tmp_lwe_before_ks;

    /// With multiple GPUs we allocate arrays to be pushed to the vectors and
    /// copy data on each GPU then when we gather data to GPU 0 we can copy back
    /// to the original indexing
    lwe_array_in_vec = base_lut_object->lwe_array_in_vec;
    lwe_after_ks_vec = base_lut_object->lwe_after_ks_vec;
    lwe_after_pbs_vec = base_lut_object->lwe_after_pbs_vec;
    lwe_trivial_indexes_vec = base_lut_object->lwe_trivial_indexes_vec;

    ks_tmp_buf_vec = base_lut_object->ks_tmp_buf_vec;

    mem_reuse = true;
  }

  void setup_lwe_trivial_indices(uint32_t num_radix_blocks,
                                 bool allocate_gpu_memory,
                                 uint64_t &size_tracker) {
    // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
    // by default
    lwe_indexes_in = (InputTorus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(InputTorus), active_streams.stream(0),
        active_streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    lwe_indexes_out = (InputTorus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(InputTorus), active_streams.stream(0),
        active_streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    lwe_trivial_indexes = (InputTorus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(InputTorus), active_streams.stream(0),
        active_streams.gpu_index(0), size_tracker, allocate_gpu_memory);

    h_lwe_indexes_in =
        (InputTorus *)malloc(num_radix_blocks * sizeof(InputTorus));
    h_lwe_indexes_out =
        (InputTorus *)malloc(num_radix_blocks * sizeof(InputTorus));

    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes_in[i] = i;

    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_in, h_lwe_indexes_in, num_radix_blocks * sizeof(InputTorus),
        active_streams.stream(0), active_streams.gpu_index(0),
        allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_out, h_lwe_indexes_in,
        num_radix_blocks * sizeof(InputTorus), active_streams.stream(0),
        active_streams.gpu_index(0), allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_trivial_indexes, h_lwe_indexes_in,
        num_radix_blocks * sizeof(InputTorus), active_streams.stream(0),
        active_streams.gpu_index(0), allocate_gpu_memory);
    memcpy(h_lwe_indexes_out, h_lwe_indexes_in,
           num_radix_blocks * sizeof(InputTorus));

    h_lut_indexes =
        (InputTorus *)(calloc(num_radix_blocks, sizeof(InputTorus)));
  }

  void setup_multi_gpu(int_radix_params params, uint32_t num_radix_blocks,
                       bool allocate_gpu_memory, uint64_t &size_tracker) {

    if (!mem_reuse)
      alloc_and_init_multi_gpu_buffers(params, num_radix_blocks,
                                       allocate_gpu_memory, size_tracker);

    if (active_streams.count() > 1) {
      multi_gpu_gather_barrier.create_on(active_streams);
      multi_gpu_broadcast_barrier.create_on(active_streams);
      multi_gpu_scatter_barrier.create_on(active_streams);
    }
  }

  int_radix_lut_custom_input_output(CudaStreams streams,
                                    int_radix_params params, uint32_t num_luts,
                                    uint32_t num_radix_blocks,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {

    setup_config_and_degrees(streams, params.big_lwe_dimension, params,
                             num_luts, 1, num_radix_blocks, num_radix_blocks,
                             allocate_gpu_memory);

    setup_degrees();

    allocate_pbs_buffers(params, num_radix_blocks, allocate_gpu_memory,
                         size_tracker);

    allocate_luts_and_indexes(num_radix_blocks, size_tracker);

    setup_lwe_trivial_indices(num_radix_blocks, allocate_gpu_memory,
                              size_tracker);

    setup_multi_gpu(params, num_radix_blocks, allocate_gpu_memory,
                    size_tracker);
  }

  // Constructor for noise squashing LUT which packs the input
  // ciphertext of num_input_blocks blocks into a new one with fewer blocks,
  // num_radix_blocks
  int_radix_lut_custom_input_output(CudaStreams streams,
                                    uint32_t input_big_lwe_dimension,
                                    int_radix_params params, uint32_t num_luts,
                                    uint32_t num_radix_blocks,
                                    uint32_t num_input_blocks,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {

    setup_config_and_degrees(streams, input_big_lwe_dimension, params, num_luts,
                             1, num_radix_blocks, num_input_blocks,
                             allocate_gpu_memory);

    setup_degrees();

    allocate_pbs_buffers(params, num_radix_blocks, allocate_gpu_memory,
                         size_tracker);

    allocate_luts_and_indexes(num_radix_blocks, size_tracker);

    setup_lwe_trivial_indices(num_radix_blocks, allocate_gpu_memory,
                              size_tracker);

    setup_multi_gpu(params, num_radix_blocks, allocate_gpu_memory,
                    size_tracker);
  }

  // constructor to reuse memory
  int_radix_lut_custom_input_output(
      CudaStreams streams, int_radix_params params, uint32_t num_luts,
      uint32_t num_radix_blocks,
      int_radix_lut_custom_input_output *base_lut_object,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    setup_config_and_degrees(streams, params.big_lwe_dimension, params,
                             num_luts, 1, num_radix_blocks, num_radix_blocks,
                             allocate_gpu_memory);

    setup_degrees();

    setup_mem_reuse(num_radix_blocks, base_lut_object);

    allocate_luts_and_indexes(num_radix_blocks, size_tracker);

    setup_lwe_trivial_indices(num_radix_blocks, allocate_gpu_memory,
                              size_tracker);

    setup_multi_gpu(params, num_radix_blocks, allocate_gpu_memory,
                    size_tracker);
  }

  // Construction for many luts
  int_radix_lut_custom_input_output(CudaStreams streams,
                                    int_radix_params params, uint32_t num_luts,
                                    uint32_t num_radix_blocks,
                                    uint32_t num_many_lut,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {

    setup_config_and_degrees(streams, params.big_lwe_dimension, params,
                             num_luts, num_many_lut, num_radix_blocks,
                             num_radix_blocks, allocate_gpu_memory);

    setup_degrees();

    allocate_pbs_buffers(params, num_radix_blocks, allocate_gpu_memory,
                         size_tracker);

    allocate_luts_and_indexes(num_radix_blocks, size_tracker);

    setup_lwe_trivial_indices(num_radix_blocks, allocate_gpu_memory,
                              size_tracker);

    setup_multi_gpu(params, num_radix_blocks, allocate_gpu_memory,
                    size_tracker);
  }

  // Return a pointer to idx-ith lut at gpu_index's global memory
  OutputTorus *get_lut(uint32_t gpu_index, size_t idx) {
    if (!gpu_memory_allocated)
      return nullptr;
    auto lut = lut_vec[gpu_index];
    size_t lut_size = (params.glwe_dimension + 1) * params.polynomial_size;

    if (lut == nullptr)
      PANIC("Cuda error: invalid lut pointer")
    return &lut[idx * lut_size];
  }

  // Return a pointer to idx-ith degree
  uint64_t *get_degree(size_t idx) {
    GPU_ASSERT(idx < num_luts, "Invalid degree requested");
    return &degrees[num_many_lut * idx];
  }

  // Return a pointer to idx-ith max degree
  uint64_t *get_max_degree(size_t idx) {
    GPU_ASSERT(idx < num_luts, "Invalid degree requested");
    return &max_degrees[idx];
  }

  // Return a pointer to idx-ith lut indexes at gpu_index's global memory
  InputTorus *get_lut_indexes(uint32_t gpu_index, size_t ind) {
    if (!gpu_memory_allocated)
      return nullptr;
    auto lut_indexes = lut_indexes_vec[gpu_index];
    return &lut_indexes[ind];
  }

  // Allocate LUT
  // LUT is used as a trivial encryption and must be initialized outside
  // this constructor
  void allocate_luts_and_indexes(uint32_t num_radix_blocks,
                                 uint64_t &size_tracker) {
    uint64_t lut_indexes_size = num_radix_blocks * sizeof(InputTorus);
    uint64_t lut_buffer_size = (params.glwe_dimension + 1) *
                               params.polynomial_size * sizeof(OutputTorus);

    for (uint i = 0; i < active_streams.count(); i++) {
      auto lut = (OutputTorus *)cuda_malloc_with_size_tracking_async(
          num_luts * lut_buffer_size, active_streams.stream(i),
          active_streams.gpu_index(i), size_tracker, gpu_memory_allocated);
      auto lut_indexes = (InputTorus *)cuda_malloc_with_size_tracking_async(
          lut_indexes_size, active_streams.stream(i),
          active_streams.gpu_index(i), size_tracker, gpu_memory_allocated);
      // lut_indexes is initialized to 0 by default
      // if a different behavior is wanted, it should be rewritten later
      cuda_memset_with_size_tracking_async(
          lut_indexes, 0, lut_indexes_size, active_streams.stream(i),
          active_streams.gpu_index(i), gpu_memory_allocated);
      lut_vec.push_back(lut);
      lut_indexes_vec.push_back(lut_indexes);
    }
  }
  // If this function is called we assume the lwe_indexes_(in/out) are not the
  // trivial anymore and thus we disable optimizations
  void set_lwe_indexes(cudaStream_t stream, uint32_t gpu_index,
                       InputTorus *h_indexes_in, InputTorus *h_indexes_out) {

    memcpy(h_lwe_indexes_in, h_indexes_in, num_blocks * sizeof(InputTorus));
    memcpy(h_lwe_indexes_out, h_indexes_out, num_blocks * sizeof(InputTorus));

    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_in, h_lwe_indexes_in, num_blocks * sizeof(InputTorus),
        stream, gpu_index, gpu_memory_allocated);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_out, h_lwe_indexes_out, num_blocks * sizeof(InputTorus),
        stream, gpu_index, gpu_memory_allocated);

    using_trivial_lwe_indexes = false;
  }

private:
  /// Generates LUT indexes, validates them, and copies to this LUT's GPU index
  /// buffer. This is an internal helper - use generate_and_broadcast_lut with
  /// an index generator instead.
  ///
  /// @tparam IndexGenerator Callable with signature: void(InputTorus* indexes,
  /// uint32_t count)
  /// @param streams         CUDA streams for async operations
  /// @param generator       Function/lambda that fills the index buffer
  /// @param num_indexes     Number of indexes to generate (must equal
  /// num_blocks)
  /// @param h_buffer        Optional CPU buffer; if nullptr, uses h_lut_indexes
  template <typename IndexGenerator>
  void set_lut_indexes(CudaStreams streams, IndexGenerator generator,
                       uint32_t num_indexes, InputTorus *h_buffer = nullptr) {
    GPU_ASSERT(num_indexes == num_blocks,
               "num_indexes (%u) must equal num_blocks (%u)", num_indexes,
               num_blocks);

    InputTorus *index_buffer = (h_buffer != nullptr) ? h_buffer : h_lut_indexes;

    GPU_ASSERT(index_buffer != nullptr,
               "No buffer provided and h_lut_indexes is null");

    generate_lut_indexes<InputTorus>(streams, generator, get_lut_indexes(0, 0),
                                     num_indexes, num_luts, index_buffer,
                                     gpu_memory_allocated);
  }

  /// Sets all LUT indexes to a constant value on both CPU and GPU.
  /// Does not broadcast - caller must call broadcast_lut if needed.
  void set_lut_indexes_to_constant_async(const CudaStreams &streams,
                                         InputTorus value) {
    GPU_ASSERT(
        value < num_luts,
        "Constant LUT index out of bounds: value = %llu >= num_luts (%u)",
        (unsigned long long)value, num_luts);

    if (gpu_memory_allocated) {
      // Keep the CPU buffer equal to the GPU one
      for (uint32_t i = 0; i < num_blocks; i++) {
        h_lut_indexes[i] = value;
      }

      cuda_set_value_async<InputTorus>(streams.stream(0), streams.gpu_index(0),
                                       get_lut_indexes(0, 0), value,
                                       num_blocks);
    }
  }

public:
  /// Copies precomputed LUT indexes from a GPU buffer to this LUT's GPU index
  /// buffer.
  ///
  /// @param streams              CUDA streams for async operations
  /// @param d_src_lut_indexes    Source GPU buffer containing precomputed
  /// indexes
  /// @param num_indexes          Number of indexes to copy
  void
  set_lut_indexes_and_broadcast_from_gpu(CudaStreams streams,
                                         InputTorus const *d_src_lut_indexes,
                                         uint32_t num_indexes) {
    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        get_lut_indexes(0, 0), d_src_lut_indexes,
        num_indexes * sizeof(InputTorus), streams.stream(0),
        streams.gpu_index(0), gpu_memory_allocated);
    broadcast_lut(streams, false);

    // In some cases, num_indexes can be less than the number of blocks
    // that the LUT was created for but broadcast_lut sets
    // last_broadcast_num_radix_blocks = num_blocks
    last_broadcast_num_radix_blocks = num_indexes;
  }

  /// Sets all LUT indexes to a constant value and broadcasts to all active
  /// GPUs. Also updates the CPU-side h_lut_indexes to keep them in sync.
  ///
  /// @param streams    CUDA streams for async operations
  /// @param value      The constant value to set all indexes to
  void set_lut_indexes_and_broadcast_constant(CudaStreams streams,
                                              InputTorus value) {
    set_lut_indexes_to_constant_async(streams, value);
    broadcast_lut(streams, false);
  }

  // Broadcast luts from device gpu_indexes[0] to all active gpus
  void broadcast_lut(CudaStreams new_active_streams,
                     bool broadcast_lut_values = true) {
    PANIC_IF_FALSE(new_active_streams.gpu_index(0) ==
                       active_streams.gpu_index(0),
                   "Broadcasting LUTs can only be done using the same GPUs "
                   " originally assigned to the int_radix_lut");

    last_broadcast_streams = new_active_streams;
    last_broadcast_num_radix_blocks = num_blocks;

    // We only do broadcast if there are more than 1 active GPU
    if (new_active_streams.count() == 1)
      return;

    GPU_ASSERT(active_streams.count() >= new_active_streams.count(),
               "To broadcast a LUT to a GPU set, it must have been initialized "
               "with a GPU set that is greater or equal in size");

    int active_device = cuda_get_device();

    uint64_t lut_size = (params.glwe_dimension + 1) * params.polynomial_size;

    // Wait for GPU 0 to receive all data from previous computations
    // that may have occurred on different GPUs
    multi_gpu_broadcast_barrier.local_streams_wait_for_stream_0(
        new_active_streams);

    // The LUT and its indexes reside on GPU 0
    // these were filled by calls to generate_device_accumulator
    // due to the previous synchronization, we're sure these buffers have
    // finished copying to GPU 0 from CPU
    auto src_lut = lut_vec[0];
    auto src_lut_indexes = lut_indexes_vec[0];

    for (uint i = 1; i < new_active_streams.count(); i++) {
      PANIC_IF_FALSE(
          new_active_streams.gpu_index(i) == active_streams.gpu_index(i),
          "Broadcasting LUTs can only be done to the LUT streams or to new "
          "streams that reside on the same GPUs as the source LUTs");

      // Check for redundant copies
#ifndef DEBUG_FAKE_MULTI_GPU
      PANIC_IF_FALSE(new_active_streams.gpu_index(i) !=
                         new_active_streams.gpu_index(0),
                     "Broadcast LUT does not handle duplicate GPUs in the "
                     "active streams set");
#endif

      if (broadcast_lut_values) {
        auto dst_lut = lut_vec[i];
        cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
            dst_lut, src_lut, num_luts * lut_size * sizeof(OutputTorus),
            new_active_streams.stream(i), new_active_streams.gpu_index(i),
            gpu_memory_allocated);
      }
      auto dst_lut_indexes = lut_indexes_vec[i];
      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          dst_lut_indexes, src_lut_indexes, num_blocks * sizeof(InputTorus),
          new_active_streams.stream(i), new_active_streams.gpu_index(i),
          gpu_memory_allocated);
    }

    // Ensure the device set at the end of this method is the same as it was
    // set at the beginning
    cuda_set_device(active_device);
  }

  void allocate_lwe_vector_for_non_trivial_indexes(
      CudaStreams streams, uint64_t max_num_radix_blocks,
      uint64_t &size_tracker, bool allocate_gpu_memory) {
    int classical_threshold =
        sizeof(OutputTorus) == 16
            ? THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128
            : THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS;
    int threshold = (params.pbs_type == PBS_TYPE::MULTI_BIT)
                        ? THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS
                        : classical_threshold;

    // We need to create the auxiliary array only in GPU 0
    if (active_streams.count() > 1) {
      lwe_aligned_vec.resize(active_streams.count());
      for (uint i = 0; i < active_streams.count(); i++) {
        uint64_t size_tracker_on_array_i = 0;
        auto inputs_on_gpu = std::min(
            (int)max_num_radix_blocks,
            std::max(threshold, get_num_inputs_on_gpu(max_num_radix_blocks, i,
                                                      active_streams.count())));
        InputTorus *d_array =
            (InputTorus *)cuda_malloc_with_size_tracking_async(
                inputs_on_gpu * (params.big_lwe_dimension + 1) *
                    sizeof(InputTorus),
                streams.stream(0), streams.gpu_index(0),
                size_tracker_on_array_i, allocate_gpu_memory);
        lwe_aligned_vec[i] = d_array;
        size_tracker += size_tracker_on_array_i;
      }
    }
  }

  template <typename IndexGenerator = std::nullptr_t>
  void generate_and_broadcast_lut(
      const CudaStreams &streams, std::vector<uint32_t> lut_ids,
      std::vector<std::function<OutputTorus(OutputTorus)>> lut_value_generator,
      IndexGenerator index_generator, bool use_encoding = true,
      std::vector<OutputTorus *> h_lut_value_buffers = {},
      InputTorus *h_index_buffer = nullptr) {
    // streams should be a subset of active_streams

    GPU_ASSERT(
        h_lut_value_buffers.empty() || (use_encoding && gpu_memory_allocated),
        "LUT Generation with pre-allocated CPU buffer only supports "
        "generation with encoding and expects gpu_memory_allocated==True "
        "");

    // Generate LUT indexes based on index_generator
    if constexpr (!std::is_same_v<IndexGenerator, std::nullptr_t>) {
      set_lut_indexes(streams, index_generator, num_blocks, h_index_buffer);
    } else {
      // LUT_0_FOR_ALL_BLOCKS: set all indexes to 0
      set_lut_indexes_to_constant_async(streams, 0);
    }

    for (uint32_t i = 0; i < lut_ids.size(); ++i) {
      if (use_encoding) {
        if (h_lut_value_buffers.empty()) {
          generate_device_accumulator<OutputTorus>(
              streams.stream(0), streams.gpu_index(0), get_lut(0, lut_ids[i]),
              get_degree(lut_ids[i]), get_max_degree(lut_ids[i]),
              params.glwe_dimension, params.polynomial_size,
              params.message_modulus, params.carry_modulus,
              lut_value_generator[i], gpu_memory_allocated);
        } else {
          generate_device_accumulator_with_cpu_prealloc<OutputTorus>(
              streams.stream(0), streams.gpu_index(0), get_lut(0, lut_ids[i]),
              get_degree(lut_ids[i]), get_max_degree(lut_ids[i]),
              params.glwe_dimension, params.polynomial_size,
              params.message_modulus, params.carry_modulus,
              lut_value_generator[i], true, h_lut_value_buffers[i]);
        }
      } else {
        generate_device_accumulator_no_encoding<OutputTorus>(
            streams.stream(0), streams.gpu_index(0), get_lut(0, lut_ids[i]),
            get_degree(lut_ids[i]), params.message_modulus,
            params.carry_modulus, params.glwe_dimension, params.polynomial_size,
            lut_value_generator[i], gpu_memory_allocated);
      }
    }
    broadcast_lut(streams);
  }

  // Generate and broadcast LUT with custom input/output encoding parameters.
  // This is useful when the input and output message/carry modulus differ,
  // such as in decompression rescaling.
  void generate_and_broadcast_lut_with_encoding(
      const CudaStreams &streams, std::vector<uint32_t> lut_indexes,
      std::vector<std::function<OutputTorus(OutputTorus)>> f,
      uint32_t input_message_modulus, uint32_t input_carry_modulus,
      uint32_t output_message_modulus, uint32_t output_carry_modulus,
      std::vector<OutputTorus *> cpu_prealloc_buffers = {}) {

    GPU_ASSERT(cpu_prealloc_buffers.empty() || gpu_memory_allocated,
               "LUT Generation with pre-allocated CPU buffer expects "
               "gpu_memory_allocated==True ");

    for (uint32_t i = 0; i < lut_indexes.size(); ++i) {
      if (cpu_prealloc_buffers.empty()) {
        generate_device_accumulator_with_encoding<OutputTorus>(
            streams.stream(0), streams.gpu_index(0), get_lut(0, lut_indexes[i]),
            get_degree(lut_indexes[i]), get_max_degree(lut_indexes[i]),
            params.glwe_dimension, params.polynomial_size,
            input_message_modulus, input_carry_modulus, output_message_modulus,
            output_carry_modulus, f[i], gpu_memory_allocated);
      } else {
        generate_device_accumulator_with_encoding_with_cpu_prealloc<
            OutputTorus>(
            streams.stream(0), streams.gpu_index(0), get_lut(0, lut_indexes[i]),
            get_degree(lut_indexes[i]), get_max_degree(lut_indexes[i]),
            params.glwe_dimension, params.polynomial_size,
            input_message_modulus, input_carry_modulus, output_message_modulus,
            output_carry_modulus, f[i], true, cpu_prealloc_buffers[i]);
      }
    }
    broadcast_lut(streams);
  }

  template <typename IndexGenerator = std::nullptr_t>
  void generate_and_broadcast_many_lut(
      const CudaStreams &streams, std::vector<uint32_t> lut_indexes,
      std::vector<std::vector<std::function<OutputTorus(OutputTorus)>>>
          funcs_many_lut,
      IndexGenerator index_generator) {
    // streams should be a subset of active_streams

    if constexpr (!std::is_same_v<IndexGenerator, std::nullptr_t>) {
      set_lut_indexes(streams, index_generator, num_blocks);
    } else {
      // LUT_0_FOR_ALL_BLOCKS: set all indexes to 0
      set_lut_indexes_to_constant_async(streams, 0);
    }

    for (uint32_t i = 0; i < lut_indexes.size(); ++i) {
      generate_many_lut_device_accumulator<OutputTorus>(
          streams.stream(0), streams.gpu_index(0), get_lut(0, lut_indexes[i]),
          get_degree(lut_indexes[i]), get_max_degree(lut_indexes[i]),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, funcs_many_lut[i], gpu_memory_allocated);
    }
    broadcast_lut(streams);
  }

  template <typename IndexGenerator = std::nullptr_t>
  void generate_and_broadcast_bivariate_lut(
      const CudaStreams &streams, std::vector<uint32_t> lut_indexes,
      std::vector<std::function<OutputTorus(OutputTorus, OutputTorus)>> f,
      IndexGenerator index_generator,
      std::vector<OutputTorus *> cpu_prealloc_buffers = {},
      std::optional<int> factor = std::nullopt) {
    // streams should be a subset of active_streams

    if constexpr (!std::is_same_v<IndexGenerator, std::nullptr_t>) {
      set_lut_indexes(streams, index_generator, num_blocks);
    } else {
      // LUT_0_FOR_ALL_BLOCKS: set all indexes to 0
      set_lut_indexes_to_constant_async(streams, 0);
    }

    for (uint32_t i = 0; i < lut_indexes.size(); ++i) {
      if (cpu_prealloc_buffers.empty()) {
        if (factor.has_value()) {
          generate_device_accumulator_bivariate_with_factor<OutputTorus>(
              streams.stream(0), streams.gpu_index(0),
              get_lut(0, lut_indexes[i]), get_degree(lut_indexes[i]),
              get_max_degree(lut_indexes[i]), params.glwe_dimension,
              params.polynomial_size, params.message_modulus,
              params.carry_modulus, f[i], factor.value(), gpu_memory_allocated);
        } else {
          generate_device_accumulator_bivariate<OutputTorus>(
              streams.stream(0), streams.gpu_index(0),
              get_lut(0, lut_indexes[i]), get_degree(lut_indexes[i]),
              get_max_degree(lut_indexes[i]), params.glwe_dimension,
              params.polynomial_size, params.message_modulus,
              params.carry_modulus, f[i], gpu_memory_allocated);
        }
      } else {
        generate_device_accumulator_bivariate_with_cpu_prealloc<OutputTorus>(
            streams.stream(0), streams.gpu_index(0), get_lut(0, lut_indexes[i]),
            get_degree(lut_indexes[i]), get_max_degree(lut_indexes[i]),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, f[i], true,
            cpu_prealloc_buffers[i]);
      }
    }
    broadcast_lut(streams);
  }

  void release(CudaStreams streams) {
    PANIC_IF_FALSE(lut_indexes_vec.size() == lut_vec.size(),
                   "Lut vec and Lut vec indexes must have the same size");
    for (uint i = 0; i < lut_vec.size(); i++) {
      cuda_drop_with_size_tracking_async(lut_vec[i], active_streams.stream(i),
                                         active_streams.gpu_index(i),
                                         gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          lut_indexes_vec[i], active_streams.stream(i),
          active_streams.gpu_index(i), gpu_memory_allocated);
    }
    cuda_drop_with_size_tracking_async(lwe_indexes_in, active_streams.stream(0),
                                       active_streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(
        lwe_indexes_out, active_streams.stream(0), active_streams.gpu_index(0),
        gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(
        lwe_trivial_indexes, active_streams.stream(0),
        active_streams.gpu_index(0), gpu_memory_allocated);

    cuda_synchronize_stream(active_streams.stream(0),
                            active_streams.gpu_index(0));
    lut_vec.clear();
    lut_indexes_vec.clear();
    free(h_lwe_indexes_in);
    free(h_lwe_indexes_out);

    if (active_streams.count() > 1) {
      active_streams.synchronize();
      event_pool.release();
      multi_gpu_gather_barrier.release();
      multi_gpu_broadcast_barrier.release();
      multi_gpu_scatter_barrier.release();
    }

    if (!mem_reuse) {
      release_radix_ciphertext_async(active_streams.stream(0),
                                     active_streams.gpu_index(0),
                                     tmp_lwe_before_ks, gpu_memory_allocated);
      for (int i = 0; i < buffer.size(); i++) {
        switch (params.pbs_type) {
        case MULTI_BIT:
          cleanup_cuda_multi_bit_programmable_bootstrap(
              active_streams.stream(i), active_streams.gpu_index(i),
              &buffer[i]);
          break;
        case CLASSICAL:
          cleanup_cuda_programmable_bootstrap(active_streams.stream(i),
                                              active_streams.gpu_index(i),
                                              &buffer[i]);
          break;
        default:
          PANIC("Cuda error (PBS): unknown PBS type. ")
        }
        cuda_synchronize_stream(active_streams.stream(i),
                                active_streams.gpu_index(i));
      }
      delete tmp_lwe_before_ks;
      buffer.clear();

      if (gpu_memory_allocated) {
        multi_gpu_release_async(active_streams, lwe_array_in_vec);
        multi_gpu_release_async(active_streams, lwe_after_ks_vec);
        multi_gpu_release_async(active_streams, lwe_after_pbs_vec);
        multi_gpu_release_async(active_streams, lwe_trivial_indexes_vec);
      }
      lwe_array_in_vec.clear();
      lwe_after_ks_vec.clear();
      lwe_after_pbs_vec.clear();
      lwe_trivial_indexes_vec.clear();
      if (lwe_aligned_vec.size() > 0) {
        for (uint i = 0; i < active_streams.count(); i++) {
          cuda_drop_with_size_tracking_async(
              lwe_aligned_vec[i], active_streams.stream(0),
              active_streams.gpu_index(0), gpu_memory_allocated);
        }
        lwe_aligned_vec.clear();
      }

      for (auto i = 0; i < ks_tmp_buf_vec.size(); i++) {
        cleanup_cuda_keyswitch(active_streams.stream(i),
                               active_streams.gpu_index(i), ks_tmp_buf_vec[i],
                               gpu_memory_allocated);
      }
      ks_tmp_buf_vec.clear();
    }
    free(h_lut_indexes);
    free(degrees);
    free(max_degrees);
  }
};

template <typename Torus, typename OutputTorus = Torus>
using int_radix_lut = int_radix_lut_custom_input_output<Torus, Torus>;

template <typename InputTorus>
struct int_noise_squashing_lut
    : int_radix_lut_custom_input_output<InputTorus, __uint128_t> {

  std::vector<InputTorus *> lwe_aligned_scatter_vec;
  std::vector<__uint128_t *> lwe_aligned_gather_vec;
  // noise squashing constructor
  int_noise_squashing_lut(CudaStreams streams, int_radix_params params,
                          uint32_t input_glwe_dimension,
                          uint32_t input_polynomial_size,
                          uint32_t num_radix_blocks,
                          uint32_t original_num_blocks,
                          bool allocate_gpu_memory, uint64_t &size_tracker)

      : int_radix_lut_custom_input_output<InputTorus, __uint128_t>(
            streams, input_glwe_dimension * input_polynomial_size, params, 1,
            num_radix_blocks, original_num_blocks, allocate_gpu_memory,
            size_tracker) {

    // lut for the squashing
    auto f_squash = [](__uint128_t block) -> __uint128_t { return block; };

    this->generate_and_broadcast_lut(this->active_streams, {0}, {f_squash},
                                     LUT_0_FOR_ALL_BLOCKS);
  }

  using int_radix_lut_custom_input_output<InputTorus, __uint128_t>::release;
};

// Forward declarations for operation buffers
template <typename Torus> struct int_sub_and_propagate;

template <typename Torus> struct int_bit_extract_luts_buffer {
  int_radix_params params;
  int_radix_lut<Torus> *lut;
  bool gpu_memory_allocated;

  // With offset
  int_bit_extract_luts_buffer(CudaStreams streams, int_radix_params params,
                              uint32_t bits_per_block, uint32_t final_offset,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    lut = new int_radix_lut<Torus>(streams, params, bits_per_block,
                                   bits_per_block * num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);

    std::vector<std::function<Torus(Torus)>> lut_funs;
    std::vector<uint32_t> lut_indices;
    for (int i = 0; i < bits_per_block; i++) {
      auto operator_f = [i, final_offset](Torus x) -> Torus {
        Torus y = (x >> i) & 1;
        return y << final_offset;
      };
      lut_funs.push_back(operator_f);
      lut_indices.push_back(i);
    }

    /**
     * we have bits_per_blocks LUTs that should be used for all bits in all
     * blocks
     */
    auto total_blocks = bits_per_block * num_radix_blocks;
    auto active_streams =
        streams.active_gpu_subset(total_blocks, params.pbs_type);

    auto lut_index_generator =
        [num_radix_blocks, bits_per_block](Torus *h_lut_indexes, uint32_t) {
          for (int j = 0; j < num_radix_blocks; j++) {
            for (int i = 0; i < bits_per_block; i++)
              h_lut_indexes[i + j * bits_per_block] = i;
          }
        };

    lut->generate_and_broadcast_lut(active_streams, lut_indices, lut_funs,
                                    lut_index_generator);

    /**
     * the input indexes should take the first bits_per_block PBS to target
     * the block 0, then block 1, etc...
     */
    Torus *h_lwe_indexes_in =
        (Torus *)malloc(num_radix_blocks * bits_per_block * sizeof(Torus));

    for (int j = 0; j < num_radix_blocks; j++) {
      for (int i = 0; i < bits_per_block; i++)
        h_lwe_indexes_in[i + j * bits_per_block] = j;
    }

    /**
     * the output should aim different lwe ciphertexts, so lwe_indexes_out =
     * range(num_luts)
     */
    Torus *h_lwe_indexes_out =
        (Torus *)malloc(num_radix_blocks * bits_per_block * sizeof(Torus));

    for (int i = 0; i < num_radix_blocks * bits_per_block; i++)
      h_lwe_indexes_out[i] = i;

    lut->set_lwe_indexes(streams.stream(0), streams.gpu_index(0),
                         h_lwe_indexes_in, h_lwe_indexes_out);
    lut->allocate_lwe_vector_for_non_trivial_indexes(
        active_streams, num_radix_blocks * bits_per_block, size_tracker,
        allocate_gpu_memory);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(h_lwe_indexes_in);
    free(h_lwe_indexes_out);
  }

  // Without offset
  int_bit_extract_luts_buffer(CudaStreams streams, int_radix_params params,
                              uint32_t bits_per_block,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory, uint64_t &size_tracker)
      : int_bit_extract_luts_buffer(streams, params, bits_per_block, 0,
                                    num_radix_blocks, allocate_gpu_memory,
                                    size_tracker) {}

  void release(CudaStreams streams) {
    lut->release(streams);
    delete (lut);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_fullprop_buffer {
  int_radix_params params;

  int_radix_lut<Torus> *lut;

  CudaRadixCiphertextFFI *tmp_small_lwe_vector;
  CudaRadixCiphertextFFI *tmp_big_lwe_vector;
  bool gpu_memory_allocated;

  int_fullprop_buffer(CudaStreams streams, int_radix_params params,
                      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;
    lut = new int_radix_lut<Torus>(streams.get_ith(0), params, 2, 2,
                                   allocate_gpu_memory, size_tracker);

    // LUTs
    auto lut_f_message = [params](Torus x) -> Torus {
      return x % params.message_modulus;
    };
    auto lut_f_carry = [params](Torus x) -> Torus {
      return x / params.message_modulus;
    };

    //

    //
    // No broadcast is needed because full prop is done on 1 single GPU.
    // By passing a single-GPU CudaStreams with streams.get_ith(0) the LUT is
    // not broadcast.
    //
    auto active_streams = streams.get_ith(0);
    auto lut_index_generator = [](Torus *h_lut_indexes, uint32_t) {
      for (int i = 0; i < 2; i++)
        h_lut_indexes[i] = i;
    };
    lut->generate_and_broadcast_lut(active_streams, {0, 1},
                                    {lut_f_message, lut_f_carry},
                                    lut_index_generator);

    tmp_small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_small_lwe_vector, 2,
        params.small_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_big_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_big_lwe_vector, 2,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_small_lwe_vector, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_big_lwe_vector, gpu_memory_allocated);
    lut->release(streams.get_ith(0));
    delete tmp_small_lwe_vector;
    delete tmp_big_lwe_vector;
    delete lut;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_sum_ciphertexts_vec_memory {

  int_radix_params params;
  uint32_t max_total_blocks_in_vec;
  uint32_t num_blocks_in_radix;
  uint32_t max_num_radix_in_vec;
  uint32_t chunk_size;
  bool gpu_memory_allocated;
  bool reduce_degrees_for_single_carry_propagation;

  // temporary buffers
  CudaRadixCiphertextFFI *current_blocks;
  CudaRadixCiphertextFFI *small_lwe_vector;

  uint32_t *d_columns_data;
  uint32_t *d_columns_counter;
  uint32_t **d_columns;

  uint32_t *d_new_columns_data;
  uint32_t *d_new_columns_counter;
  uint32_t **d_new_columns;

  uint64_t *d_degrees;

  // lookup table for extracting message and carry
  int_radix_lut<Torus> *luts_message_carry;

  bool mem_reuse = false;
  bool allocated_luts_message_carry;

  void setup_index_buffers(CudaStreams streams, uint64_t &size_tracker) {

    d_degrees = (uint64_t *)cuda_malloc_with_size_tracking_async(
        max_total_blocks_in_vec * sizeof(uint64_t), streams.stream(0),
        streams.gpu_index(0), size_tracker, gpu_memory_allocated);

    auto num_blocks_in_radix = this->num_blocks_in_radix;
    auto max_num_radix_in_vec = this->max_num_radix_in_vec;
    auto setup_columns = [num_blocks_in_radix, max_num_radix_in_vec, streams](
                             uint32_t **&columns, uint32_t *&columns_data,
                             uint32_t *&columns_counter, uint64_t &size_tracker,
                             bool gpu_memory_allocated) {
      columns_data = (uint32_t *)cuda_malloc_with_size_tracking_async(
          num_blocks_in_radix * max_num_radix_in_vec * sizeof(uint32_t),
          streams.stream(0), streams.gpu_index(0), size_tracker,
          gpu_memory_allocated);
      columns_counter = (uint32_t *)cuda_malloc_with_size_tracking_async(
          num_blocks_in_radix * sizeof(uint32_t), streams.stream(0),
          streams.gpu_index(0), size_tracker, gpu_memory_allocated);
      cuda_memset_with_size_tracking_async(
          columns_counter, 0, num_blocks_in_radix * sizeof(uint32_t),
          streams.stream(0), streams.gpu_index(0), gpu_memory_allocated);
      uint32_t **h_columns = new uint32_t *[num_blocks_in_radix];
      for (int i = 0; i < num_blocks_in_radix; ++i) {
        h_columns[i] = columns_data + i * max_num_radix_in_vec;
      }
      columns = (uint32_t **)cuda_malloc_with_size_tracking_async(
          num_blocks_in_radix * sizeof(uint32_t *), streams.stream(0),
          streams.gpu_index(0), size_tracker, gpu_memory_allocated);
      if (gpu_memory_allocated) {
        cuda_memcpy_async_to_gpu(columns, h_columns,
                                 num_blocks_in_radix * sizeof(uint32_t *),
                                 streams.stream(0), streams.gpu_index(0));
      }
      cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
      delete[] h_columns;
    };

    setup_columns(d_columns, d_columns_data, d_columns_counter, size_tracker,
                  gpu_memory_allocated);
    setup_columns(d_new_columns, d_new_columns_data, d_new_columns_counter,
                  size_tracker, gpu_memory_allocated);
  }

  void setup_lookup_tables(CudaStreams streams, uint32_t num_radix_in_vec,
                           const uint64_t *const degrees) {
    uint32_t message_modulus = params.message_modulus;
    bool _needs_processing = false;
    radix_columns current_columns(degrees, num_blocks_in_radix,
                                  num_radix_in_vec, chunk_size,
                                  _needs_processing);
    uint32_t total_ciphertexts = 0;
    uint32_t total_messages = 0;
    current_columns.next_accumulation(total_ciphertexts, total_messages,
                                      _needs_processing);
    uint32_t pbs_count = std::max(total_ciphertexts, 2 * num_blocks_in_radix);
    if (!mem_reuse) {
      if (total_ciphertexts > 0 ||
          reduce_degrees_for_single_carry_propagation) {
        uint64_t size_tracker = 0;
        allocated_luts_message_carry = true;
        luts_message_carry = new int_radix_lut<Torus>(
            streams, params, 2, pbs_count, true, size_tracker);

        uint64_t message_modulus_bits =
            (uint64_t)std::log2(params.message_modulus);
        uint64_t carry_modulus_bits = (uint64_t)std::log2(params.carry_modulus);
        uint64_t total_bits_per_block =
            message_modulus_bits + carry_modulus_bits;
        uint64_t denominator =
            (uint64_t)std::ceil((pow(2, total_bits_per_block) - 1) /
                                (pow(2, message_modulus_bits) - 1));

        uint64_t upper_bound_num_blocks =
            max_total_blocks_in_vec * 2 / denominator;
        luts_message_carry->allocate_lwe_vector_for_non_trivial_indexes(
            streams, upper_bound_num_blocks, size_tracker, true);
      }
    }

    if (allocated_luts_message_carry) {
      // define functions for each accumulator
      auto lut_f_message = [message_modulus](Torus x) -> Torus {
        return x % message_modulus;
      };
      auto lut_f_carry = [message_modulus](Torus x) -> Torus {
        return x / message_modulus;
      };

      auto active_gpu_count_mc =
          streams.active_gpu_subset(pbs_count, params.pbs_type);
      luts_message_carry->generate_and_broadcast_lut(
          active_gpu_count_mc, {0, 1}, {lut_f_message, lut_f_carry},
          LUT_0_FOR_ALL_BLOCKS);
    }
  }
  int_sum_ciphertexts_vec_memory(
      CudaStreams streams, int_radix_params params,
      uint32_t num_blocks_in_radix, uint32_t max_num_radix_in_vec,
      bool reduce_degrees_for_single_carry_propagation,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->mem_reuse = false;
    this->max_total_blocks_in_vec = num_blocks_in_radix * max_num_radix_in_vec;
    this->num_blocks_in_radix = num_blocks_in_radix;
    this->max_num_radix_in_vec = max_num_radix_in_vec;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->chunk_size = (params.message_modulus * params.carry_modulus - 1) /
                       (params.message_modulus - 1);
    this->allocated_luts_message_carry = false;
    this->reduce_degrees_for_single_carry_propagation =
        reduce_degrees_for_single_carry_propagation;

    setup_index_buffers(streams, size_tracker);
    // because we setup_lut in host function for sum_ciphertexts to save memory
    // the size_tracker is topped up here to have a max bound on the used memory
    uint32_t max_pbs_count = std::max(
        2 * (max_total_blocks_in_vec / chunk_size), 2 * num_blocks_in_radix);
    if (max_pbs_count > 0) {
      int_radix_lut<Torus> *luts_message_carry_dry_run =
          new int_radix_lut<Torus>(streams, params, 2, max_pbs_count, false,
                                   size_tracker);
      luts_message_carry_dry_run->release(streams);
      delete luts_message_carry_dry_run;
    }

    // create and allocate intermediate buffers
    current_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), current_blocks,
        max_total_blocks_in_vec, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), small_lwe_vector,
        max_total_blocks_in_vec, params.small_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  int_sum_ciphertexts_vec_memory(
      CudaStreams streams, int_radix_params params,
      uint32_t num_blocks_in_radix, uint32_t max_num_radix_in_vec,
      CudaRadixCiphertextFFI *current_blocks,
      CudaRadixCiphertextFFI *small_lwe_vector,
      int_radix_lut<Torus> *reused_lut,
      bool reduce_degrees_for_single_carry_propagation,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->mem_reuse = true;
    this->params = params;
    this->max_total_blocks_in_vec = num_blocks_in_radix * max_num_radix_in_vec;
    this->num_blocks_in_radix = num_blocks_in_radix;
    this->max_num_radix_in_vec = max_num_radix_in_vec;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->chunk_size = (params.message_modulus * params.carry_modulus - 1) /
                       (params.message_modulus - 1);
    this->allocated_luts_message_carry = true;
    this->reduce_degrees_for_single_carry_propagation =
        reduce_degrees_for_single_carry_propagation;

    this->current_blocks = current_blocks;
    this->small_lwe_vector = small_lwe_vector;
    this->luts_message_carry = reused_lut;

    uint64_t message_modulus_bits = (uint64_t)std::log2(params.message_modulus);
    uint64_t carry_modulus_bits = (uint64_t)std::log2(params.carry_modulus);
    uint64_t total_bits_per_block = message_modulus_bits + carry_modulus_bits;
    uint64_t denominator =
        (uint64_t)std::ceil((pow(2, total_bits_per_block) - 1) /
                            (pow(2, message_modulus_bits) - 1));

    uint64_t upper_bound_num_blocks = max_total_blocks_in_vec * 2 / denominator;
    this->luts_message_carry->allocate_lwe_vector_for_non_trivial_indexes(
        streams, upper_bound_num_blocks, size_tracker, allocate_gpu_memory);
    setup_index_buffers(streams, size_tracker);
  }

  void release(CudaStreams streams) {
    cuda_drop_with_size_tracking_async(d_degrees, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_columns_data, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_columns_counter, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_columns, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);

    cuda_drop_with_size_tracking_async(d_new_columns_data, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_new_columns_counter, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_new_columns, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);

    if (!mem_reuse) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     current_blocks, gpu_memory_allocated);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     small_lwe_vector, gpu_memory_allocated);
      if (allocated_luts_message_carry) {
        luts_message_carry->release(streams);
        delete luts_message_carry;
      }
      delete current_blocks;
      delete small_lwe_vector;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

// For sequential algorithm in group propagation
template <typename Torus> struct int_seq_group_prop_memory {

  CudaRadixCiphertextFFI *group_resolved_carries;
  int_radix_lut<Torus> *lut_sequential_algorithm;
  uint32_t grouping_size;
  bool gpu_memory_allocated;

  int_seq_group_prop_memory(CudaStreams streams, int_radix_params params,
                            uint32_t group_size, uint32_t big_lwe_size_bytes,
                            bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    grouping_size = group_size;
    group_resolved_carries = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), group_resolved_carries,
        grouping_size, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    int num_seq_luts = grouping_size - 1;
    lut_sequential_algorithm =
        new int_radix_lut<Torus>(streams, params, num_seq_luts, num_seq_luts,
                                 allocate_gpu_memory, size_tracker);
    std::vector<std::function<Torus(Torus)>> lut_funcs;
    std::vector<uint32_t> lut_indices;
    Torus *h_seq_lut_indexes = (Torus *)malloc(num_seq_luts * sizeof(Torus));

    for (int index = 0; index < num_seq_luts; index++) {
      auto f_lut_sequential = [index](Torus propa_cum_sum_block) {
        return (propa_cum_sum_block >> (index + 1)) & 1;
      };
      lut_funcs.push_back(f_lut_sequential);
      lut_indices.push_back(index);
    }
    auto active_streams =
        streams.active_gpu_subset(num_seq_luts, params.pbs_type);
    auto lut_index_generator = [](Torus *h_lut_indexes, uint32_t num_indexes) {
      for (uint32_t i = 0; i < num_indexes; i++)
        h_lut_indexes[i] = i;
    };
    lut_sequential_algorithm->generate_and_broadcast_lut(
        active_streams, lut_indices, lut_funcs, lut_index_generator, true, {},
        h_seq_lut_indexes);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(h_seq_lut_indexes);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   group_resolved_carries,
                                   gpu_memory_allocated);
    lut_sequential_algorithm->release(streams);
    delete group_resolved_carries;
    delete lut_sequential_algorithm;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  };
};

// For hillis steele algorithm in group propagation
template <typename Torus> struct int_hs_group_prop_memory {

  int_radix_lut<Torus> *lut_hillis_steele;
  bool gpu_memory_allocated;

  int_hs_group_prop_memory(CudaStreams streams, int_radix_params params,
                           uint32_t num_groups, uint32_t big_lwe_size_bytes,
                           bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;

    auto f_lut_hillis_steele = [](Torus msb, Torus lsb) -> Torus {
      if (msb == 2) {
        return 1; // Remap Generate to 1
      } else if (msb == 3) {
        // MSB propagates
        if (lsb == 2) {
          return 1;
        } else {
          return lsb;
        } // also remap here
      } else {
        return msb;
      }
    };

    lut_hillis_steele = new int_radix_lut<Torus>(
        streams, params, 1, num_groups, allocate_gpu_memory, size_tracker);

    auto active_streams =
        streams.active_gpu_subset(num_groups, params.pbs_type);
    lut_hillis_steele->generate_and_broadcast_bivariate_lut(
        active_streams, {0}, {f_lut_hillis_steele}, LUT_0_FOR_ALL_BLOCKS);
  }
  void release(CudaStreams streams) {

    lut_hillis_steele->release(streams);
    delete lut_hillis_steele;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

// compute_shifted_blocks_and_block_states
template <typename Torus> struct int_shifted_blocks_and_states_memory {
  CudaRadixCiphertextFFI *shifted_blocks_and_states;
  CudaRadixCiphertextFFI *shifted_blocks;
  CudaRadixCiphertextFFI *block_states;

  int_radix_lut<Torus> *luts_array_first_step;
  bool gpu_memory_allocated;

  int_shifted_blocks_and_states_memory(
      CudaStreams streams, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t num_many_lut, uint32_t grouping_size, bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    gpu_memory_allocated = allocate_gpu_memory;
    auto message_modulus = params.message_modulus;

    shifted_blocks_and_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), shifted_blocks_and_states,
        num_many_lut * num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    shifted_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), shifted_blocks,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    block_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), block_states, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    uint32_t num_luts_first_step = 2 * grouping_size + 1;

    luts_array_first_step = new int_radix_lut<Torus>(
        streams, params, num_luts_first_step, num_radix_blocks, num_many_lut,
        allocate_gpu_memory, size_tracker);

    auto f_shift_block = [message_modulus](Torus block) -> Torus {
      return (block % message_modulus) << 1;
    };

    auto f_first_block_state = [message_modulus](Torus block) -> Torus {
      if (block >= message_modulus)
        return OUTPUT_CARRY::GENERATED;
      else {
        return OUTPUT_CARRY::NONE;
      }
    };

    std::vector<std::vector<std::function<Torus(Torus)>>> luts_array_funcs;
    std::vector<uint32_t> lut_func_indexes;

    std::vector<std::function<Torus(Torus)>> f_first_grouping_luts = {
        f_first_block_state, f_shift_block};

    luts_array_funcs.push_back(f_first_grouping_luts);
    lut_func_indexes.push_back(0);

    // luts for other blocks of the first grouping
    for (int lut_id = 1; lut_id < grouping_size; lut_id++) {
      auto f_state = [message_modulus, lut_id](Torus block) -> Torus {
        uint64_t r = 0;
        if (block >= message_modulus) {
          r = 2; // Generates Carry
        } else if (block == (message_modulus - 1)) {
          r = 1; // Propagates a carry
        } else {
          r = 0; // Does not generate carry
        }
        return r << (lut_id - 1);
      };
      std::vector<std::function<Torus(Torus)>> f_grouping_luts = {
          f_state, f_shift_block};

      luts_array_funcs.push_back(f_grouping_luts);
      lut_func_indexes.push_back(lut_id);
    }

    // luts for the rest of groupings (except for the last block)
    for (int i = 0; i < grouping_size; i++) {
      uint32_t lut_id = i + grouping_size;
      auto f_state = [message_modulus, i](Torus block) -> Torus {
        uint64_t r = 0;
        if (block >= message_modulus) {
          r = 2; // Generates Carry
        } else if (block == (message_modulus - 1)) {
          r = 1; // Propagates a carry
        } else {
          r = 0; // Does not borrow
        }
        return r << i;
      };
      std::vector<std::function<Torus(Torus)>> f_grouping_luts = {
          f_state, f_shift_block};

      luts_array_funcs.push_back(f_grouping_luts);
      lut_func_indexes.push_back(lut_id);
    }

    // For the last block we need to generate a new lut
    auto f_last_block_state = [message_modulus](Torus block) -> Torus {
      if (block >= message_modulus)
        return 2 << 1; // Generates
      else
        return 0; // Nothing
    };

    uint32_t lut_id = num_luts_first_step - 1; // The last lut of the first step

    std::vector<std::function<Torus(Torus)>> f_last_grouping_luts = {
        f_last_block_state, f_shift_block};

    luts_array_funcs.push_back(f_last_grouping_luts);
    lut_func_indexes.push_back(lut_id);

    // Generate the indexes to switch between luts within the pbs
    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    auto lut_index_generator = [num_radix_blocks,
                                grouping_size](Torus *h_lut_indexes, uint32_t) {
      for (int index = 0; index < num_radix_blocks; index++) {
        uint32_t grouping_index = index / grouping_size;
        bool is_in_first_grouping = (grouping_index == 0);
        uint32_t index_in_grouping = index % grouping_size;
        bool is_last_index = (index == (num_radix_blocks - 1));
        if (is_last_index) {
          if (num_radix_blocks == 1) {
            h_lut_indexes[index] = 2 * grouping_size;
          } else {
            h_lut_indexes[index] = 2;
          }
        } else if (is_in_first_grouping) {
          h_lut_indexes[index] = index_in_grouping;
        } else {
          h_lut_indexes[index] = index_in_grouping + grouping_size;
        }
      }
    };

    luts_array_first_step->generate_and_broadcast_many_lut(
        active_streams, lut_func_indexes, luts_array_funcs,
        lut_index_generator);
  };
  void release(CudaStreams streams) {

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   shifted_blocks_and_states,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   shifted_blocks, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   block_states, gpu_memory_allocated);

    luts_array_first_step->release(streams);
    delete luts_array_first_step;
    delete shifted_blocks_and_states;
    delete shifted_blocks;
    delete block_states;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  };
};

// compute_propagation simulator and group carries
template <typename Torus> struct int_prop_simu_group_carries_memory {
  CudaRadixCiphertextFFI *propagation_cum_sums;
  CudaRadixCiphertextFFI *simulators;
  CudaRadixCiphertextFFI *prepared_blocks;
  CudaRadixCiphertextFFI *grouping_pgns;
  CudaRadixCiphertextFFI *resolved_carries;

  Torus *scalar_array_cum_sum;
  Torus *h_scalar_array_cum_sum;

  int_radix_lut<Torus> *luts_array_second_step;

  int_seq_group_prop_memory<Torus> *seq_group_prop_mem;
  int_hs_group_prop_memory<Torus> *hs_group_prop_mem;

  uint32_t group_size;
  bool use_sequential_algorithm_to_resolve_group_carries;
  bool gpu_memory_allocated;

  int_prop_simu_group_carries_memory(
      CudaStreams streams, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t grouping_size, uint32_t num_groups, bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    gpu_memory_allocated = allocate_gpu_memory;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    uint32_t block_modulus = message_modulus * carry_modulus;
    uint32_t num_bits_in_block = std::log2(block_modulus);

    group_size = grouping_size;

    propagation_cum_sums = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), propagation_cum_sums,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    simulators = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), simulators, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    prepared_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), prepared_blocks,
        num_radix_blocks + 1, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    resolved_carries = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), resolved_carries,
        num_groups + 1, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    grouping_pgns = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), grouping_pgns, num_groups,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    scalar_array_cum_sum = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    cuda_memset_with_size_tracking_async(
        scalar_array_cum_sum, 0, num_radix_blocks * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
    h_scalar_array_cum_sum = new Torus[num_radix_blocks]();

    // create lut objects for step 2
    uint64_t lut_indexes_size = num_radix_blocks * sizeof(Torus);
    uint32_t num_carry_to_resolve = num_groups - 1;
    uint32_t saturated_sub =
        ((num_carry_to_resolve > 1) ? num_carry_to_resolve - 1 : 0);
    uint32_t sequential_depth = saturated_sub / (grouping_size - 1);
    uint32_t hillis_steel_depth;

    if (num_carry_to_resolve == 0) {
      hillis_steel_depth = 0;
    } else {
      hillis_steel_depth = std::ceil(std::log2(num_carry_to_resolve));
    }

    use_sequential_algorithm_to_resolve_group_carries =
        sequential_depth <= hillis_steel_depth;
    uint32_t num_extra_luts = 0;
    if (use_sequential_algorithm_to_resolve_group_carries) {
      num_extra_luts = (grouping_size - 1);
    } else {
      num_extra_luts = 1;
    }

    for (int index = 0; index < num_radix_blocks; index++) {
      uint32_t grouping_index = index / grouping_size;
      bool is_in_first_grouping = (grouping_index == 0);
      uint32_t index_in_grouping = index % grouping_size;

      bool may_have_its_padding_bit_set =
          !is_in_first_grouping && (index_in_grouping == grouping_size - 1);

      if (may_have_its_padding_bit_set) {
        if (use_sequential_algorithm_to_resolve_group_carries) {
          h_scalar_array_cum_sum[index] =
              1 << ((grouping_index - 1) % (grouping_size - 1));
        } else {
          h_scalar_array_cum_sum[index] = 1;
        }
      } else {
        h_scalar_array_cum_sum[index] = 0;
      }
    }

    cuda_memcpy_with_size_tracking_async_to_gpu(
        scalar_array_cum_sum, h_scalar_array_cum_sum,
        num_radix_blocks * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);

    uint32_t num_luts_second_step = 2 * grouping_size + num_extra_luts;
    luts_array_second_step = new int_radix_lut<Torus>(
        streams, params, num_luts_second_step, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    auto use_sequential_algorithm =
        use_sequential_algorithm_to_resolve_group_carries;
    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    auto second_step_lut_index_generator =
        [num_radix_blocks, grouping_size,
         use_sequential_algorithm](Torus *h_buffer, uint32_t) {
          for (int index = 0; index < num_radix_blocks; index++) {
            uint32_t grouping_index = index / grouping_size;
            bool is_in_first_grouping = (grouping_index == 0);
            uint32_t index_in_grouping = index % grouping_size;

            if (is_in_first_grouping) {
              h_buffer[index] = index_in_grouping;
            } else if (index_in_grouping == (grouping_size - 1)) {
              if (use_sequential_algorithm) {
                int inner_index = (grouping_index - 1) % (grouping_size - 1);
                h_buffer[index] = inner_index + 2 * grouping_size;
              } else {
                h_buffer[index] = 2 * grouping_size;
              }
            } else {
              h_buffer[index] = index_in_grouping + grouping_size;
            }
          }
        };

    std::vector<std::function<Torus(Torus)>> lut_funcs;
    std::vector<uint32_t> lut_ids;

    // luts for first group inner propagation
    for (int lut_id = 0; lut_id < grouping_size - 1; lut_id++) {
      auto f_first_grouping_inner_propagation =
          [lut_id](Torus propa_cum_sum_block) -> Torus {
        uint64_t carry = (propa_cum_sum_block >> lut_id) & 1;

        if (carry != 0) {
          return 2ull; // Generates Carry
        } else {
          return 0ull; // Does not generate carry
        }
      };
      lut_funcs.push_back(f_first_grouping_inner_propagation);
      lut_ids.push_back(lut_id);
    }

    auto f_first_grouping_outer_propagation =
        [num_bits_in_block](Torus block) -> Torus {
      return (block >> (num_bits_in_block - 1)) & 1;
    };

    int lut_id = grouping_size - 1;

    lut_funcs.push_back(f_first_grouping_outer_propagation);
    lut_ids.push_back(lut_id);

    // for other groupings inner propagation
    for (int index = 0; index < grouping_size; index++) {
      uint32_t lut_id = index + grouping_size;

      auto f_other_groupings_inner_propagation =
          [index](Torus propa_cum_sum_block) -> Torus {
        uint64_t mask = (2 << index) - 1;
        if (propa_cum_sum_block >= (2 << index)) {
          return 2ull; // Generates
        } else if ((propa_cum_sum_block & mask) == mask) {
          return 1ull; // Propagate
        } else {
          return 0ull; // Nothing
        }
      };

      lut_funcs.push_back(f_other_groupings_inner_propagation);
      lut_ids.push_back(lut_id);
    }

    if (use_sequential_algorithm_to_resolve_group_carries) {
      for (int index = 0; index < grouping_size - 1; index++) {
        uint32_t lut_id = index + 2 * grouping_size;

        auto f_group_propagation = [index, block_modulus,
                                    num_bits_in_block](Torus block) -> Torus {
          if (block == (block_modulus - 1)) {
            return 0ull;
          } else {
            return ((UINT64_MAX << index) % (1ull << (num_bits_in_block + 1)));
          }
        };

        lut_funcs.push_back(f_group_propagation);
        lut_ids.push_back(lut_id);
      }
    } else {
      uint32_t lut_id = 2 * grouping_size;
      auto f_group_propagation = [block_modulus](Torus block) {
        if (block == (block_modulus - 1)) {
          return 2ull;
        } else {
          return UINT64_MAX % (block_modulus * 2ull);
        }
      };

      lut_funcs.push_back(f_group_propagation);
      lut_ids.push_back(lut_id);
    }

    Torus *h_second_lut_indexes = (Torus *)malloc(lut_indexes_size);

    luts_array_second_step->generate_and_broadcast_lut(
        active_streams, lut_ids, lut_funcs, second_step_lut_index_generator,
        true, {}, h_second_lut_indexes);

    if (use_sequential_algorithm_to_resolve_group_carries) {

      seq_group_prop_mem = new int_seq_group_prop_memory<Torus>(
          streams, params, grouping_size, big_lwe_size_bytes,
          allocate_gpu_memory, size_tracker);

    } else {
      hs_group_prop_mem = new int_hs_group_prop_memory<Torus>(
          streams, params, num_groups, big_lwe_size_bytes, allocate_gpu_memory,
          size_tracker);
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(h_second_lut_indexes);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(CudaStreams streams, Torus *new_lut_indexes,
                          Torus *new_scalars, uint32_t new_num_blocks) {
    auto new_active_streams = streams.active_gpu_subset(
        new_num_blocks, luts_array_second_step->params.pbs_type);
    luts_array_second_step->set_lut_indexes_and_broadcast_from_gpu(
        new_active_streams, new_lut_indexes, new_num_blocks);

    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        scalar_array_cum_sum, new_scalars, new_num_blocks * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), gpu_memory_allocated);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   propagation_cum_sums, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   simulators, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   grouping_pgns, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   prepared_blocks, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   resolved_carries, gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(scalar_array_cum_sum, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    luts_array_second_step->release(streams);

    if (use_sequential_algorithm_to_resolve_group_carries) {
      seq_group_prop_mem->release(streams);
      delete seq_group_prop_mem;
    } else {
      hs_group_prop_mem->release(streams);
      delete hs_group_prop_mem;
    }

    delete propagation_cum_sums;
    delete simulators;
    delete grouping_pgns;
    delete prepared_blocks;
    delete resolved_carries;
    delete luts_array_second_step;
    delete[] h_scalar_array_cum_sum;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  };
};

template <typename Torus> struct int_sc_prop_memory {
  uint32_t num_many_lut;
  uint32_t lut_stride;

  uint32_t num_groups;
  CudaRadixCiphertextFFI *output_flag;
  CudaRadixCiphertextFFI *last_lhs;
  CudaRadixCiphertextFFI *last_rhs;
  int_radix_lut<Torus> *lut_message_extract;

  int_radix_lut<Torus> *lut_overflow_flag_prep;

  int_shifted_blocks_and_states_memory<Torus> *shifted_blocks_state_mem;
  int_prop_simu_group_carries_memory<Torus> *prop_simu_group_carries_mem;

  int_radix_params params;
  uint32_t requested_flag;
  bool gpu_memory_allocated;

  int_sc_prop_memory(CudaStreams streams, int_radix_params params,
                     uint32_t num_radix_blocks, uint32_t requested_flag_in,
                     bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    requested_flag = requested_flag_in;
    // for compute shifted blocks and block states
    uint32_t block_modulus = message_modulus * carry_modulus;
    uint32_t num_bits_in_block = std::log2(block_modulus);
    uint32_t grouping_size = num_bits_in_block;
    num_groups = CEIL_DIV(num_radix_blocks, grouping_size);

    num_many_lut = 2; // many luts apply 2 luts
    uint32_t box_size = polynomial_size / block_modulus;
    lut_stride = (block_modulus / num_many_lut) * box_size;

    shifted_blocks_state_mem = new int_shifted_blocks_and_states_memory<Torus>(
        streams, params, num_radix_blocks, num_many_lut, grouping_size,
        allocate_gpu_memory, size_tracker);

    prop_simu_group_carries_mem = new int_prop_simu_group_carries_memory<Torus>(
        streams, params, num_radix_blocks, grouping_size, num_groups,
        allocate_gpu_memory, size_tracker);

    // This store a single block that with be used to store the overflow or
    // carry results
    output_flag = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output_flag,
        num_radix_blocks + 1, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    if (requested_flag == outputFlag::FLAG_OVERFLOW) {
      last_lhs = new CudaRadixCiphertextFFI;
      last_rhs = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), last_lhs, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), last_rhs, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      // For step 1 overflow should be enable only if flag overflow
      uint32_t num_bits_in_message = std::log2(message_modulus);
      lut_overflow_flag_prep = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);

      auto f_overflow_fp = [num_bits_in_message](Torus lhs,
                                                 Torus rhs) -> Torus {
        Torus mask = (1 << (num_bits_in_message - 1)) - 1;
        Torus lhs_except_last_bit = lhs & mask;
        Torus rhs_except_last_bit = rhs & mask;
        Torus input_carry1 = 1;
        Torus input_carry2 = 0;

        Torus output_carry1 =
            ((lhs + rhs + input_carry1) >> num_bits_in_message) & 1;
        Torus output_carry2 =
            ((lhs + rhs + input_carry2) >> num_bits_in_message) & 1;
        Torus input_carry_last_bit1 =
            ((lhs_except_last_bit + rhs_except_last_bit + input_carry1) >>
             (num_bits_in_message - 1)) &
            1;
        Torus input_carry_last_bit2 =
            ((lhs_except_last_bit + rhs_except_last_bit + input_carry2) >>
             (num_bits_in_message - 1)) &
            1;

        Torus output1 = (Torus)(input_carry_last_bit1 != output_carry1);
        Torus output2 = (Torus)(input_carry_last_bit2 != output_carry2);

        return output1 << 3 | output2 << 2;
      };

      auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
      lut_overflow_flag_prep->generate_and_broadcast_bivariate_lut(
          active_streams, {0}, {f_overflow_fp}, LUT_0_FOR_ALL_BLOCKS);
    }

    //  Step 3 elements
    int num_luts_message_extract =
        requested_flag == outputFlag::FLAG_NONE ? 1 : 2;
    lut_message_extract = new int_radix_lut<Torus>(
        streams, params, num_luts_message_extract, num_radix_blocks + 1,
        allocate_gpu_memory, size_tracker);
    // lut for the first block in the first grouping
    // this LUT is used on slot 0 for all values of outputFlag
    auto f_message_extract = [message_modulus](Torus block) -> Torus {
      return (block >> 1) % message_modulus;
    };

    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks + 1, params.pbs_type);

    // For the final cleanup in case of overflow or carry (it seems that I can)
    // It seems that this lut could be apply together with the other one but for
    // now we won't do it
    switch (requested_flag) {
    case outputFlag::FLAG_NONE:
      // In this case a single LUT is generated with the message extract
      // function
      lut_message_extract->generate_and_broadcast_lut(
          active_streams, {0}, {f_message_extract}, LUT_0_FOR_ALL_BLOCKS);
      break;
    case outputFlag::FLAG_OVERFLOW: {
      // Overflow case, an additional LUT is generated in additional to the
      // message extract one
      auto f_overflow_last = [num_radix_blocks,
                              requested_flag_in](Torus block) -> Torus {
        uint32_t position = (num_radix_blocks == 1 &&
                             requested_flag_in == outputFlag::FLAG_OVERFLOW)
                                ? 0
                                : 1;
        Torus input_carry = (block >> position) & 1;
        Torus does_overflow_if_carry_is_1 = (block >> 3) & 1;
        Torus does_overflow_if_carry_is_0 = (block >> 2) & 1;
        if (input_carry == outputFlag::FLAG_OVERFLOW) {
          return does_overflow_if_carry_is_1;
        }
        return does_overflow_if_carry_is_0;
      };

      // Index generator: all blocks use LUT 0 except the last which uses LUT 1
      auto index_gen = [num_radix_blocks](Torus *h_lut_indexes, uint32_t) {
        for (uint32_t i = 0; i < num_radix_blocks; i++) {
          h_lut_indexes[i] = 0;
        }
        h_lut_indexes[num_radix_blocks] = 1;
      };

      lut_message_extract->generate_and_broadcast_lut(
          active_streams, {0, 1}, {f_message_extract, f_overflow_last},
          index_gen);
      break;
    }
    case outputFlag::FLAG_CARRY: {
      // Carry case, an additional LUT is generated in additional to the message
      // extract one

      auto f_carry_last = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };

      // Index generator: all blocks use LUT 0 except the last which uses LUT 1
      auto index_gen = [num_radix_blocks](Torus *h_lut_indexes, uint32_t) {
        for (uint32_t i = 0; i < num_radix_blocks; i++) {
          h_lut_indexes[i] = 0;
        }
        h_lut_indexes[num_radix_blocks] = 1;
      };

      lut_message_extract->generate_and_broadcast_lut(
          active_streams, {0, 1}, {f_message_extract, f_carry_last}, index_gen);
      break;
    }
    default:
      PANIC("Invalid output flag in int_sc_prop_memory");
    }
  }

  void release(CudaStreams streams) {

    shifted_blocks_state_mem->release(streams);
    prop_simu_group_carries_mem->release(streams);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   output_flag, gpu_memory_allocated);
    lut_message_extract->release(streams);
    delete shifted_blocks_state_mem;
    delete prop_simu_group_carries_mem;
    delete output_flag;
    delete lut_message_extract;

    if (requested_flag == outputFlag::FLAG_OVERFLOW) { // In case of overflow
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     last_lhs, gpu_memory_allocated);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     last_rhs, gpu_memory_allocated);
      lut_overflow_flag_prep->release(streams);
      delete lut_overflow_flag_prep;
      delete last_lhs;
      delete last_rhs;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  };
};

template <typename Torus> struct int_shifted_blocks_and_borrow_states_memory {
  CudaRadixCiphertextFFI *shifted_blocks_and_borrow_states;
  CudaRadixCiphertextFFI *shifted_blocks;
  CudaRadixCiphertextFFI *borrow_states;

  int_radix_lut<Torus> *luts_array_first_step;
  bool gpu_memory_allocated;

  int_shifted_blocks_and_borrow_states_memory(
      CudaStreams streams, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t num_many_lut, uint32_t grouping_size, bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    gpu_memory_allocated = allocate_gpu_memory;
    auto message_modulus = params.message_modulus;

    shifted_blocks_and_borrow_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        shifted_blocks_and_borrow_states, num_radix_blocks * num_many_lut,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    shifted_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), shifted_blocks,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    borrow_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), borrow_states,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint32_t num_luts_first_step = 2 * grouping_size + 1;

    luts_array_first_step = new int_radix_lut<Torus>(
        streams, params, num_luts_first_step, num_radix_blocks, num_many_lut,
        allocate_gpu_memory, size_tracker);

    std::vector<std::vector<std::function<Torus(Torus)>>> luts_array_funcs;
    std::vector<uint32_t> lut_func_indexes;

    auto f_shift_block = [message_modulus](Torus block) -> Torus {
      uint64_t overflow_guard = message_modulus;
      uint64_t block_mod = block % message_modulus;
      return (overflow_guard | block_mod) << 1;
    };

    auto f_first_block_state = [message_modulus](Torus block) -> Torus {
      if (block < message_modulus)
        return 1; // Borrows
      else {
        return 0; // Nothing
      }
    };
    std::vector<std::function<Torus(Torus)>> f_first_grouping_luts = {
        f_first_block_state, f_shift_block};

    luts_array_funcs.push_back(f_first_grouping_luts);
    lut_func_indexes.push_back(0);

    // luts for other blocks of the first grouping
    for (int lut_id = 1; lut_id < grouping_size; lut_id++) {
      auto f_state = [message_modulus, lut_id](Torus block) -> Torus {
        uint64_t r = 0;
        if (block < message_modulus) {
          r = 2; // Borrows
        } else if (block == message_modulus) {
          r = 1; // Propagates a borrow
        } else {
          r = 0; // Does not borrow
        }
        return r << (lut_id - 1);
      };
      std::vector<std::function<Torus(Torus)>> f_grouping_luts = {
          f_state, f_shift_block};

      luts_array_funcs.push_back(f_grouping_luts);
      lut_func_indexes.push_back(lut_id);
    }

    // luts for the rest of groupings (except for the last block)
    for (int i = 0; i < grouping_size; i++) {
      uint32_t lut_id = i + grouping_size;
      auto f_state = [message_modulus, i](Torus block) -> Torus {
        uint64_t r = 0;
        if (block < message_modulus) {
          r = 2; // Generates borrow
        } else if (block == message_modulus) {
          r = 1; // Propagates a borrow
        } else {
          r = 0; // Does not borrow
        }
        return r << i;
      };
      std::vector<std::function<Torus(Torus)>> f_grouping_luts = {
          f_state, f_shift_block};

      luts_array_funcs.push_back(f_grouping_luts);
      lut_func_indexes.push_back(lut_id);
    }

    auto f_last_block_state = [message_modulus](Torus block) -> Torus {
      if (block < message_modulus)
        return 2 << 1; // Generates a borrow
      else
        return 0; // Nothing
    };

    uint32_t lut_id = num_luts_first_step - 1; // The last lut of the first step

    std::vector<std::function<Torus(Torus)>> f_last_grouping_luts = {
        f_last_block_state, f_shift_block};

    luts_array_funcs.push_back(f_last_grouping_luts);
    lut_func_indexes.push_back(lut_id);

    // Generate the indexes to switch between luts within the pbs
    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    auto lut_index_generator = [num_radix_blocks,
                                grouping_size](Torus *h_lut_indexes, uint32_t) {
      for (int index = 0; index < num_radix_blocks; index++) {
        uint32_t grouping_index = index / grouping_size;
        bool is_in_first_grouping = (grouping_index == 0);
        uint32_t index_in_grouping = index % grouping_size;
        bool is_last_index = (index == (num_radix_blocks - 1));
        if (is_last_index) {
          if (num_radix_blocks == 1) {
            h_lut_indexes[index] = 2 * grouping_size;
          } else {
            h_lut_indexes[index] = 2;
          }
        } else if (is_in_first_grouping) {
          h_lut_indexes[index] = index_in_grouping;
        } else {
          h_lut_indexes[index] = index_in_grouping + grouping_size;
        }
      }
    };
    luts_array_first_step->generate_and_broadcast_many_lut(
        active_streams, lut_func_indexes, luts_array_funcs,
        lut_index_generator);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(CudaStreams streams, Torus *new_lut_indexes,
                          uint32_t new_num_blocks) {
    auto new_active_streams = streams.active_gpu_subset(
        new_num_blocks, luts_array_first_step->params.pbs_type);
    luts_array_first_step->set_lut_indexes_and_broadcast_from_gpu(
        new_active_streams, new_lut_indexes, new_num_blocks);
  }
  void release(CudaStreams streams) {

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   shifted_blocks_and_borrow_states,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   shifted_blocks, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   borrow_states, gpu_memory_allocated);

    luts_array_first_step->release(streams);
    delete luts_array_first_step;
    delete shifted_blocks_and_borrow_states;
    delete shifted_blocks;
    delete borrow_states;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  };
};

template <typename Torus> struct int_borrow_prop_memory {
  uint32_t num_many_lut;
  uint32_t lut_stride;

  uint32_t group_size;
  uint32_t num_groups;
  CudaRadixCiphertextFFI *overflow_block;

  int_radix_lut<Torus> *lut_message_extract;
  int_radix_lut<Torus> *lut_borrow_flag;

  int_shifted_blocks_and_borrow_states_memory<Torus>
      *shifted_blocks_borrow_state_mem;
  int_prop_simu_group_carries_memory<Torus> *prop_simu_group_carries_mem;

  int_radix_params params;

  CudaStreams active_streams;
  InternalCudaStreams internal_streams;

  uint32_t compute_overflow;
  bool gpu_memory_allocated;
  int_borrow_prop_memory(CudaStreams streams, int_radix_params params,
                         uint32_t num_radix_blocks,
                         uint32_t compute_overflow_in, bool allocate_gpu_memory,
                         uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    compute_overflow = compute_overflow_in;
    // for compute shifted blocks and block states
    uint32_t block_modulus = message_modulus * carry_modulus;
    uint32_t num_bits_in_block = std::log2(block_modulus);
    uint32_t grouping_size = num_bits_in_block;
    group_size = grouping_size;
    num_groups = CEIL_DIV(num_radix_blocks, grouping_size);

    num_many_lut = 2; // many luts apply 2 luts
    uint32_t box_size = polynomial_size / block_modulus;
    lut_stride = (block_modulus / num_many_lut) * box_size;

    shifted_blocks_borrow_state_mem =
        new int_shifted_blocks_and_borrow_states_memory<Torus>(
            streams, params, num_radix_blocks, num_many_lut, grouping_size,
            allocate_gpu_memory, size_tracker);

    prop_simu_group_carries_mem = new int_prop_simu_group_carries_memory<Torus>(
        streams, params, num_radix_blocks, grouping_size, num_groups,
        allocate_gpu_memory, size_tracker);

    overflow_block = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), overflow_block, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    lut_message_extract =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);
    // lut for the first block in the first grouping
    auto f_message_extract = [message_modulus](Torus block) -> Torus {
      return (block >> 1) % message_modulus;
    };

    active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);

    lut_message_extract->generate_and_broadcast_lut(
        active_streams, {0}, {f_message_extract}, LUT_0_FOR_ALL_BLOCKS);

    if (compute_overflow) {
      lut_borrow_flag =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);
      // lut for the first block in the first grouping
      auto f_borrow_flag = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };

      lut_borrow_flag->generate_and_broadcast_lut(
          active_streams, {0}, {f_borrow_flag}, LUT_0_FOR_ALL_BLOCKS);
    }

    active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    internal_streams.create_internal_cuda_streams_on_same_gpus(active_streams,
                                                               2);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(CudaStreams streams, Torus *first_indexes_for_div,
                          Torus *second_indexes_for_div, Torus *scalars_for_div,
                          uint32_t new_num_blocks) {
    shifted_blocks_borrow_state_mem->update_lut_indexes(
        streams, first_indexes_for_div, new_num_blocks);
    prop_simu_group_carries_mem->update_lut_indexes(
        streams, second_indexes_for_div, scalars_for_div, new_num_blocks);
  }
  void release(CudaStreams streams) {

    shifted_blocks_borrow_state_mem->release(streams);
    delete shifted_blocks_borrow_state_mem;
    prop_simu_group_carries_mem->release(streams);
    delete prop_simu_group_carries_mem;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   overflow_block, gpu_memory_allocated);

    lut_message_extract->release(streams);
    delete lut_message_extract;
    delete overflow_block;
    if (compute_overflow) {
      lut_borrow_flag->release(streams);
      delete lut_borrow_flag;
    }

    internal_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  };
};
std::pair<bool, bool> get_invert_flags(COMPARISON_TYPE compare);
void reverseArray(uint64_t arr[], size_t n);
#endif // CUDA_INTEGER_UTILITIES_H
