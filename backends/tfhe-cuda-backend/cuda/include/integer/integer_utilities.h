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
#include <queue>

#include <stdio.h>

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
        PANIC("Cuda error: noise exceeds maximum authorized value for 2_2 "    \
              "parameters");                                                   \
    } else if ((msg_mod) == 8 && (carry_mod) == 8) {                           \
      constexpr int max_noise_level = 9;                                       \
      if ((noise_level_expr) > max_noise_level)                                \
        PANIC("Cuda error: noise exceeds maximum authorized value for 3_3 "    \
              "parameters");                                                   \
    } else if ((msg_mod) == 0 && (carry_mod) == 0) {                           \
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
    uint32_t polynomial_size, std::function<Torus(uint32_t)> f,
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
  std::vector<InputTorus *> lwe_aligned_vec;

  bool gpu_memory_allocated;

  CudaStreamsBarrier multi_gpu_scatter_barrier, multi_gpu_broadcast_barrier;
  CudaStreamsBarrier multi_gpu_gather_barrier;

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

    this->active_streams = streams.active_gpu_subset(num_radix_blocks);
  }

  void setup_degrees() {
    this->degrees =
        (uint64_t *)malloc(num_many_lut * num_luts * sizeof(uint64_t));
    this->max_degrees = (uint64_t *)malloc(num_luts * sizeof(uint64_t));
  }

  void allocate_pbs_buffers(int_radix_params params, uint32_t num_radix_blocks,
                            bool allocate_gpu_memory, uint64_t &size_tracker) {
    for (uint i = 0; i < active_streams.count(); i++) {
      cuda_set_device(active_streams.gpu_index(i));
      int8_t *gpu_pbs_buffer;
      auto num_blocks_on_gpu = std::max(
          THRESHOLD_MULTI_GPU,
          get_num_inputs_on_gpu(num_radix_blocks, i, active_streams.count()));

      uint64_t size = 0;
      execute_scratch_pbs<OutputTorus>(
          active_streams.stream(i), active_streams.gpu_index(i),
          &gpu_pbs_buffer, params.glwe_dimension, params.small_lwe_dimension,
          params.polynomial_size, params.pbs_level, params.grouping_factor,
          num_blocks_on_gpu, params.pbs_type, allocate_gpu_memory,
          params.noise_reduction_type, size);
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
                              size_tracker, allocate_gpu_memory);
    multi_gpu_alloc_lwe_async(active_streams, lwe_after_ks_vec,
                              num_radix_blocks, params.small_lwe_dimension + 1,
                              size_tracker, allocate_gpu_memory);
    if (num_many_lut > 1) {
      multi_gpu_alloc_lwe_many_lut_output_async(
          active_streams, lwe_after_pbs_vec, num_radix_blocks, num_many_lut,
          params.big_lwe_dimension + 1, size_tracker, allocate_gpu_memory);
    } else {
      multi_gpu_alloc_lwe_async(active_streams, lwe_after_pbs_vec,
                                num_radix_blocks, params.big_lwe_dimension + 1,
                                size_tracker, allocate_gpu_memory);
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

  // Broadcast luts from device gpu_indexes[0] to all active gpus
  void broadcast_lut(CudaStreams new_active_streams,
                     bool broadcast_lut_values = true) {
    PANIC_IF_FALSE(new_active_streams.gpu_index(0) ==
                       active_streams.gpu_index(0),
                   "Broadcasting LUTs can only be done using the same GPUs "
                   " originally assigned to the int_radix_lut");

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
    // We need to create the auxiliary array only in GPU 0
    if (active_streams.count() > 1) {
      lwe_aligned_vec.resize(active_streams.count());
      for (uint i = 0; i < active_streams.count(); i++) {
        uint64_t size_tracker_on_array_i = 0;
        auto inputs_on_gpu = std::max(
            THRESHOLD_MULTI_GPU, get_num_inputs_on_gpu(max_num_radix_blocks, i,
                                                       active_streams.count()));
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

    generate_device_accumulator<__uint128_t>(
        this->active_streams.stream(0), this->active_streams.gpu_index(0),
        this->get_lut(0, 0), this->get_degree(0), this->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, f_squash, allocate_gpu_memory);

    this->broadcast_lut(this->active_streams);
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

    for (int i = 0; i < bits_per_block; i++) {

      auto operator_f = [i, final_offset](Torus x) -> Torus {
        Torus y = (x >> i) & 1;
        return y << final_offset;
      };

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), lut->get_lut(0, i),
          lut->get_degree(i), lut->get_max_degree(i), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          operator_f, gpu_memory_allocated);
    }

    /**
     * we have bits_per_blocks LUTs that should be used for all bits in all
     * blocks
     */
    Torus *h_lut_indexes = lut->h_lut_indexes;
    for (int j = 0; j < num_radix_blocks; j++) {
      for (int i = 0; i < bits_per_block; i++)
        h_lut_indexes[i + j * bits_per_block] = i;
    }
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lut->get_lut_indexes(0, 0), h_lut_indexes,
        num_radix_blocks * bits_per_block * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);

    auto active_streams =
        streams.active_gpu_subset(bits_per_block * num_radix_blocks);
    lut->broadcast_lut(active_streams);

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
    Torus *lut_buffer_message = lut->get_lut(0, 0);
    uint64_t *message_degree = lut->get_degree(0);
    uint64_t *message_max_degree = lut->get_max_degree(0);
    Torus *lut_buffer_carry = lut->get_lut(0, 1);
    uint64_t *carry_degree = lut->get_degree(1);
    uint64_t *carry_max_degree = lut->get_max_degree(1);

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), lut_buffer_message,
        message_degree, message_max_degree, params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        lut_f_message, gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), lut_buffer_carry, carry_degree,
        carry_max_degree, params.glwe_dimension, params.polynomial_size,
        params.message_modulus, params.carry_modulus, lut_f_carry,
        gpu_memory_allocated);

    uint64_t lwe_indexes_size = 2 * sizeof(Torus);
    Torus *h_lwe_indexes = (Torus *)malloc(lwe_indexes_size);
    for (int i = 0; i < 2; i++)
      h_lwe_indexes[i] = i;
    Torus *lwe_indexes = lut->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes, h_lwe_indexes, lwe_indexes_size, streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);
    auto active_streams = streams.active_gpu_subset(2);
    lut->broadcast_lut(active_streams);

    tmp_small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_small_lwe_vector, 2,
        params.small_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_big_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_big_lwe_vector, 2,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(h_lwe_indexes);
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
        luts_message_carry = new int_radix_lut<Torus>(
            streams, params, 2, pbs_count, true, size_tracker);
        allocated_luts_message_carry = true;
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
      auto message_acc = luts_message_carry->get_lut(0, 0);
      auto carry_acc = luts_message_carry->get_lut(0, 1);

      // define functions for each accumulator
      auto lut_f_message = [message_modulus](Torus x) -> Torus {
        return x % message_modulus;
      };
      auto lut_f_carry = [message_modulus](Torus x) -> Torus {
        return x / message_modulus;
      };

      // generate accumulators
      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), message_acc,
          luts_message_carry->get_degree(0),
          luts_message_carry->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, message_modulus, params.carry_modulus,
          lut_f_message, gpu_memory_allocated);
      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), carry_acc,
          luts_message_carry->get_degree(1),
          luts_message_carry->get_max_degree(1), params.glwe_dimension,
          params.polynomial_size, message_modulus, params.carry_modulus,
          lut_f_carry, gpu_memory_allocated);
      auto active_gpu_count_mc = streams.active_gpu_subset(pbs_count);
      luts_message_carry->broadcast_lut(active_gpu_count_mc);
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
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    grouping_size = group_size;
    group_resolved_carries = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), group_resolved_carries,
        grouping_size, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    int num_seq_luts = grouping_size - 1;
    Torus *h_seq_lut_indexes = (Torus *)malloc(num_seq_luts * sizeof(Torus));
    lut_sequential_algorithm =
        new int_radix_lut<Torus>(streams, params, num_seq_luts, num_seq_luts,
                                 allocate_gpu_memory, size_tracker);
    for (int index = 0; index < num_seq_luts; index++) {
      auto f_lut_sequential = [index](Torus propa_cum_sum_block) {
        return (propa_cum_sum_block >> (index + 1)) & 1;
      };
      auto seq_lut = lut_sequential_algorithm->get_lut(0, index);
      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), seq_lut,
          lut_sequential_algorithm->get_degree(index),
          lut_sequential_algorithm->get_max_degree(index), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_lut_sequential,
          gpu_memory_allocated);
      h_seq_lut_indexes[index] = index;
    }
    Torus *seq_lut_indexes = lut_sequential_algorithm->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        seq_lut_indexes, h_seq_lut_indexes, num_seq_luts * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
    auto active_streams = streams.active_gpu_subset(num_seq_luts);
    lut_sequential_algorithm->broadcast_lut(active_streams);
    free(h_seq_lut_indexes);
  };
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
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

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

    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0),
        lut_hillis_steele->get_lut(0, 0), lut_hillis_steele->get_degree(0),
        lut_hillis_steele->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_lut_hillis_steele,
        gpu_memory_allocated);
    auto active_streams = streams.active_gpu_subset(num_groups);
    lut_hillis_steele->broadcast_lut(active_streams);
  };
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
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

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
    std::vector<std::function<Torus(Torus)>> f_first_grouping_luts = {
        f_first_block_state, f_shift_block};

    auto first_block_lut = luts_array_first_step->get_lut(0, 0);
    auto first_block_lut_degrees = luts_array_first_step->get_degree(0);
    auto first_block_lut_max_degree = luts_array_first_step->get_max_degree(0);
    generate_many_lut_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), first_block_lut,
        first_block_lut_degrees, first_block_lut_max_degree, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_first_grouping_luts,
        gpu_memory_allocated);

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
      auto lut = luts_array_first_step->get_lut(0, lut_id);
      auto lut_degrees = luts_array_first_step->get_degree(lut_id);
      auto lut_max_degree = luts_array_first_step->get_max_degree(lut_id);
      generate_many_lut_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), lut, lut_degrees,
          lut_max_degree, glwe_dimension, polynomial_size, message_modulus,
          carry_modulus, f_grouping_luts, gpu_memory_allocated);
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

      auto lut = luts_array_first_step->get_lut(0, lut_id);
      auto lut_degrees = luts_array_first_step->get_degree(lut_id);
      auto lut_max_degree = luts_array_first_step->get_max_degree(lut_id);
      generate_many_lut_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), lut, lut_degrees,
          lut_max_degree, glwe_dimension, polynomial_size, message_modulus,
          carry_modulus, f_grouping_luts, gpu_memory_allocated);
    }

    // For the last block we need to generate a new lut
    auto f_last_block_state = [message_modulus](Torus block) -> Torus {
      if (block >= message_modulus)
        return 2 << 1; // Generates
      else
        return 0; // Nothing
    };

    uint32_t lut_id = num_luts_first_step - 1; // The last lut of the first step

    auto last_block_lut = luts_array_first_step->get_lut(0, lut_id);
    auto last_block_lut_degrees = luts_array_first_step->get_degree(lut_id);
    auto last_block_lut_max_degree =
        luts_array_first_step->get_max_degree(lut_id);

    std::vector<std::function<Torus(Torus)>> f_last_grouping_luts = {
        f_last_block_state, f_shift_block};

    generate_many_lut_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), last_block_lut,
        last_block_lut_degrees, last_block_lut_max_degree, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_last_grouping_luts,
        gpu_memory_allocated);

    // Generate the indexes to switch between luts within the pbs
    uint64_t lut_indexes_size = num_radix_blocks * sizeof(Torus);

    Torus *h_lut_indexes = luts_array_first_step->h_lut_indexes;
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

    // copy the indexes to the gpu
    Torus *lut_indexes = luts_array_first_step->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lut_indexes, h_lut_indexes, lut_indexes_size, streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);
    // Do I need to do something else for the multi-gpu?
    auto active_streams = streams.active_gpu_subset(num_radix_blocks);
    luts_array_first_step->broadcast_lut(active_streams);
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

    uint32_t num_luts_second_step = 2 * grouping_size + num_extra_luts;
    luts_array_second_step = new int_radix_lut<Torus>(
        streams, params, num_luts_second_step, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

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

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          luts_array_second_step->get_lut(0, lut_id),
          luts_array_second_step->get_degree(lut_id),
          luts_array_second_step->get_max_degree(lut_id), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus,
          f_first_grouping_inner_propagation, gpu_memory_allocated);
    }

    auto f_first_grouping_outer_propagation =
        [num_bits_in_block](Torus block) -> Torus {
      return (block >> (num_bits_in_block - 1)) & 1;
    };

    int lut_id = grouping_size - 1;
    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        luts_array_second_step->get_lut(0, lut_id),
        luts_array_second_step->get_degree(lut_id),
        luts_array_second_step->get_max_degree(lut_id), glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_first_grouping_outer_propagation, gpu_memory_allocated);

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

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          luts_array_second_step->get_lut(0, lut_id),
          luts_array_second_step->get_degree(lut_id),
          luts_array_second_step->get_max_degree(lut_id), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus,
          f_other_groupings_inner_propagation, gpu_memory_allocated);
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

        generate_device_accumulator<Torus>(
            streams.stream(0), streams.gpu_index(0),
            luts_array_second_step->get_lut(0, lut_id),
            luts_array_second_step->get_degree(lut_id),
            luts_array_second_step->get_max_degree(lut_id), glwe_dimension,
            polynomial_size, message_modulus, carry_modulus,
            f_group_propagation, gpu_memory_allocated);
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

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          luts_array_second_step->get_lut(0, lut_id),
          luts_array_second_step->get_degree(lut_id),
          luts_array_second_step->get_max_degree(lut_id), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_group_propagation,
          gpu_memory_allocated);
    }

    Torus *h_second_lut_indexes = (Torus *)malloc(lut_indexes_size);

    for (int index = 0; index < num_radix_blocks; index++) {
      uint32_t grouping_index = index / grouping_size;
      bool is_in_first_grouping = (grouping_index == 0);
      uint32_t index_in_grouping = index % grouping_size;

      if (is_in_first_grouping) {
        h_second_lut_indexes[index] = index_in_grouping;
      } else if (index_in_grouping == (grouping_size - 1)) {
        if (use_sequential_algorithm_to_resolve_group_carries) {
          int inner_index = (grouping_index - 1) % (grouping_size - 1);
          h_second_lut_indexes[index] = inner_index + 2 * grouping_size;
        } else {
          h_second_lut_indexes[index] = 2 * grouping_size;
        }
      } else {
        h_second_lut_indexes[index] = index_in_grouping + grouping_size;
      }

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

    // copy the indexes to the gpu
    Torus *second_lut_indexes = luts_array_second_step->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        second_lut_indexes, h_second_lut_indexes, lut_indexes_size,
        streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);

    cuda_memcpy_with_size_tracking_async_to_gpu(
        scalar_array_cum_sum, h_scalar_array_cum_sum,
        num_radix_blocks * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);
    auto active_streams = streams.active_gpu_subset(num_radix_blocks);
    luts_array_second_step->broadcast_lut(active_streams);

    if (use_sequential_algorithm_to_resolve_group_carries) {

      seq_group_prop_mem = new int_seq_group_prop_memory<Torus>(
          streams, params, grouping_size, big_lwe_size_bytes,
          allocate_gpu_memory, size_tracker);

    } else {
      hs_group_prop_mem = new int_hs_group_prop_memory<Torus>(
          streams, params, num_groups, big_lwe_size_bytes, allocate_gpu_memory,
          size_tracker);
    }

    free(h_second_lut_indexes);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(CudaStreams streams, Torus *new_lut_indexes,
                          Torus *new_scalars, uint32_t new_num_blocks) {
    Torus *lut_indexes = luts_array_second_step->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        lut_indexes, new_lut_indexes, new_num_blocks * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), gpu_memory_allocated);
    auto new_active_streams = streams.active_gpu_subset(new_num_blocks);
    // We just need to update the lut indexes so we use false here
    luts_array_second_step->broadcast_lut(new_active_streams, false);

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
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    requested_flag = requested_flag_in;
    // for compute shifted blocks and block states
    uint32_t block_modulus = message_modulus * carry_modulus;
    uint32_t num_bits_in_block = std::log2(block_modulus);
    uint32_t grouping_size = num_bits_in_block;
    num_groups = (num_radix_blocks + grouping_size - 1) / grouping_size;

    num_many_lut = 2; // many luts apply 2 luts
    uint32_t box_size = polynomial_size / block_modulus;
    lut_stride = (block_modulus / num_many_lut) * box_size;

    shifted_blocks_state_mem = new int_shifted_blocks_and_states_memory<Torus>(
        streams, params, num_radix_blocks, num_many_lut, grouping_size,
        allocate_gpu_memory, size_tracker);

    prop_simu_group_carries_mem = new int_prop_simu_group_carries_memory<Torus>(
        streams, params, num_radix_blocks, grouping_size, num_groups,
        allocate_gpu_memory, size_tracker);

    //  Step 3 elements
    int num_luts_message_extract =
        requested_flag == outputFlag::FLAG_NONE ? 1 : 2;
    lut_message_extract = new int_radix_lut<Torus>(
        streams, params, num_luts_message_extract, num_radix_blocks + 1,
        allocate_gpu_memory, size_tracker);
    // lut for the first block in the first grouping
    auto f_message_extract = [message_modulus](Torus block) -> Torus {
      return (block >> 1) % message_modulus;
    };

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        lut_message_extract->get_lut(0, 0), lut_message_extract->get_degree(0),
        lut_message_extract->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_message_extract,
        gpu_memory_allocated);

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

      generate_device_accumulator_bivariate<Torus>(
          streams.stream(0), streams.gpu_index(0),
          lut_overflow_flag_prep->get_lut(0, 0),
          lut_overflow_flag_prep->get_degree(0),
          lut_overflow_flag_prep->get_max_degree(0), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_overflow_fp,
          gpu_memory_allocated);

      auto active_streams = streams.active_gpu_subset(1);
      lut_overflow_flag_prep->broadcast_lut(active_streams);
    }

    // For the final cleanup in case of overflow or carry (it seems that I can)
    // It seems that this lut could be apply together with the other one but for
    // now we won't do it
    if (requested_flag == outputFlag::FLAG_OVERFLOW) { // Overflow case
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
        } else {
          return does_overflow_if_carry_is_0;
        }
      };

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          lut_message_extract->get_lut(0, 1),
          lut_message_extract->get_degree(1),
          lut_message_extract->get_max_degree(1), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_overflow_last,
          gpu_memory_allocated);

      Torus *h_lut_indexes = lut_message_extract->h_lut_indexes;
      for (int index = 0; index < num_radix_blocks + 1; index++) {
        if (index < num_radix_blocks) {
          h_lut_indexes[index] = 0;
        } else {
          h_lut_indexes[index] = 1;
        }
      }
      cuda_memcpy_with_size_tracking_async_to_gpu(
          lut_message_extract->get_lut_indexes(0, 0), h_lut_indexes,
          (num_radix_blocks + 1) * sizeof(Torus), streams.stream(0),
          streams.gpu_index(0), allocate_gpu_memory);
    }
    if (requested_flag == outputFlag::FLAG_CARRY) { // Carry case

      auto f_carry_last = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          lut_message_extract->get_lut(0, 1),
          lut_message_extract->get_degree(1),
          lut_message_extract->get_max_degree(1), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_carry_last,
          gpu_memory_allocated);

      Torus *h_lut_indexes = lut_message_extract->h_lut_indexes;
      for (int index = 0; index < num_radix_blocks + 1; index++) {
        if (index < num_radix_blocks) {
          h_lut_indexes[index] = 0;
        } else {
          h_lut_indexes[index] = 1;
        }
      }
      cuda_memcpy_with_size_tracking_async_to_gpu(
          lut_message_extract->get_lut_indexes(0, 0), h_lut_indexes,
          (num_radix_blocks + 1) * sizeof(Torus), streams.stream(0),
          streams.gpu_index(0), allocate_gpu_memory);
    }
    auto active_streams = streams.active_gpu_subset(num_radix_blocks + 1);
    lut_message_extract->broadcast_lut(active_streams);
  };

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
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

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

    auto first_block_lut = luts_array_first_step->get_lut(0, 0);
    auto first_block_lut_degrees = luts_array_first_step->get_degree(0);
    auto first_block_lut_max_degree = luts_array_first_step->get_max_degree(0);

    generate_many_lut_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), first_block_lut,
        first_block_lut_degrees, first_block_lut_max_degree, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_first_grouping_luts,
        gpu_memory_allocated);

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
      auto lut = luts_array_first_step->get_lut(0, lut_id);
      auto lut_degrees = luts_array_first_step->get_degree(lut_id);
      auto lut_max_degree = luts_array_first_step->get_max_degree(lut_id);
      generate_many_lut_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), lut, lut_degrees,
          lut_max_degree, glwe_dimension, polynomial_size, message_modulus,
          carry_modulus, f_grouping_luts, gpu_memory_allocated);
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

      auto lut = luts_array_first_step->get_lut(0, lut_id);
      auto lut_degrees = luts_array_first_step->get_degree(lut_id);
      auto lut_max_degree = luts_array_first_step->get_max_degree(lut_id);
      generate_many_lut_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), lut, lut_degrees,
          lut_max_degree, glwe_dimension, polynomial_size, message_modulus,
          carry_modulus, f_grouping_luts, gpu_memory_allocated);
    }

    auto f_last_block_state = [message_modulus](Torus block) -> Torus {
      if (block < message_modulus)
        return 2 << 1; // Generates a borrow
      else
        return 0; // Nothing
    };

    uint32_t lut_id = num_luts_first_step - 1; // The last lut of the first step

    auto last_block_lut = luts_array_first_step->get_lut(0, lut_id);
    auto last_block_lut_degrees = luts_array_first_step->get_degree(lut_id);
    auto last_block_lut_max_degree =
        luts_array_first_step->get_max_degree(lut_id);

    std::vector<std::function<Torus(Torus)>> f_last_grouping_luts = {
        f_last_block_state, f_shift_block};

    generate_many_lut_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), last_block_lut,
        last_block_lut_degrees, last_block_lut_max_degree, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_last_grouping_luts,
        gpu_memory_allocated);

    // Generate the indexes to switch between luts within the pbs
    uint64_t lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus *h_lut_indexes = luts_array_first_step->h_lut_indexes;

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
    // copy the indexes to the gpu
    Torus *lut_indexes = luts_array_first_step->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lut_indexes, h_lut_indexes, lut_indexes_size, streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);
    // Do I need to do something else for the multi-gpu?
    auto active_streams = streams.active_gpu_subset(num_radix_blocks);
    luts_array_first_step->broadcast_lut(active_streams);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(CudaStreams streams, Torus *new_lut_indexes,
                          uint32_t new_num_blocks) {
    Torus *lut_indexes = luts_array_first_step->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        lut_indexes, new_lut_indexes, new_num_blocks * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), gpu_memory_allocated);
    auto new_active_streams = streams.active_gpu_subset(new_num_blocks);
    // We just need to update the lut indexes so we use false here
    luts_array_first_step->broadcast_lut(new_active_streams, false);
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
  CudaStreams sub_streams_1;
  CudaStreams sub_streams_2;

  cudaEvent_t *incoming_events;
  cudaEvent_t *outgoing_events1;
  cudaEvent_t *outgoing_events2;

  uint32_t compute_overflow;
  bool gpu_memory_allocated;
  int_borrow_prop_memory(CudaStreams streams, int_radix_params params,
                         uint32_t num_radix_blocks,
                         uint32_t compute_overflow_in, bool allocate_gpu_memory,
                         uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    compute_overflow = compute_overflow_in;
    // for compute shifted blocks and block states
    uint32_t block_modulus = message_modulus * carry_modulus;
    uint32_t num_bits_in_block = std::log2(block_modulus);
    uint32_t grouping_size = num_bits_in_block;
    group_size = grouping_size;
    num_groups = (num_radix_blocks + grouping_size - 1) / grouping_size;

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

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        lut_message_extract->get_lut(0, 0), lut_message_extract->get_degree(0),
        lut_message_extract->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_message_extract,
        gpu_memory_allocated);
    active_streams = streams.active_gpu_subset(num_radix_blocks);

    lut_message_extract->broadcast_lut(active_streams);

    if (compute_overflow) {
      lut_borrow_flag =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);
      // lut for the first block in the first grouping
      auto f_borrow_flag = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          lut_borrow_flag->get_lut(0, 0), lut_borrow_flag->get_degree(0),
          lut_borrow_flag->get_max_degree(0), glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_borrow_flag, gpu_memory_allocated);
      lut_borrow_flag->broadcast_lut(active_streams);
    }

    active_streams = streams.active_gpu_subset(num_radix_blocks);
    sub_streams_1.create_on_same_gpus(active_streams);
    sub_streams_2.create_on_same_gpus(active_streams);

    incoming_events =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    outgoing_events1 =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    outgoing_events2 =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    for (uint j = 0; j < active_streams.count(); j++) {
      incoming_events[j] = cuda_create_event(active_streams.gpu_index(j));
      outgoing_events1[j] = cuda_create_event(active_streams.gpu_index(j));
      outgoing_events2[j] = cuda_create_event(active_streams.gpu_index(j));
    }
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
    prop_simu_group_carries_mem->release(streams);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   overflow_block, gpu_memory_allocated);

    lut_message_extract->release(streams);
    delete lut_message_extract;
    delete overflow_block;
    if (compute_overflow) {
      lut_borrow_flag->release(streams);
      delete lut_borrow_flag;
    }

    // The substreams have to be synchronized before destroying events
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    // release events
    for (uint j = 0; j < active_streams.count(); j++) {
      cuda_event_destroy(incoming_events[j], active_streams.gpu_index(j));
      cuda_event_destroy(outgoing_events1[j], active_streams.gpu_index(j));
      cuda_event_destroy(outgoing_events2[j], active_streams.gpu_index(j));
    }
    free(incoming_events);
    free(outgoing_events1);
    free(outgoing_events2);

    sub_streams_1.release();
    sub_streams_2.release();
  };
};
std::pair<bool, bool> get_invert_flags(COMPARISON_TYPE compare);
void reverseArray(uint64_t arr[], size_t n);
#endif // CUDA_INTEGER_UTILITIES_H
