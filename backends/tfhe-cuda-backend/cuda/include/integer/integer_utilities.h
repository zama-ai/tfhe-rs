#ifndef CUDA_INTEGER_UTILITIES_H
#define CUDA_INTEGER_UTILITIES_H

#include "integer.h"
#include "integer/radix_ciphertext.cuh"
#include "integer/radix_ciphertext.h"
#include "keyswitch/keyswitch.h"
#include "pbs/programmable_bootstrap.cuh"
#include "pbs/programmable_bootstrap_128.cuh"
#include "utils/helper_multi_gpu.cuh"
#include <cmath>
#include <functional>
#include <queue>

class NoiseLevel {
public:
  // Constants equivalent to the Rust code
  static const uint64_t NOMINAL = 1;
  static const uint64_t ZERO = 0;
  static const uint64_t UNKNOWN = std::numeric_limits<uint64_t>::max();
};

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
  bool allocate_ms_array;

  int_radix_params(){};

  int_radix_params(PBS_TYPE pbs_type, uint32_t glwe_dimension,
                   uint32_t polynomial_size, uint32_t big_lwe_dimension,
                   uint32_t small_lwe_dimension, uint32_t ks_level,
                   uint32_t ks_base_log, uint32_t pbs_level,
                   uint32_t pbs_base_log, uint32_t grouping_factor,
                   uint32_t message_modulus, uint32_t carry_modulus,
                   bool allocate_ms_array)

      : pbs_type(pbs_type), glwe_dimension(glwe_dimension),
        polynomial_size(polynomial_size), big_lwe_dimension(big_lwe_dimension),
        small_lwe_dimension(small_lwe_dimension), ks_level(ks_level),
        ks_base_log(ks_base_log), pbs_level(pbs_level),
        pbs_base_log(pbs_base_log), grouping_factor(grouping_factor),
        message_modulus(message_modulus), carry_modulus(carry_modulus),
        allocate_ms_array(allocate_ms_array){};

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
template <typename Torus> struct int_radix_lut {
  int_radix_params params;
  uint32_t num_blocks;
  uint32_t num_luts;
  uint32_t num_many_lut = 1;
  // Tracks the degree of each LUT and the max degree on CPU
  // The max degree is (message_modulus * carry_modulus - 1) except for many lut
  // for which it's different
  uint64_t *degrees;
  uint64_t *max_degrees;

  int active_gpu_count;
  bool mem_reuse = false;

  // There will be one buffer on each GPU in multi-GPU computations
  // (same for tmp lwe arrays)
  std::vector<int8_t *> buffer;

  // These arrays will reside on all GPUs
  // lut could actually be allocated & initialized GPU per GPU but this is not
  // done at the moment
  std::vector<Torus *> lut_vec;
  std::vector<Torus *> lut_indexes_vec;
  Torus *h_lut_indexes;
  // All tmp lwe arrays and index arrays for lwe contain the total
  // amount of blocks to be computed on, there is no split between GPUs
  // for the moment
  Torus *lwe_indexes_in;
  Torus *lwe_indexes_out;
  Torus *h_lwe_indexes_in;
  Torus *h_lwe_indexes_out;
  // Enable optimizations if lwe_indexes_(in/out) are trivial
  bool using_trivial_lwe_indexes = true;
  // lwe_trivial_indexes is the intermediary index we need in case
  // lwe_indexes_in != lwe_indexes_out
  Torus *lwe_trivial_indexes;
  CudaRadixCiphertextFFI *tmp_lwe_before_ks;

  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec;

  uint32_t *gpu_indexes;
  bool gpu_memory_allocated;

  int_radix_lut(cudaStream_t const *streams, uint32_t const *input_gpu_indexes,
                uint32_t gpu_count, int_radix_params params, uint32_t num_luts,
                uint32_t num_radix_blocks, bool allocate_gpu_memory,
                uint64_t &size_tracker) {

    this->params = params;
    this->num_blocks = num_radix_blocks;
    this->num_luts = num_luts;
    gpu_memory_allocated = allocate_gpu_memory;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    gpu_indexes = (uint32_t *)malloc(gpu_count * sizeof(uint32_t));
    std::memcpy(gpu_indexes, input_gpu_indexes, gpu_count * sizeof(uint32_t));

    ///////////////
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_set_device(i);
      int8_t *gpu_pbs_buffer;
      auto num_blocks_on_gpu =
          get_num_inputs_on_gpu(num_radix_blocks, i, active_gpu_count);

      uint64_t size = 0;
      execute_scratch_pbs<Torus>(
          streams[i], gpu_indexes[i], &gpu_pbs_buffer, params.glwe_dimension,
          params.small_lwe_dimension, params.polynomial_size, params.pbs_level,
          params.grouping_factor, num_blocks_on_gpu, params.pbs_type,
          allocate_gpu_memory, params.allocate_ms_array, size);
      if (i == 0) {
        size_tracker += size;
      }
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      buffer.push_back(gpu_pbs_buffer);
    }

    // Allocate LUT
    // LUT is used as a trivial encryption and must be initialized outside
    // this constructor
    for (uint i = 0; i < active_gpu_count; i++) {
      auto lut = (Torus *)cuda_malloc_with_size_tracking_async(
          num_luts * lut_buffer_size, streams[i], gpu_indexes[i], size_tracker,
          allocate_gpu_memory);
      auto lut_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
          lut_indexes_size, streams[i], gpu_indexes[i], size_tracker,
          allocate_gpu_memory);
      // lut_indexes is initialized to 0 by default
      // if a different behavior is wanted, it should be rewritten later
      cuda_memset_with_size_tracking_async(lut_indexes, 0, lut_indexes_size,
                                           streams[i], gpu_indexes[i],
                                           allocate_gpu_memory);

      lut_vec.push_back(lut);
      lut_indexes_vec.push_back(lut_indexes);

      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }

    // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
    // by default
    lwe_indexes_in = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    lwe_indexes_out = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    lwe_trivial_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);

    h_lwe_indexes_in = (Torus *)malloc(num_radix_blocks * sizeof(Torus));
    h_lwe_indexes_out = (Torus *)malloc(num_radix_blocks * sizeof(Torus));
    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes_in[i] = i;

    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_in, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_out, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_trivial_indexes, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    memcpy(h_lwe_indexes_out, h_lwe_indexes_in,
           num_radix_blocks * sizeof(Torus));

    /// With multiple GPUs we allocate arrays to be pushed to the vectors and
    /// copy data on each GPU then when we gather data to GPU 0 we can copy
    /// back to the original indexing
    multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                              lwe_array_in_vec, num_radix_blocks,
                              params.big_lwe_dimension + 1, size_tracker,
                              allocate_gpu_memory);
    multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                              lwe_after_ks_vec, num_radix_blocks,
                              params.small_lwe_dimension + 1, size_tracker,
                              allocate_gpu_memory);
    multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                              lwe_after_pbs_vec, num_radix_blocks,
                              params.big_lwe_dimension + 1, size_tracker,
                              allocate_gpu_memory);
    multi_gpu_alloc_array_async(streams, gpu_indexes, active_gpu_count,
                                lwe_trivial_indexes_vec, num_radix_blocks,
                                size_tracker, allocate_gpu_memory);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    multi_gpu_copy_array_async(streams, gpu_indexes, active_gpu_count,
                               lwe_trivial_indexes_vec, lwe_trivial_indexes,
                               num_radix_blocks, allocate_gpu_memory);

    // Keyswitch
    tmp_lwe_before_ks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_lwe_before_ks, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    h_lut_indexes = (Torus *)(calloc(num_radix_blocks, sizeof(Torus)));
    degrees = (uint64_t *)malloc(num_luts * sizeof(uint64_t));
    max_degrees = (uint64_t *)malloc(num_luts * sizeof(uint64_t));
  }

  // constructor to reuse memory
  int_radix_lut(cudaStream_t const *streams, uint32_t const *input_gpu_indexes,
                uint32_t gpu_count, int_radix_params params, uint32_t num_luts,
                uint32_t num_radix_blocks, int_radix_lut *base_lut_object,
                bool allocate_gpu_memory, uint64_t &size_tracker) {

    this->params = params;
    this->num_blocks = num_radix_blocks;
    this->num_luts = num_luts;
    gpu_memory_allocated = allocate_gpu_memory;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    gpu_indexes = (uint32_t *)malloc(gpu_count * sizeof(uint32_t));
    std::memcpy(gpu_indexes, input_gpu_indexes, gpu_count * sizeof(uint32_t));

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

    // Allocate LUT
    // LUT is used as a trivial encryption and must be initialized outside
    // this constructor
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
    for (uint i = 0; i < active_gpu_count; i++) {
      auto lut = (Torus *)cuda_malloc_with_size_tracking_async(
          num_luts * lut_buffer_size, streams[i], gpu_indexes[i], size_tracker,
          allocate_gpu_memory);
      auto lut_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
          lut_indexes_size, streams[i], gpu_indexes[i], size_tracker,
          allocate_gpu_memory);
      // lut_indexes is initialized to 0 by default
      // if a different behavior is wanted, it should be rewritten later
      cuda_memset_with_size_tracking_async(lut_indexes, 0, lut_indexes_size,
                                           streams[i], gpu_indexes[i],
                                           allocate_gpu_memory);

      lut_vec.push_back(lut);
      lut_indexes_vec.push_back(lut_indexes);

      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }

    // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
    // by default
    lwe_indexes_in = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    lwe_indexes_out = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    lwe_trivial_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);

    h_lwe_indexes_in = (Torus *)malloc(num_radix_blocks * sizeof(Torus));
    h_lwe_indexes_out = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes_in[i] = i;

    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_in, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_out, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_trivial_indexes, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    memcpy(h_lwe_indexes_out, h_lwe_indexes_in,
           num_radix_blocks * sizeof(Torus));
    h_lut_indexes = (Torus *)(calloc(num_radix_blocks, sizeof(Torus)));
    degrees = (uint64_t *)malloc(num_luts * sizeof(uint64_t));
    max_degrees = (uint64_t *)malloc(num_luts * sizeof(uint64_t));
  }

  // Construction for many luts
  int_radix_lut(cudaStream_t const *streams, uint32_t const *input_gpu_indexes,
                uint32_t gpu_count, int_radix_params params, uint32_t num_luts,
                uint32_t num_radix_blocks, uint32_t num_many_lut,
                bool allocate_gpu_memory, uint64_t &size_tracker) {

    this->num_many_lut = num_many_lut;
    this->params = params;
    this->num_blocks = num_radix_blocks;
    this->num_luts = num_luts;
    gpu_memory_allocated = allocate_gpu_memory;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    gpu_indexes = (uint32_t *)malloc(gpu_count * sizeof(uint32_t));
    std::memcpy(gpu_indexes, input_gpu_indexes, gpu_count * sizeof(uint32_t));

    ///////////////
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_set_device(i);
      int8_t *gpu_pbs_buffer;
      auto num_blocks_on_gpu =
          get_num_inputs_on_gpu(num_radix_blocks, i, active_gpu_count);

      uint64_t size = 0;
      execute_scratch_pbs<Torus>(
          streams[i], gpu_indexes[i], &gpu_pbs_buffer, params.glwe_dimension,
          params.small_lwe_dimension, params.polynomial_size, params.pbs_level,
          params.grouping_factor, num_blocks_on_gpu, params.pbs_type,
          allocate_gpu_memory, params.allocate_ms_array, size);
      if (i == 0) {
        size_tracker += size;
      }
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      buffer.push_back(gpu_pbs_buffer);
    }

    // Allocate LUT
    // LUT is used as a trivial encryption and must be initialized outside
    // this constructor
    for (uint i = 0; i < active_gpu_count; i++) {
      auto lut = (Torus *)cuda_malloc_with_size_tracking_async(
          num_luts * lut_buffer_size, streams[i], gpu_indexes[i], size_tracker,
          allocate_gpu_memory);
      auto lut_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
          lut_indexes_size, streams[i], gpu_indexes[i], size_tracker,
          allocate_gpu_memory);
      // lut_indexes is initialized to 0 by default
      // if a different behavior is wanted, it should be rewritten later
      cuda_memset_with_size_tracking_async(lut_indexes, 0, lut_indexes_size,
                                           streams[i], gpu_indexes[i],
                                           allocate_gpu_memory);

      lut_vec.push_back(lut);
      lut_indexes_vec.push_back(lut_indexes);

      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }

    // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
    // by default
    lwe_indexes_in = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    lwe_indexes_out = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    lwe_trivial_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);

    h_lwe_indexes_in = (Torus *)malloc(num_radix_blocks * sizeof(Torus));
    h_lwe_indexes_out = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes_in[i] = i;

    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_in, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_out, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_trivial_indexes, h_lwe_indexes_in, num_radix_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    memcpy(h_lwe_indexes_out, h_lwe_indexes_in,
           num_radix_blocks * sizeof(Torus));

    /// With multiple GPUs we allocate arrays to be pushed to the vectors and
    /// copy data on each GPU then when we gather data to GPU 0 we can copy
    /// back to the original indexing
    multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                              lwe_array_in_vec, num_radix_blocks,
                              params.big_lwe_dimension + 1, size_tracker,
                              allocate_gpu_memory);
    multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                              lwe_after_ks_vec, num_radix_blocks,
                              params.small_lwe_dimension + 1, size_tracker,
                              allocate_gpu_memory);
    multi_gpu_alloc_lwe_many_lut_output_async(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        num_radix_blocks, num_many_lut, params.big_lwe_dimension + 1,
        size_tracker, allocate_gpu_memory);
    multi_gpu_alloc_array_async(streams, gpu_indexes, active_gpu_count,
                                lwe_trivial_indexes_vec, num_radix_blocks,
                                size_tracker, allocate_gpu_memory);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    multi_gpu_copy_array_async(streams, gpu_indexes, active_gpu_count,
                               lwe_trivial_indexes_vec, lwe_trivial_indexes,
                               num_radix_blocks, allocate_gpu_memory);

    // Keyswitch
    tmp_lwe_before_ks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_lwe_before_ks, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    h_lut_indexes = (Torus *)(calloc(num_radix_blocks, sizeof(Torus)));
    degrees = (uint64_t *)malloc(num_many_lut * num_luts * sizeof(uint64_t));
    max_degrees = (uint64_t *)malloc(num_luts * sizeof(uint64_t));
  }

  // Return a pointer to idx-ith lut at gpu_index's global memory
  Torus *get_lut(uint32_t gpu_index, size_t idx) {
    if (!gpu_memory_allocated)
      return nullptr;
    auto lut = lut_vec[gpu_index];
    size_t lut_size = (params.glwe_dimension + 1) * params.polynomial_size;

    if (lut == nullptr)
      PANIC("Cuda error: invalid lut pointer")
    return &lut[idx * lut_size];
  }

  // Return a pointer to idx-ith degree
  uint64_t *get_degree(size_t idx) { return &degrees[num_many_lut * idx]; }

  // Return a pointer to idx-ith max degree
  uint64_t *get_max_degree(size_t idx) { return &max_degrees[idx]; }

  // Return a pointer to idx-ith lut indexes at gpu_index's global memory
  Torus *get_lut_indexes(uint32_t gpu_index, size_t ind) {
    if (!gpu_memory_allocated)
      return nullptr;
    auto lut_indexes = lut_indexes_vec[gpu_index];
    return &lut_indexes[ind];
  }

  // If this function is called we assume the lwe_indexes_(in/out) are not the
  // trivial anymore and thus we disable optimizations
  void set_lwe_indexes(cudaStream_t stream, uint32_t gpu_index,
                       Torus *h_indexes_in, Torus *h_indexes_out) {

    memcpy(h_lwe_indexes_in, h_indexes_in, num_blocks * sizeof(Torus));
    memcpy(h_lwe_indexes_out, h_indexes_out, num_blocks * sizeof(Torus));

    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_in, h_lwe_indexes_in, num_blocks * sizeof(Torus), stream,
        gpu_index, gpu_memory_allocated);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_out, h_lwe_indexes_out, num_blocks * sizeof(Torus), stream,
        gpu_index, gpu_memory_allocated);

    using_trivial_lwe_indexes = false;
  }

  // Broadcast luts from gpu src_gpu_idx to all active gpus
  void broadcast_lut(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                     uint32_t src_gpu_idx) {
    Torus lut_size = (params.glwe_dimension + 1) * params.polynomial_size;

    auto src_lut = lut_vec[src_gpu_idx];
    auto src_lut_indexes = lut_indexes_vec[src_gpu_idx];

    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    for (uint i = 0; i < active_gpu_count; i++) {
      if (i != src_gpu_idx) {
        auto dst_lut = lut_vec[i];
        auto dst_lut_indexes = lut_indexes_vec[i];
        cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
            dst_lut, src_lut, num_luts * lut_size * sizeof(Torus), streams[i],
            gpu_indexes[i], gpu_memory_allocated);
        cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
            dst_lut_indexes, src_lut_indexes, num_blocks * sizeof(Torus),
            streams[i], gpu_indexes[i], gpu_memory_allocated);
      }
    }
    cuda_set_device(gpu_indexes[0]);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    free(this->gpu_indexes);
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_drop_with_size_tracking_async(lut_vec[i], streams[i], gpu_indexes[i],
                                         gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(lut_indexes_vec[i], streams[i],
                                         gpu_indexes[i], gpu_memory_allocated);
    }

    cuda_drop_with_size_tracking_async(lwe_indexes_in, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(lwe_indexes_out, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(lwe_trivial_indexes, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);

    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    lut_vec.clear();
    lut_indexes_vec.clear();
    free(h_lwe_indexes_in);
    free(h_lwe_indexes_out);

    if (!mem_reuse) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     tmp_lwe_before_ks, gpu_memory_allocated);
      if (gpu_memory_allocated) {
        for (int i = 0; i < buffer.size(); i++) {
          switch (params.pbs_type) {
          case MULTI_BIT:
            cleanup_cuda_multi_bit_programmable_bootstrap(
                streams[i], gpu_indexes[i], &buffer[i]);
            break;
          case CLASSICAL:
            cleanup_cuda_programmable_bootstrap(streams[i], gpu_indexes[i],
                                                &buffer[i]);
            break;
          default:
            PANIC("Cuda error (PBS): unknown PBS type. ")
          }
          cuda_synchronize_stream(streams[i], gpu_indexes[i]);
        }
      }
      delete tmp_lwe_before_ks;
      buffer.clear();

      if (gpu_memory_allocated) {
        multi_gpu_release_async(streams, gpu_indexes, lwe_array_in_vec);
        multi_gpu_release_async(streams, gpu_indexes, lwe_after_ks_vec);
        multi_gpu_release_async(streams, gpu_indexes, lwe_after_pbs_vec);
        multi_gpu_release_async(streams, gpu_indexes, lwe_trivial_indexes_vec);
        for (uint i = 0; i < active_gpu_count; i++)
          cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      }
      lwe_array_in_vec.clear();
      lwe_after_ks_vec.clear();
      lwe_after_pbs_vec.clear();
      lwe_trivial_indexes_vec.clear();
    }
    free(h_lut_indexes);
    free(degrees);
    free(max_degrees);
  }
};

template <typename InputTorus> struct int_noise_squashing_lut {

  int_radix_params params;
  uint32_t input_glwe_dimension;
  uint32_t input_polynomial_size;
  uint32_t input_big_lwe_dimension;
  uint32_t num_blocks;
  // Tracks the degree of each LUT and the max degree on CPU
  // The max degree is (message_modulus * carry_modulus - 1) except for many lut
  // for which it's different
  uint64_t *degrees;
  uint64_t *max_degrees;

  int active_gpu_count;

  // There will be one buffer on each GPU in multi-GPU computations
  // (same for tmp lwe arrays)
  std::vector<int8_t *> pbs_buffer;

  std::vector<__uint128_t *> lut_vec;

  uint32_t *gpu_indexes;
  CudaRadixCiphertextFFI *tmp_lwe_before_ks;

  // All tmp lwe arrays and index arrays for lwe contain the total
  // amount of blocks to be computed on, there is no split between GPUs
  // for the moment
  InputTorus *lwe_indexes_in;

  InputTorus *h_lwe_indexes_in;
  InputTorus *h_lwe_indexes_out;
  InputTorus *lwe_trivial_indexes;

  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<InputTorus *> lwe_array_in_vec;
  std::vector<InputTorus *> lwe_after_ks_vec;
  std::vector<__uint128_t *> lwe_after_pbs_vec;
  std::vector<InputTorus *> lwe_trivial_indexes_vec;

  bool using_trivial_lwe_indexes = true;
  bool gpu_memory_allocated;
  // noise squashing constructor
  int_noise_squashing_lut(cudaStream_t const *streams,
                          uint32_t const *input_gpu_indexes, uint32_t gpu_count,
                          int_radix_params params,
                          uint32_t input_glwe_dimension,
                          uint32_t input_polynomial_size,
                          uint32_t num_radix_blocks,
                          uint32_t original_num_blocks,
                          bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->num_blocks = num_radix_blocks;
    gpu_memory_allocated = allocate_gpu_memory;
    // This are the glwe dimension and polynomial size before squashing
    this->input_glwe_dimension = input_glwe_dimension;
    this->input_polynomial_size = input_polynomial_size;
    uint32_t input_big_lwe_dimension =
        input_glwe_dimension * input_polynomial_size;
    this->input_big_lwe_dimension = input_big_lwe_dimension;

    uint32_t lut_buffer_size = (params.glwe_dimension + 1) *
                               params.polynomial_size * sizeof(__uint128_t);

    gpu_indexes = (uint32_t *)malloc(gpu_count * sizeof(uint32_t));
    std::memcpy(gpu_indexes, input_gpu_indexes, gpu_count * sizeof(uint32_t));

    ///////////////
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_set_device(i);
      auto num_radix_blocks_on_gpu =
          get_num_inputs_on_gpu(num_radix_blocks, i, active_gpu_count);
      int8_t *gpu_pbs_buffer;
      uint64_t size = 0;
      execute_scratch_pbs_128(streams[i], gpu_indexes[i], &gpu_pbs_buffer,
                              params.small_lwe_dimension, params.glwe_dimension,
                              params.polynomial_size, params.pbs_level,
                              num_radix_blocks_on_gpu, allocate_gpu_memory,
                              params.allocate_ms_array, size);
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      if (i == 0) {
        size_tracker += size;
      }
      pbs_buffer.push_back(gpu_pbs_buffer);
    }
    lwe_indexes_in = (InputTorus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(InputTorus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    lwe_trivial_indexes = (InputTorus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(InputTorus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    h_lwe_indexes_in =
        (InputTorus *)malloc(num_radix_blocks * sizeof(InputTorus));
    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes_in[i] = i;

    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes_in, h_lwe_indexes_in, num_radix_blocks * sizeof(InputTorus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_trivial_indexes, h_lwe_indexes_in,
        num_radix_blocks * sizeof(InputTorus), streams[0], gpu_indexes[0],
        allocate_gpu_memory);

    multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                              lwe_array_in_vec, num_radix_blocks,
                              params.big_lwe_dimension + 1, size_tracker,
                              allocate_gpu_memory);

    multi_gpu_alloc_lwe_async<InputTorus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_ks_vec,
        num_radix_blocks, params.small_lwe_dimension + 1, size_tracker,
        allocate_gpu_memory);
    multi_gpu_alloc_lwe_async<__uint128_t>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        num_radix_blocks, params.big_lwe_dimension + 1, size_tracker,
        allocate_gpu_memory);
    multi_gpu_alloc_array_async<InputTorus>(
        streams, gpu_indexes, active_gpu_count, lwe_trivial_indexes_vec,
        num_radix_blocks, size_tracker, allocate_gpu_memory);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    multi_gpu_copy_array_async(streams, gpu_indexes, active_gpu_count,
                               lwe_trivial_indexes_vec, lwe_trivial_indexes,
                               num_radix_blocks, allocate_gpu_memory);
    if (allocate_gpu_memory) {
      // Allocate LUT
      // LUT is used as a trivial encryption and must be initialized outside
      // this constructor
      for (uint i = 0; i < active_gpu_count; i++) {
        auto lut = (__uint128_t *)cuda_malloc_with_size_tracking_async(
            lut_buffer_size, streams[i], gpu_indexes[i], size_tracker,
            allocate_gpu_memory);
        lut_vec.push_back(lut);
        cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      }
    }
    // Keyswitch
    tmp_lwe_before_ks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<InputTorus>(
        streams[0], gpu_indexes[0], tmp_lwe_before_ks, original_num_blocks,
        input_big_lwe_dimension, size_tracker, allocate_gpu_memory);

    degrees = (uint64_t *)malloc(sizeof(uint64_t));
    max_degrees = (uint64_t *)malloc(sizeof(uint64_t));

    // lut for the squashing
    auto f_squash = [](__uint128_t block) -> __uint128_t { return block; };

    // Generate the identity LUT, for now we only use one GPU
    for (uint i = 0; i < active_gpu_count; i++) {
      auto squash_lut = lut_vec[i];
      generate_device_accumulator<__uint128_t>(
          streams[i], gpu_indexes[i], squash_lut, degrees, max_degrees,
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, f_squash, allocate_gpu_memory);
    }
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    free(this->gpu_indexes);
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_drop_with_size_tracking_async(lut_vec[i], streams[i], gpu_indexes[i],
                                         gpu_memory_allocated);
    }
    cuda_drop_with_size_tracking_async(lwe_indexes_in, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(lwe_trivial_indexes, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    lut_vec.clear();
    free(h_lwe_indexes_in);

    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   tmp_lwe_before_ks, gpu_memory_allocated);
    for (int i = 0; i < pbs_buffer.size(); i++) {
      cleanup_cuda_programmable_bootstrap_128(streams[i], gpu_indexes[i],
                                              &pbs_buffer[i]);
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }

    multi_gpu_release_async(streams, gpu_indexes, lwe_array_in_vec);
    multi_gpu_release_async(streams, gpu_indexes, lwe_after_ks_vec);
    multi_gpu_release_async(streams, gpu_indexes, lwe_after_pbs_vec);
    multi_gpu_release_async(streams, gpu_indexes, lwe_trivial_indexes_vec);
    for (uint i = 0; i < active_gpu_count; i++)
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    lwe_array_in_vec.clear();
    lwe_after_ks_vec.clear();
    lwe_after_pbs_vec.clear();
    lwe_trivial_indexes_vec.clear();

    delete tmp_lwe_before_ks;
    pbs_buffer.clear();
  }
};

template <typename Torus> struct int_bit_extract_luts_buffer {
  int_radix_params params;
  int_radix_lut<Torus> *lut;
  bool gpu_memory_allocated;

  // With offset
  int_bit_extract_luts_buffer(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              int_radix_params params, uint32_t bits_per_block,
                              uint32_t final_offset, uint32_t num_radix_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, bits_per_block,
        bits_per_block * num_radix_blocks, allocate_gpu_memory, size_tracker);

    for (int i = 0; i < bits_per_block; i++) {

      auto operator_f = [i, final_offset](Torus x) -> Torus {
        Torus y = (x >> i) & 1;
        return y << final_offset;
      };

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut->get_lut(0, i), lut->get_degree(i),
          lut->get_max_degree(i), params.glwe_dimension, params.polynomial_size,
          params.message_modulus, params.carry_modulus, operator_f,
          gpu_memory_allocated);
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
        num_radix_blocks * bits_per_block * sizeof(Torus), streams[0],
        gpu_indexes[0], allocate_gpu_memory);
    lut->broadcast_lut(streams, gpu_indexes, 0);

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

    lut->set_lwe_indexes(streams[0], gpu_indexes[0], h_lwe_indexes_in,
                         h_lwe_indexes_out);

    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    free(h_lwe_indexes_in);
    free(h_lwe_indexes_out);
  }

  // Without offset
  int_bit_extract_luts_buffer(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              int_radix_params params, uint32_t bits_per_block,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory, uint64_t &size_tracker)
      : int_bit_extract_luts_buffer(streams, gpu_indexes, gpu_count, params,
                                    bits_per_block, 0, num_radix_blocks,
                                    allocate_gpu_memory, size_tracker) {}

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    lut->release(streams, gpu_indexes, gpu_count);
    delete (lut);
  }
};

template <typename Torus> struct int_shift_and_rotate_buffer {
  int_radix_params params;
  SHIFT_OR_ROTATE_TYPE shift_type;
  bool is_signed;

  CudaRadixCiphertextFFI *tmp_bits;
  CudaRadixCiphertextFFI *tmp_shift_bits;
  CudaRadixCiphertextFFI *tmp_rotated;
  CudaRadixCiphertextFFI *tmp_input_bits_a;
  CudaRadixCiphertextFFI *tmp_input_bits_b;
  CudaRadixCiphertextFFI *tmp_mux_inputs;

  int_bit_extract_luts_buffer<Torus> *bit_extract_luts;
  int_bit_extract_luts_buffer<Torus> *bit_extract_luts_with_offset_2;
  int_radix_lut<Torus> *mux_lut;
  int_radix_lut<Torus> *cleaning_lut;

  Torus offset;
  bool gpu_memory_allocated;

  int_shift_and_rotate_buffer(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
                              int_radix_params params,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->shift_type = shift_type;
    this->is_signed = is_signed;
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    uint32_t bits_per_block = std::log2(params.message_modulus);
    uint32_t total_nb_bits =
        std::log2(params.message_modulus) * num_radix_blocks;
    uint32_t max_num_bits_that_tell_shift = std::log2(total_nb_bits);

    auto is_power_of_two = [](uint32_t n) {
      return (n > 0) && ((n & (n - 1)) == 0);
    };

    if (!is_power_of_two(total_nb_bits))
      max_num_bits_that_tell_shift += 1;

    offset = (shift_type == LEFT_SHIFT ? 0 : total_nb_bits);

    bit_extract_luts = new int_bit_extract_luts_buffer<Torus>(
        streams, gpu_indexes, gpu_count, params, bits_per_block,
        num_radix_blocks, allocate_gpu_memory, size_tracker);
    bit_extract_luts_with_offset_2 = new int_bit_extract_luts_buffer<Torus>(
        streams, gpu_indexes, gpu_count, params, bits_per_block, 2,
        num_radix_blocks, allocate_gpu_memory, size_tracker);

    mux_lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params,
                                       1, bits_per_block * num_radix_blocks,
                                       allocate_gpu_memory, size_tracker);
    cleaning_lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                            params, 1, num_radix_blocks,
                                            allocate_gpu_memory, size_tracker);

    tmp_bits = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_bits, bits_per_block * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tmp_shift_bits = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_shift_bits,
        max_num_bits_that_tell_shift * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tmp_rotated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_rotated,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_input_bits_a = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_input_bits_a,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_input_bits_b = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_input_bits_b,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_mux_inputs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_mux_inputs,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    auto mux_lut_f = [](Torus x) -> Torus {
      // x is expected to be x = 0bcba
      // where
      // - c is the control bit
      // - b the bit value returned if c is 1
      // - a the bit value returned if c is 0
      // (any bit above c is ignored)
      x = x & 7;
      auto control_bit = x >> 2;
      auto previous_bit = (x & 2) >> 1;
      auto current_bit = x & 1;

      if (control_bit == 1)
        return previous_bit;
      else
        return current_bit;
    };

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], mux_lut->get_lut(0, 0),
        mux_lut->get_degree(0), mux_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, mux_lut_f, gpu_memory_allocated);
    mux_lut->broadcast_lut(streams, gpu_indexes, 0);

    auto cleaning_lut_f = [params](Torus x) -> Torus {
      return x % params.message_modulus;
    };
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], cleaning_lut->get_lut(0, 0),
        cleaning_lut->get_degree(0), cleaning_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, cleaning_lut_f, gpu_memory_allocated);
    cleaning_lut->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_bits,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_shift_bits,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_rotated,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_input_bits_a,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_input_bits_b,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_mux_inputs,
                                   gpu_memory_allocated);

    bit_extract_luts->release(streams, gpu_indexes, gpu_count);
    bit_extract_luts_with_offset_2->release(streams, gpu_indexes, gpu_count);
    mux_lut->release(streams, gpu_indexes, gpu_count);
    cleaning_lut->release(streams, gpu_indexes, gpu_count);

    delete tmp_bits;
    delete tmp_shift_bits;
    delete tmp_rotated;
    delete tmp_input_bits_a;
    delete tmp_input_bits_b;
    delete tmp_mux_inputs;
    delete bit_extract_luts;
    delete bit_extract_luts_with_offset_2;
    delete mux_lut;
    delete cleaning_lut;
  }
};

template <typename Torus> struct int_fullprop_buffer {
  int_radix_params params;

  int_radix_lut<Torus> *lut;

  CudaRadixCiphertextFFI *tmp_small_lwe_vector;
  CudaRadixCiphertextFFI *tmp_big_lwe_vector;
  bool gpu_memory_allocated;

  int_fullprop_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                      uint32_t gpu_count, int_radix_params params,
                      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;
    lut = new int_radix_lut<Torus>(streams, gpu_indexes, 1, params, 2, 2,
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
        streams[0], gpu_indexes[0], lut_buffer_message, message_degree,
        message_max_degree, params.glwe_dimension, params.polynomial_size,
        params.message_modulus, params.carry_modulus, lut_f_message,
        gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_buffer_carry, carry_degree,
        carry_max_degree, params.glwe_dimension, params.polynomial_size,
        params.message_modulus, params.carry_modulus, lut_f_carry,
        gpu_memory_allocated);

    Torus lwe_indexes_size = 2 * sizeof(Torus);
    Torus *h_lwe_indexes = (Torus *)malloc(lwe_indexes_size);
    for (int i = 0; i < 2; i++)
      h_lwe_indexes[i] = i;
    Torus *lwe_indexes = lut->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lwe_indexes, h_lwe_indexes, lwe_indexes_size, streams[0],
        gpu_indexes[0], allocate_gpu_memory);

    lut->broadcast_lut(streams, gpu_indexes, 0);

    tmp_small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_small_lwe_vector, 2,
        params.small_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_big_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_big_lwe_vector, 2,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    free(h_lwe_indexes);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   tmp_small_lwe_vector, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   tmp_big_lwe_vector, gpu_memory_allocated);
    lut->release(streams, gpu_indexes, 1);
    delete tmp_small_lwe_vector;
    delete tmp_big_lwe_vector;
    delete lut;
  }
};

template <typename Torus> struct int_overflowing_sub_memory {
  Torus *generates_or_propagates;
  Torus *step_output;

  int_radix_lut<Torus> *luts_array;
  int_radix_lut<Torus> *luts_borrow_propagation_sum;
  int_radix_lut<Torus> *message_acc;

  int_radix_params params;
  bool gpu_memory_allocated;

  int_overflowing_sub_memory(cudaStream_t const *streams,
                             uint32_t const *gpu_indexes, uint32_t gpu_count,
                             int_radix_params params, uint32_t num_radix_blocks,
                             bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    // allocate memory for intermediate calculations
    generates_or_propagates = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    step_output = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    cuda_memset_with_size_tracking_async(
        generates_or_propagates, 0, num_radix_blocks * big_lwe_size_bytes,
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memset_with_size_tracking_async(
        step_output, 0, num_radix_blocks * big_lwe_size_bytes, streams[0],
        gpu_indexes[0], allocate_gpu_memory);

    // declare functions for lut generation
    auto f_lut_does_block_generate_carry = [message_modulus](Torus x) -> Torus {
      if (x < message_modulus)
        return OUTPUT_CARRY::GENERATED;
      return OUTPUT_CARRY::NONE;
    };

    auto f_lut_does_block_generate_or_propagate =
        [message_modulus](Torus x) -> Torus {
      if (x < message_modulus)
        return OUTPUT_CARRY::GENERATED;
      else if (x == message_modulus)
        return OUTPUT_CARRY::PROPAGATED;
      return OUTPUT_CARRY::NONE;
    };

    auto f_luts_borrow_propagation_sum = [](Torus msb, Torus lsb) -> Torus {
      if (msb == OUTPUT_CARRY::PROPAGATED)
        return lsb;
      return msb;
    };

    auto f_message_acc = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };

    // create lut objects
    luts_array = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                          params, 2, num_radix_blocks,
                                          allocate_gpu_memory, size_tracker);
    luts_borrow_propagation_sum = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
        luts_array, size_tracker, allocate_gpu_memory, size_tracker);
    message_acc = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
        luts_array, size_tracker, allocate_gpu_memory, size_tracker);

    auto lut_does_block_generate_carry = luts_array->get_lut(0, 0);
    auto lut_does_block_generate_or_propagate = luts_array->get_lut(0, 1);

    // generate luts (aka accumulators)
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_does_block_generate_carry,
        luts_array->get_degree(0), luts_array->get_max_degree(0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_carry, gpu_memory_allocated);
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_does_block_generate_or_propagate,
        luts_array->get_degree(1), luts_array->get_max_degree(1),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_or_propagate, gpu_memory_allocated);
    if (allocate_gpu_memory)
      cuda_set_value_async<Torus>(streams[0], gpu_indexes[0],
                                  luts_array->get_lut_indexes(0, 1), 1,
                                  num_radix_blocks - 1);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], luts_borrow_propagation_sum->get_lut(0, 0),
        luts_borrow_propagation_sum->get_degree(0),
        luts_borrow_propagation_sum->get_max_degree(0), glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_luts_borrow_propagation_sum, gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], message_acc->get_lut(0, 0),
        message_acc->get_degree(0), message_acc->get_max_degree(0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_message_acc, gpu_memory_allocated);

    luts_array->broadcast_lut(streams, gpu_indexes, 0);
    luts_borrow_propagation_sum->broadcast_lut(streams, gpu_indexes, 0);
    message_acc->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_with_size_tracking_async(generates_or_propagates, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(step_output, streams[0], gpu_indexes[0],
                                       gpu_memory_allocated);

    luts_array->release(streams, gpu_indexes, gpu_count);
    luts_borrow_propagation_sum->release(streams, gpu_indexes, gpu_count);
    message_acc->release(streams, gpu_indexes, gpu_count);

    delete luts_array;
    delete luts_borrow_propagation_sum;
    delete message_acc;
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

  void setup_index_buffers(cudaStream_t const *streams,
                           uint32_t const *gpu_indexes,
                           uint64_t &size_tracker) {

    d_degrees = (uint64_t *)cuda_malloc_with_size_tracking_async(
        max_total_blocks_in_vec * sizeof(uint64_t), streams[0], gpu_indexes[0],
        size_tracker, gpu_memory_allocated);

    auto num_blocks_in_radix = this->num_blocks_in_radix;
    auto max_num_radix_in_vec = this->max_num_radix_in_vec;
    auto setup_columns =
        [num_blocks_in_radix, max_num_radix_in_vec, streams,
         gpu_indexes](uint32_t **&columns, uint32_t *&columns_data,
                      uint32_t *&columns_counter, uint64_t &size_tracker,
                      bool gpu_memory_allocated) {
          columns_data = (uint32_t *)cuda_malloc_with_size_tracking_async(
              num_blocks_in_radix * max_num_radix_in_vec * sizeof(uint32_t),
              streams[0], gpu_indexes[0], size_tracker, gpu_memory_allocated);
          columns_counter = (uint32_t *)cuda_malloc_with_size_tracking_async(
              num_blocks_in_radix * sizeof(uint32_t), streams[0],
              gpu_indexes[0], size_tracker, gpu_memory_allocated);
          cuda_memset_with_size_tracking_async(
              columns_counter, 0, num_blocks_in_radix * sizeof(uint32_t),
              streams[0], gpu_indexes[0], gpu_memory_allocated);
          uint32_t **h_columns = new uint32_t *[num_blocks_in_radix];
          for (int i = 0; i < num_blocks_in_radix; ++i) {
            h_columns[i] = columns_data + i * max_num_radix_in_vec;
          }
          columns = (uint32_t **)cuda_malloc_with_size_tracking_async(
              num_blocks_in_radix * sizeof(uint32_t *), streams[0],
              gpu_indexes[0], size_tracker, gpu_memory_allocated);
          if (gpu_memory_allocated) {
            cuda_memcpy_async_to_gpu(columns, h_columns,
                                     num_blocks_in_radix * sizeof(uint32_t *),
                                     streams[0], gpu_indexes[0]);
          }
          cuda_synchronize_stream(streams[0], gpu_indexes[0]);
          delete[] h_columns;
        };

    setup_columns(d_columns, d_columns_data, d_columns_counter, size_tracker,
                  gpu_memory_allocated);
    setup_columns(d_new_columns, d_new_columns_data, d_new_columns_counter,
                  size_tracker, gpu_memory_allocated);
  }

  void setup_lookup_tables(cudaStream_t const *streams,
                           uint32_t const *gpu_indexes, uint32_t gpu_count,
                           uint32_t num_radix_in_vec,
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

    if (!mem_reuse) {
      uint32_t pbs_count = std::max(total_ciphertexts, 2 * num_blocks_in_radix);
      if (total_ciphertexts > 0 ||
          reduce_degrees_for_single_carry_propagation) {
        uint64_t size_tracker = 0;
        luts_message_carry =
            new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                     pbs_count, true, size_tracker);
        allocated_luts_message_carry = true;
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
          streams[0], gpu_indexes[0], message_acc,
          luts_message_carry->get_degree(0),
          luts_message_carry->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, message_modulus, params.carry_modulus,
          lut_f_message, gpu_memory_allocated);
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], carry_acc,
          luts_message_carry->get_degree(1),
          luts_message_carry->get_max_degree(1), params.glwe_dimension,
          params.polynomial_size, message_modulus, params.carry_modulus,
          lut_f_carry, gpu_memory_allocated);
      luts_message_carry->broadcast_lut(streams, gpu_indexes, 0);
    }
  }
  int_sum_ciphertexts_vec_memory(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_blocks_in_radix,
      uint32_t max_num_radix_in_vec,
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
    setup_index_buffers(streams, gpu_indexes, size_tracker);
    // because we setup_lut in host function for sum_ciphertexts to save memory
    // the size_tracker is topped up here to have a max bound on the used memory
    uint32_t max_pbs_count = std::max(
        2 * (max_total_blocks_in_vec / chunk_size), 2 * num_blocks_in_radix);
    if (max_pbs_count > 0) {
      int_radix_lut<Torus> *luts_message_carry_dry_run =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                   max_pbs_count, false, size_tracker);
      luts_message_carry_dry_run->release(streams, gpu_indexes, gpu_count);
      delete luts_message_carry_dry_run;
    }

    // create and allocate intermediate buffers
    current_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], current_blocks, max_total_blocks_in_vec,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], small_lwe_vector, max_total_blocks_in_vec,
        params.small_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  int_sum_ciphertexts_vec_memory(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_blocks_in_radix,
      uint32_t max_num_radix_in_vec, CudaRadixCiphertextFFI *current_blocks,
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
    setup_index_buffers(streams, gpu_indexes, size_tracker);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_with_size_tracking_async(d_degrees, streams[0], gpu_indexes[0],
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_columns_data, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_columns_counter, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_columns, streams[0], gpu_indexes[0],
                                       gpu_memory_allocated);

    cuda_drop_with_size_tracking_async(d_new_columns_data, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_new_columns_counter, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_new_columns, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);

    if (!mem_reuse) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], current_blocks,
                                     gpu_memory_allocated);
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     small_lwe_vector, gpu_memory_allocated);
      if (allocated_luts_message_carry) {
        luts_message_carry->release(streams, gpu_indexes, gpu_count);
        delete luts_message_carry;
      }
      delete current_blocks;
      delete small_lwe_vector;
    }
  }
};

// For sequential algorithm in group propagation
template <typename Torus> struct int_seq_group_prop_memory {

  CudaRadixCiphertextFFI *group_resolved_carries;
  int_radix_lut<Torus> *lut_sequential_algorithm;
  uint32_t grouping_size;
  bool gpu_memory_allocated;

  int_seq_group_prop_memory(cudaStream_t const *streams,
                            uint32_t const *gpu_indexes, uint32_t gpu_count,
                            int_radix_params params, uint32_t group_size,
                            uint32_t big_lwe_size_bytes,
                            bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    grouping_size = group_size;
    group_resolved_carries = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], group_resolved_carries, grouping_size,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    int num_seq_luts = grouping_size - 1;
    Torus *h_seq_lut_indexes = (Torus *)malloc(num_seq_luts * sizeof(Torus));
    lut_sequential_algorithm = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, num_seq_luts, num_seq_luts,
        allocate_gpu_memory, size_tracker);
    for (int index = 0; index < num_seq_luts; index++) {
      auto f_lut_sequential = [index](Torus propa_cum_sum_block) {
        return (propa_cum_sum_block >> (index + 1)) & 1;
      };
      auto seq_lut = lut_sequential_algorithm->get_lut(0, index);
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], seq_lut,
          lut_sequential_algorithm->get_degree(index),
          lut_sequential_algorithm->get_max_degree(index), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_lut_sequential,
          gpu_memory_allocated);
      h_seq_lut_indexes[index] = index;
    }
    Torus *seq_lut_indexes = lut_sequential_algorithm->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        seq_lut_indexes, h_seq_lut_indexes, num_seq_luts * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);

    lut_sequential_algorithm->broadcast_lut(streams, gpu_indexes, 0);
    free(h_seq_lut_indexes);
  };
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   group_resolved_carries,
                                   gpu_memory_allocated);
    lut_sequential_algorithm->release(streams, gpu_indexes, gpu_count);
    delete group_resolved_carries;
    delete lut_sequential_algorithm;
  };
};

// For hillis steele algorithm in group propagation
template <typename Torus> struct int_hs_group_prop_memory {

  int_radix_lut<Torus> *lut_hillis_steele;
  bool gpu_memory_allocated;

  int_hs_group_prop_memory(cudaStream_t const *streams,
                           uint32_t const *gpu_indexes, uint32_t gpu_count,
                           int_radix_params params, uint32_t num_groups,
                           uint32_t big_lwe_size_bytes,
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

    lut_hillis_steele =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_groups, allocate_gpu_memory, size_tracker);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], lut_hillis_steele->get_lut(0, 0),
        lut_hillis_steele->get_degree(0), lut_hillis_steele->get_max_degree(0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_hillis_steele, gpu_memory_allocated);

    lut_hillis_steele->broadcast_lut(streams, gpu_indexes, 0);
  };
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    lut_hillis_steele->release(streams, gpu_indexes, gpu_count);
    delete lut_hillis_steele;
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
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t num_many_lut, uint32_t grouping_size, bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    gpu_memory_allocated = allocate_gpu_memory;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    shifted_blocks_and_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], shifted_blocks_and_states,
        num_many_lut * num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    shifted_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], shifted_blocks, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    block_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], block_states, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    uint32_t num_luts_first_step = 2 * grouping_size + 1;

    luts_array_first_step = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, num_luts_first_step,
        num_radix_blocks, num_many_lut, allocate_gpu_memory, size_tracker);

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
        streams[0], gpu_indexes[0], first_block_lut, first_block_lut_degrees,
        first_block_lut_max_degree, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_first_grouping_luts,
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
          streams[0], gpu_indexes[0], lut, lut_degrees, lut_max_degree,
          glwe_dimension, polynomial_size, message_modulus, carry_modulus,
          f_grouping_luts, gpu_memory_allocated);
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
          streams[0], gpu_indexes[0], lut, lut_degrees, lut_max_degree,
          glwe_dimension, polynomial_size, message_modulus, carry_modulus,
          f_grouping_luts, gpu_memory_allocated);
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
        streams[0], gpu_indexes[0], last_block_lut, last_block_lut_degrees,
        last_block_lut_max_degree, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_last_grouping_luts,
        gpu_memory_allocated);

    // Generate the indexes to switch between luts within the pbs
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);

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
        lut_indexes, h_lut_indexes, lut_indexes_size, streams[0],
        gpu_indexes[0], allocate_gpu_memory);
    // Do I need to do something else for the multi-gpu?

    luts_array_first_step->broadcast_lut(streams, gpu_indexes, 0);
  };
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   shifted_blocks_and_states,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], shifted_blocks,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], block_states,
                                   gpu_memory_allocated);

    luts_array_first_step->release(streams, gpu_indexes, gpu_count);
    delete luts_array_first_step;
    delete shifted_blocks_and_states;
    delete shifted_blocks;
    delete block_states;
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
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_radix_blocks,
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
        streams[0], gpu_indexes[0], propagation_cum_sums, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    simulators = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], simulators, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    prepared_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], prepared_blocks, num_radix_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    resolved_carries = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], resolved_carries, num_groups + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    grouping_pgns = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], grouping_pgns, num_groups,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    scalar_array_cum_sum = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        size_tracker, allocate_gpu_memory);
    cuda_memset_with_size_tracking_async(
        scalar_array_cum_sum, 0, num_radix_blocks * sizeof(Torus), streams[0],
        gpu_indexes[0], allocate_gpu_memory);
    h_scalar_array_cum_sum = new Torus[num_radix_blocks]();

    // create lut objects for step 2
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
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
        streams, gpu_indexes, gpu_count, params, num_luts_second_step,
        num_radix_blocks, allocate_gpu_memory, size_tracker);

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
          streams[0], gpu_indexes[0],
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
        streams[0], gpu_indexes[0], luts_array_second_step->get_lut(0, lut_id),
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
          streams[0], gpu_indexes[0],
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
            streams[0], gpu_indexes[0],
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
          streams[0], gpu_indexes[0],
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
        second_lut_indexes, h_second_lut_indexes, lut_indexes_size, streams[0],
        gpu_indexes[0], allocate_gpu_memory);

    cuda_memcpy_with_size_tracking_async_to_gpu(
        scalar_array_cum_sum, h_scalar_array_cum_sum,
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        allocate_gpu_memory);
    luts_array_second_step->broadcast_lut(streams, gpu_indexes, 0);

    if (use_sequential_algorithm_to_resolve_group_carries) {

      seq_group_prop_mem = new int_seq_group_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, grouping_size,
          big_lwe_size_bytes, allocate_gpu_memory, size_tracker);

    } else {
      hs_group_prop_mem = new int_hs_group_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_groups,
          big_lwe_size_bytes, allocate_gpu_memory, size_tracker);
    }

    free(h_second_lut_indexes);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes, Torus *new_lut_indexes,
                          Torus *new_scalars, uint32_t new_num_blocks) {
    Torus *lut_indexes = luts_array_second_step->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        lut_indexes, new_lut_indexes, new_num_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], gpu_memory_allocated);

    luts_array_second_step->broadcast_lut(streams, gpu_indexes, 0);

    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        scalar_array_cum_sum, new_scalars, new_num_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], gpu_memory_allocated);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   propagation_cum_sums, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], simulators,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], grouping_pgns,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], prepared_blocks,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], resolved_carries,
                                   gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(scalar_array_cum_sum, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    luts_array_second_step->release(streams, gpu_indexes, gpu_count);

    if (use_sequential_algorithm_to_resolve_group_carries) {
      seq_group_prop_mem->release(streams, gpu_indexes, gpu_count);
      delete seq_group_prop_mem;
    } else {
      hs_group_prop_mem->release(streams, gpu_indexes, gpu_count);
      delete hs_group_prop_mem;
    }

    delete propagation_cum_sums;
    delete simulators;
    delete grouping_pgns;
    delete prepared_blocks;
    delete resolved_carries;
    delete luts_array_second_step;
    delete[] h_scalar_array_cum_sum;
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

  int_sc_prop_memory(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                     uint32_t gpu_count, int_radix_params params,
                     uint32_t num_radix_blocks, uint32_t requested_flag_in,
                     uint32_t uses_carry, bool allocate_gpu_memory,
                     uint64_t &size_tracker) {
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
        streams, gpu_indexes, gpu_count, params, num_radix_blocks, num_many_lut,
        grouping_size, allocate_gpu_memory, size_tracker);

    prop_simu_group_carries_mem = new int_prop_simu_group_carries_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        grouping_size, num_groups, allocate_gpu_memory, size_tracker);

    //  Step 3 elements
    lut_message_extract = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 2, num_radix_blocks + 1,
        allocate_gpu_memory, size_tracker);
    // lut for the first block in the first grouping
    auto f_message_extract = [message_modulus](Torus block) -> Torus {
      return (block >> 1) % message_modulus;
    };

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_message_extract->get_lut(0, 0),
        lut_message_extract->get_degree(0),
        lut_message_extract->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_message_extract,
        gpu_memory_allocated);

    lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);

    // This store a single block that with be used to store the overflow or
    // carry results
    output_flag = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], output_flag, num_radix_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    if (requested_flag == outputFlag::FLAG_OVERFLOW) {
      last_lhs = new CudaRadixCiphertextFFI;
      last_rhs = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], last_lhs, 1, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], last_rhs, 1, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);

      // For step 1 overflow should be enable only if flag overflow
      uint32_t num_bits_in_message = std::log2(message_modulus);
      lut_overflow_flag_prep =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   1, allocate_gpu_memory, size_tracker);

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
          streams[0], gpu_indexes[0], lut_overflow_flag_prep->get_lut(0, 0),
          lut_overflow_flag_prep->get_degree(0),
          lut_overflow_flag_prep->get_max_degree(0), glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_overflow_fp,
          gpu_memory_allocated);

      lut_overflow_flag_prep->broadcast_lut(streams, gpu_indexes, 0);
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
          streams[0], gpu_indexes[0], lut_message_extract->get_lut(0, 1),
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
          (num_radix_blocks + 1) * sizeof(Torus), streams[0], gpu_indexes[0],
          allocate_gpu_memory);

      lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);
    }
    if (requested_flag == outputFlag::FLAG_CARRY) { // Carry case

      auto f_carry_last = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut_message_extract->get_lut(0, 1),
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
          (num_radix_blocks + 1) * sizeof(Torus), streams[0], gpu_indexes[0],
          allocate_gpu_memory);

      lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);
    }
  };

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    shifted_blocks_state_mem->release(streams, gpu_indexes, gpu_count);
    prop_simu_group_carries_mem->release(streams, gpu_indexes, gpu_count);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], output_flag,
                                   gpu_memory_allocated);
    lut_message_extract->release(streams, gpu_indexes, gpu_count);
    delete shifted_blocks_state_mem;
    delete prop_simu_group_carries_mem;
    delete output_flag;
    delete lut_message_extract;

    if (requested_flag == outputFlag::FLAG_OVERFLOW) { // In case of overflow
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], last_lhs,
                                     gpu_memory_allocated);
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], last_rhs,
                                     gpu_memory_allocated);
      lut_overflow_flag_prep->release(streams, gpu_indexes, gpu_count);
      delete lut_overflow_flag_prep;
      delete last_lhs;
      delete last_rhs;
    }
  };
};

template <typename Torus> struct int_shifted_blocks_and_borrow_states_memory {
  CudaRadixCiphertextFFI *shifted_blocks_and_borrow_states;
  CudaRadixCiphertextFFI *shifted_blocks;
  CudaRadixCiphertextFFI *borrow_states;

  int_radix_lut<Torus> *luts_array_first_step;
  bool gpu_memory_allocated;

  int_shifted_blocks_and_borrow_states_memory(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t num_many_lut, uint32_t grouping_size, bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    gpu_memory_allocated = allocate_gpu_memory;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    shifted_blocks_and_borrow_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], shifted_blocks_and_borrow_states,
        num_radix_blocks * num_many_lut, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    shifted_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], shifted_blocks, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    borrow_states = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], borrow_states, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    uint32_t num_luts_first_step = 2 * grouping_size + 1;

    luts_array_first_step = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, num_luts_first_step,
        num_radix_blocks, num_many_lut, allocate_gpu_memory, size_tracker);

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
        streams[0], gpu_indexes[0], first_block_lut, first_block_lut_degrees,
        first_block_lut_max_degree, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_first_grouping_luts,
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
          streams[0], gpu_indexes[0], lut, lut_degrees, lut_max_degree,
          glwe_dimension, polynomial_size, message_modulus, carry_modulus,
          f_grouping_luts, gpu_memory_allocated);
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
          streams[0], gpu_indexes[0], lut, lut_degrees, lut_max_degree,
          glwe_dimension, polynomial_size, message_modulus, carry_modulus,
          f_grouping_luts, gpu_memory_allocated);
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
        streams[0], gpu_indexes[0], last_block_lut, last_block_lut_degrees,
        last_block_lut_max_degree, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_last_grouping_luts,
        gpu_memory_allocated);

    // Generate the indexes to switch between luts within the pbs
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
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
        lut_indexes, h_lut_indexes, lut_indexes_size, streams[0],
        gpu_indexes[0], allocate_gpu_memory);
    // Do I need to do something else for the multi-gpu?

    luts_array_first_step->broadcast_lut(streams, gpu_indexes, 0);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes, Torus *new_lut_indexes,
                          uint32_t new_num_blocks) {
    Torus *lut_indexes = luts_array_first_step->get_lut_indexes(0, 0);
    cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
        lut_indexes, new_lut_indexes, new_num_blocks * sizeof(Torus),
        streams[0], gpu_indexes[0], gpu_memory_allocated);
    luts_array_first_step->broadcast_lut(streams, gpu_indexes, 0);
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   shifted_blocks_and_borrow_states,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], shifted_blocks,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], borrow_states,
                                   gpu_memory_allocated);

    luts_array_first_step->release(streams, gpu_indexes, gpu_count);
    delete luts_array_first_step;
    delete shifted_blocks_and_borrow_states;
    delete shifted_blocks;
    delete borrow_states;
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

  uint32_t active_gpu_count;
  cudaStream_t *sub_streams_1;
  cudaStream_t *sub_streams_2;

  cudaEvent_t *incoming_events;
  cudaEvent_t *outgoing_events1;
  cudaEvent_t *outgoing_events2;

  uint32_t compute_overflow;
  bool gpu_memory_allocated;
  int_borrow_prop_memory(cudaStream_t const *streams,
                         uint32_t const *gpu_indexes, uint32_t gpu_count,
                         int_radix_params params, uint32_t num_radix_blocks,
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
            streams, gpu_indexes, gpu_count, params, num_radix_blocks,
            num_many_lut, grouping_size, allocate_gpu_memory, size_tracker);

    prop_simu_group_carries_mem = new int_prop_simu_group_carries_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        grouping_size, num_groups, allocate_gpu_memory, size_tracker);

    overflow_block = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], overflow_block, 1, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    lut_message_extract = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
        allocate_gpu_memory, size_tracker);
    // lut for the first block in the first grouping
    auto f_message_extract = [message_modulus](Torus block) -> Torus {
      return (block >> 1) % message_modulus;
    };

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_message_extract->get_lut(0, 0),
        lut_message_extract->get_degree(0),
        lut_message_extract->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_message_extract,
        gpu_memory_allocated);

    lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);

    if (compute_overflow) {
      lut_borrow_flag = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
          allocate_gpu_memory, size_tracker);
      // lut for the first block in the first grouping
      auto f_borrow_flag = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut_borrow_flag->get_lut(0, 0),
          lut_borrow_flag->get_degree(0), lut_borrow_flag->get_max_degree(0),
          glwe_dimension, polynomial_size, message_modulus, carry_modulus,
          f_borrow_flag, gpu_memory_allocated);

      lut_borrow_flag->broadcast_lut(streams, gpu_indexes, 0);
    }

    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
    sub_streams_1 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    sub_streams_2 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    for (uint j = 0; j < active_gpu_count; j++) {
      sub_streams_1[j] = cuda_create_stream(gpu_indexes[j]);
      sub_streams_2[j] = cuda_create_stream(gpu_indexes[j]);
    }

    incoming_events =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    outgoing_events1 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    outgoing_events2 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    for (uint j = 0; j < active_gpu_count; j++) {
      incoming_events[j] = cuda_create_event(gpu_indexes[j]);
      outgoing_events1[j] = cuda_create_event(gpu_indexes[j]);
      outgoing_events2[j] = cuda_create_event(gpu_indexes[j]);
    }
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes,
                          Torus *first_indexes_for_div,
                          Torus *second_indexes_for_div, Torus *scalars_for_div,
                          uint32_t new_num_blocks) {
    shifted_blocks_borrow_state_mem->update_lut_indexes(
        streams, gpu_indexes, first_indexes_for_div, new_num_blocks);
    prop_simu_group_carries_mem->update_lut_indexes(
        streams, gpu_indexes, second_indexes_for_div, scalars_for_div,
        new_num_blocks);
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    shifted_blocks_borrow_state_mem->release(streams, gpu_indexes, gpu_count);
    prop_simu_group_carries_mem->release(streams, gpu_indexes, gpu_count);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], overflow_block,
                                   gpu_memory_allocated);

    lut_message_extract->release(streams, gpu_indexes, gpu_count);
    delete lut_message_extract;
    delete overflow_block;
    if (compute_overflow) {
      lut_borrow_flag->release(streams, gpu_indexes, gpu_count);
      delete lut_borrow_flag;
    }

    // The substreams have to be synchronized before destroying events
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    // release events
    for (uint j = 0; j < active_gpu_count; j++) {
      cuda_event_destroy(incoming_events[j], gpu_indexes[j]);
      cuda_event_destroy(outgoing_events1[j], gpu_indexes[j]);
      cuda_event_destroy(outgoing_events2[j], gpu_indexes[j]);
    }
    free(incoming_events);
    free(outgoing_events1);
    free(outgoing_events2);

    // release sub streams
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_destroy_stream(sub_streams_1[i], gpu_indexes[i]);
      cuda_destroy_stream(sub_streams_2[i], gpu_indexes[i]);
    }
    free(sub_streams_1);
    free(sub_streams_2);
  };
};

template <typename Torus> struct int_zero_out_if_buffer {

  int_radix_params params;

  CudaRadixCiphertextFFI *tmp;

  cudaStream_t *true_streams;
  cudaStream_t *false_streams;
  uint32_t active_gpu_count;
  bool gpu_memory_allocated;

  int_zero_out_if_buffer(cudaStream_t const *streams,
                         uint32_t const *gpu_indexes, uint32_t gpu_count,
                         int_radix_params params, uint32_t num_radix_blocks,
                         bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);

    tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    // We may use a different stream to allow concurrent operation
    true_streams =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    false_streams =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    for (uint j = 0; j < active_gpu_count; j++) {
      true_streams[j] = cuda_create_stream(gpu_indexes[j]);
      false_streams[j] = cuda_create_stream(gpu_indexes[j]);
    }
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp,
                                   gpu_memory_allocated);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    delete tmp;
    for (uint j = 0; j < active_gpu_count; j++) {
      cuda_destroy_stream(true_streams[j], gpu_indexes[j]);
      cuda_destroy_stream(false_streams[j], gpu_indexes[j]);
    }
    free(true_streams);
    free(false_streams);
  }
};

template <typename Torus> struct int_mul_memory {
  CudaRadixCiphertextFFI *vector_result_sb;
  CudaRadixCiphertextFFI *block_mul_res;
  CudaRadixCiphertextFFI *small_lwe_vector;

  int_radix_lut<Torus> *luts_array; // lsb msb
  int_radix_lut<Torus> *zero_out_predicate_lut;

  int_sum_ciphertexts_vec_memory<Torus> *sum_ciphertexts_mem;
  int_sc_prop_memory<Torus> *sc_prop_mem;
  int_zero_out_if_buffer<Torus> *zero_out_mem;

  int_radix_params params;
  bool boolean_mul = false;
  bool gpu_memory_allocated;

  int_mul_memory(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                 uint32_t gpu_count, int_radix_params params,
                 bool const is_boolean_left, bool const is_boolean_right,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory,
                 uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->boolean_mul = is_boolean_left || is_boolean_right;
    this->params = params;

    if (boolean_mul) {
      auto zero_out_predicate_lut_f = [](Torus block,
                                         Torus condition) -> Torus {
        if (condition == 0)
          return 0;
        else
          return block;
      };
      zero_out_predicate_lut = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
          allocate_gpu_memory, size_tracker);
      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], zero_out_predicate_lut->get_lut(0, 0),
          zero_out_predicate_lut->get_degree(0),
          zero_out_predicate_lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          zero_out_predicate_lut_f, gpu_memory_allocated);
      zero_out_predicate_lut->broadcast_lut(streams, gpu_indexes, 0);

      zero_out_mem = new int_zero_out_if_buffer<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks,
          allocate_gpu_memory, size_tracker);

      return;
    }

    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    // 'vector_result_lsb' contains blocks from all possible shifts of
    // radix_lwe_left excluding zero ciphertext blocks
    int lsb_vector_block_count = num_radix_blocks * (num_radix_blocks + 1) / 2;

    // 'vector_result_msb' contains blocks from all possible shifts of
    // radix_lwe_left except the last blocks of each shift
    int msb_vector_block_count = num_radix_blocks * (num_radix_blocks - 1) / 2;

    int total_block_count = num_radix_blocks * num_radix_blocks;

    // allocate memory for intermediate buffers
    vector_result_sb = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], vector_result_sb, 2 * total_block_count,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    block_mul_res = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], block_mul_res, 2 * total_block_count,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], small_lwe_vector, 2 * total_block_count,
        params.small_lwe_dimension, size_tracker, allocate_gpu_memory);

    // create int_radix_lut objects for lsb, msb, message, carry
    // luts_array -> lut = {lsb_acc, msb_acc}
    luts_array = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                          params, 2, total_block_count,
                                          allocate_gpu_memory, size_tracker);
    auto lsb_acc = luts_array->get_lut(0, 0);
    auto msb_acc = luts_array->get_lut(0, 1);

    // define functions for each accumulator
    auto lut_f_lsb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) % message_modulus;
    };
    auto lut_f_msb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) / message_modulus;
    };

    // generate accumulators
    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], lsb_acc, luts_array->get_degree(0),
        luts_array->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, lut_f_lsb, gpu_memory_allocated);
    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], msb_acc, luts_array->get_degree(1),
        luts_array->get_max_degree(1), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, lut_f_msb, gpu_memory_allocated);

    // lut_indexes_vec for luts_array should be reinitialized
    // first lsb_vector_block_count value should reference to lsb_acc
    // last msb_vector_block_count values should reference to msb_acc
    // for message and carry default lut_indexes_vec is fine
    if (allocate_gpu_memory)
      cuda_set_value_async<Torus>(
          streams[0], gpu_indexes[0],
          luts_array->get_lut_indexes(0, lsb_vector_block_count), 1,
          msb_vector_block_count);

    luts_array->broadcast_lut(streams, gpu_indexes, 0);
    // create memory object for sum ciphertexts
    sum_ciphertexts_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        2 * num_radix_blocks, vector_result_sb, small_lwe_vector, luts_array,
        true, allocate_gpu_memory, size_tracker);
    uint32_t uses_carry = 0;
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        requested_flag, uses_carry, allocate_gpu_memory, size_tracker);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    if (boolean_mul) {
      zero_out_predicate_lut->release(streams, gpu_indexes, gpu_count);
      zero_out_mem->release(streams, gpu_indexes, gpu_count);
      delete zero_out_mem;
      delete zero_out_predicate_lut;

      return;
    }
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], vector_result_sb,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], block_mul_res,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], small_lwe_vector,
                                   gpu_memory_allocated);

    luts_array->release(streams, gpu_indexes, gpu_count);
    sum_ciphertexts_mem->release(streams, gpu_indexes, gpu_count);
    sc_prop_mem->release(streams, gpu_indexes, gpu_count);

    delete vector_result_sb;
    delete block_mul_res;
    delete small_lwe_vector;
    delete luts_array;
    delete sum_ciphertexts_mem;
    delete sc_prop_mem;
  }
};

template <typename Torus> struct int_logical_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  CudaRadixCiphertextFFI *tmp_rotated;

  bool reuse_memory = false;
  bool gpu_memory_allocated;

  int_logical_scalar_shift_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, SHIFT_OR_ROTATE_TYPE shift_type,
      int_radix_params params, uint32_t num_radix_blocks,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->shift_type = shift_type;
    this->params = params;

    uint32_t max_amount_of_pbs = num_radix_blocks;

    tmp_rotated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_rotated, max_amount_of_pbs + 2,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

    // LUT
    // pregenerate lut vector and indexes
    // lut for left shift
    // here we generate 'num_bits_in_block' times lut
    // one for each 'shift_within_block' = 'shift' % 'num_bits_in_block'
    // even though lut_left contains 'num_bits_in_block' lut
    // lut_indexes_vec will have indexes for single lut only and those indexes
    // will be 0 it means for pbs corresponding lut should be selected and
    // pass along lut_indexes_vec filled with zeros

    // calculate bivariate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto cur_lut_bivariate = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
          allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus, Torus)> shift_lut_f;

      if (shift_type == LEFT_SHIFT) {
        shift_lut_f = [shift_within_block, params](
                          Torus current_block, Torus previous_block) -> Torus {
          current_block = current_block << shift_within_block;
          previous_block = previous_block << shift_within_block;

          Torus message_of_current_block =
              current_block % params.message_modulus;
          Torus carry_of_previous_block =
              previous_block / params.message_modulus;
          return message_of_current_block + carry_of_previous_block;
        };
      } else {
        shift_lut_f = [num_bits_in_block, shift_within_block,
                       params](Torus current_block, Torus next_block) -> Torus {
          // left shift so as not to lose
          // bits when shifting right afterwards
          next_block <<= num_bits_in_block;
          next_block >>= shift_within_block;

          // The way of getting carry / message is reversed compared
          // to the usual way but its normal:
          // The message is in the upper bits, the carry in lower bits
          Torus message_of_current_block = current_block >> shift_within_block;
          Torus carry_of_previous_block = next_block % params.message_modulus;

          return message_of_current_block + carry_of_previous_block;
        };
      }

      // right shift
      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], cur_lut_bivariate->get_lut(0, 0),
          cur_lut_bivariate->get_degree(0),
          cur_lut_bivariate->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          shift_lut_f, gpu_memory_allocated);
      cur_lut_bivariate->broadcast_lut(streams, gpu_indexes, 0);

      lut_buffers_bivariate.push_back(cur_lut_bivariate);
    }
  }

  int_logical_scalar_shift_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, SHIFT_OR_ROTATE_TYPE shift_type,
      int_radix_params params, uint32_t num_radix_blocks,
      bool allocate_gpu_memory, CudaRadixCiphertextFFI *pre_allocated_buffer,
      uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->shift_type = shift_type;
    this->params = params;
    tmp_rotated = pre_allocated_buffer;
    reuse_memory = true;

    if (allocate_gpu_memory)
      set_zero_radix_ciphertext_slice_async<Torus>(
          streams[0], gpu_indexes[0], tmp_rotated, 0,
          tmp_rotated->num_radix_blocks);

    uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

    // LUT
    // pregenerate lut vector and indexes
    // lut for left shift
    // here we generate 'num_bits_in_block' times lut
    // one for each 'shift_within_block' = 'shift' % 'num_bits_in_block'
    // even though lut_left contains 'num_bits_in_block' lut
    // lut_indexes_vec will have indexes for single lut only and those indexes
    // will be 0 it means for pbs corresponding lut should be selected and
    // pass along lut_indexes_vec filled with zeros

    // calculate bivariate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto cur_lut_bivariate = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
          allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus, Torus)> shift_lut_f;

      if (shift_type == LEFT_SHIFT) {
        shift_lut_f = [shift_within_block, params](
                          Torus current_block, Torus previous_block) -> Torus {
          current_block = current_block << shift_within_block;
          previous_block = previous_block << shift_within_block;

          Torus message_of_current_block =
              current_block % params.message_modulus;
          Torus carry_of_previous_block =
              previous_block / params.message_modulus;
          return message_of_current_block + carry_of_previous_block;
        };
      } else {
        shift_lut_f = [num_bits_in_block, shift_within_block,
                       params](Torus current_block, Torus next_block) -> Torus {
          // left shift so as not to lose
          // bits when shifting right afterwards
          next_block <<= num_bits_in_block;
          next_block >>= shift_within_block;

          // The way of getting carry / message is reversed compared
          // to the usual way but its normal:
          // The message is in the upper bits, the carry in lower bits
          Torus message_of_current_block = current_block >> shift_within_block;
          Torus carry_of_previous_block = next_block % params.message_modulus;

          return message_of_current_block + carry_of_previous_block;
        };
      }

      // right shift
      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], cur_lut_bivariate->get_lut(0, 0),
          cur_lut_bivariate->get_degree(0),
          cur_lut_bivariate->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          shift_lut_f, gpu_memory_allocated);
      cur_lut_bivariate->broadcast_lut(streams, gpu_indexes, 0);

      lut_buffers_bivariate.push_back(cur_lut_bivariate);
    }
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    for (auto &buffer : lut_buffers_bivariate) {
      buffer->release(streams, gpu_indexes, gpu_count);
      delete buffer;
    }
    lut_buffers_bivariate.clear();

    if (!reuse_memory) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_rotated,
                                     gpu_memory_allocated);
      cuda_synchronize_stream(streams[0], gpu_indexes[0]);
      delete tmp_rotated;
    }
  }
};

template <typename Torus> struct int_arithmetic_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_univariate;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  CudaRadixCiphertextFFI *tmp_rotated;

  cudaStream_t *local_streams_1;
  cudaStream_t *local_streams_2;
  uint32_t active_gpu_count;
  bool gpu_memory_allocated;

  int_arithmetic_scalar_shift_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, SHIFT_OR_ROTATE_TYPE shift_type,
      int_radix_params params, uint32_t num_radix_blocks,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    active_gpu_count = get_active_gpu_count(1, gpu_count);
    // In the arithmetic shift, a PBS has to be applied to the last rotated
    // block twice: once to shift it, once to compute the padding block to be
    // copied onto all blocks to the left of the last rotated block
    local_streams_1 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    local_streams_2 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    for (uint j = 0; j < active_gpu_count; j++) {
      local_streams_1[j] = cuda_create_stream(gpu_indexes[j]);
      local_streams_2[j] = cuda_create_stream(gpu_indexes[j]);
    }
    this->shift_type = shift_type;
    this->params = params;

    tmp_rotated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_rotated, num_radix_blocks + 3,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

    // LUT
    // pregenerate lut vector and indexes lut

    // lut to shift the last block
    // calculate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    // With two bits of message this is actually only one LUT.
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto shift_last_block_lut_univariate =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   1, allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus)> last_block_lut_f;
      last_block_lut_f = [num_bits_in_block, shift_within_block,
                          params](Torus x) -> Torus {
        x = x % params.message_modulus;
        uint32_t x_sign_bit = x >> (num_bits_in_block - 1) & 1;
        uint32_t shifted = x >> shift_within_block;
        // padding is a message full of 1 if sign bit is one
        // else padding is a zero message
        uint32_t padding = (params.message_modulus - 1) * x_sign_bit;

        // Make padding have 1s only in places where bits
        // where actually need to be padded
        padding <<= num_bits_in_block - shift_within_block;
        padding %= params.message_modulus;

        return shifted | padding;
      };

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0],
          shift_last_block_lut_univariate->get_lut(0, 0),
          shift_last_block_lut_univariate->get_degree(0),
          shift_last_block_lut_univariate->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, last_block_lut_f, gpu_memory_allocated);
      shift_last_block_lut_univariate->broadcast_lut(streams, gpu_indexes, 0);

      lut_buffers_univariate.push_back(shift_last_block_lut_univariate);
    }

    auto padding_block_lut_univariate =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1, 1,
                                 allocate_gpu_memory, size_tracker);

    // lut to compute the padding block
    std::function<Torus(Torus)> padding_block_lut_f;
    padding_block_lut_f = [num_bits_in_block, params](Torus x) -> Torus {
      x = x % params.message_modulus;
      uint32_t x_sign_bit = x >> (num_bits_in_block - 1) & 1;
      // padding is a message full of 1 if sign bit is one
      // else padding is a zero message
      return (params.message_modulus - 1) * x_sign_bit;
    };

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], padding_block_lut_univariate->get_lut(0, 0),
        padding_block_lut_univariate->get_degree(0),
        padding_block_lut_univariate->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        padding_block_lut_f, gpu_memory_allocated);
    padding_block_lut_univariate->broadcast_lut(streams, gpu_indexes, 0);

    lut_buffers_univariate.push_back(padding_block_lut_univariate);

    // lut to shift the first blocks
    // calculate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    // NB: with two bits of message, this is actually only one LUT.
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto shift_blocks_lut_bivariate = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
          allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus, Torus)> blocks_lut_f;
      blocks_lut_f = [num_bits_in_block, shift_within_block,
                      params](Torus current_block, Torus next_block) -> Torus {
        // left shift so as not to lose
        // bits when shifting right after
        next_block <<= num_bits_in_block;
        next_block >>= shift_within_block;

        // The way of getting carry / message is reversed compared
        // to the usual way but its normal:
        // The message is in the upper bits, the carry in lower bits
        uint32_t message_of_current_block = current_block >> shift_within_block;
        uint32_t carry_of_previous_block = next_block % params.message_modulus;

        return message_of_current_block + carry_of_previous_block;
      };

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], shift_blocks_lut_bivariate->get_lut(0, 0),
          shift_blocks_lut_bivariate->get_degree(0),
          shift_blocks_lut_bivariate->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          blocks_lut_f, gpu_memory_allocated);
      shift_blocks_lut_bivariate->broadcast_lut(streams, gpu_indexes, 0);

      lut_buffers_bivariate.push_back(shift_blocks_lut_bivariate);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    for (uint j = 0; j < active_gpu_count; j++) {
      cuda_destroy_stream(local_streams_1[j], gpu_indexes[j]);
      cuda_destroy_stream(local_streams_2[j], gpu_indexes[j]);
    }
    free(local_streams_1);
    free(local_streams_2);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_rotated,
                                   gpu_memory_allocated);
    for (auto &buffer : lut_buffers_bivariate) {
      buffer->release(streams, gpu_indexes, gpu_count);
      delete buffer;
    }
    for (auto &buffer : lut_buffers_univariate) {
      buffer->release(streams, gpu_indexes, gpu_count);
      delete buffer;
    }
    lut_buffers_bivariate.clear();
    lut_buffers_univariate.clear();

    delete tmp_rotated;
  }
};

template <typename Torus> struct int_cmux_buffer {
  int_radix_lut<Torus> *predicate_lut;
  int_radix_lut<Torus> *message_extract_lut;

  CudaRadixCiphertextFFI *buffer_in;
  CudaRadixCiphertextFFI *buffer_out;
  CudaRadixCiphertextFFI *condition_array;

  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  int_cmux_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                  uint32_t gpu_count,
                  std::function<Torus(Torus)> predicate_lut_f,
                  int_radix_params params, uint32_t num_radix_blocks,
                  bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    buffer_in = new CudaRadixCiphertextFFI;
    buffer_out = new CudaRadixCiphertextFFI;
    condition_array = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], buffer_in, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], buffer_out, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], condition_array, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    auto lut_f = [predicate_lut_f](Torus block, Torus condition) -> Torus {
      return predicate_lut_f(condition) ? 0 : block;
    };
    auto inverted_lut_f = [predicate_lut_f](Torus block,
                                            Torus condition) -> Torus {
      return predicate_lut_f(condition) ? block : 0;
    };
    auto message_extract_lut_f = [params](Torus x) -> Torus {
      return x % params.message_modulus;
    };

    predicate_lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                             params, 2, 2 * num_radix_blocks,
                                             allocate_gpu_memory, size_tracker);

    message_extract_lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], predicate_lut->get_lut(0, 0),
        predicate_lut->get_degree(0), predicate_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, inverted_lut_f, gpu_memory_allocated);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], predicate_lut->get_lut(0, 1),
        predicate_lut->get_degree(1), predicate_lut->get_max_degree(1),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, lut_f, gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], message_extract_lut->get_lut(0, 0),
        message_extract_lut->get_degree(0),
        message_extract_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        message_extract_lut_f, gpu_memory_allocated);
    Torus *h_lut_indexes = predicate_lut->h_lut_indexes;
    for (int index = 0; index < 2 * num_radix_blocks; index++) {
      if (index < num_radix_blocks) {
        h_lut_indexes[index] = 0;
      } else {
        h_lut_indexes[index] = 1;
      }
    }
    cuda_memcpy_with_size_tracking_async_to_gpu(
        predicate_lut->get_lut_indexes(0, 0), h_lut_indexes,
        2 * num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0],
        allocate_gpu_memory);

    predicate_lut->broadcast_lut(streams, gpu_indexes, 0);
    message_extract_lut->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    predicate_lut->release(streams, gpu_indexes, gpu_count);
    delete predicate_lut;
    message_extract_lut->release(streams, gpu_indexes, gpu_count);
    delete message_extract_lut;

    release_radix_ciphertext_async(streams[0], gpu_indexes[0], buffer_in,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], buffer_out,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], condition_array,
                                   gpu_memory_allocated);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    delete buffer_in;
    delete buffer_out;
    delete condition_array;
  }
};

template <typename Torus> struct int_are_all_block_true_buffer {
  COMPARISON_TYPE op;
  int_radix_params params;

  CudaRadixCiphertextFFI *tmp_out;
  CudaRadixCiphertextFFI *tmp_block_accumulated;

  // This map store LUTs that checks the equality between some input and values
  // of interest in are_all_block_true(), as with max_value (the maximum message
  // value).
  int_radix_lut<Torus> *is_max_value;
  bool gpu_memory_allocated;

  int_are_all_block_true_buffer(cudaStream_t const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                COMPARISON_TYPE op, int_radix_params params,
                                uint32_t num_radix_blocks,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->op = op;

    Torus total_modulus = params.message_modulus * params.carry_modulus;
    uint32_t max_value = (total_modulus - 1) / (params.message_modulus - 1);

    int max_chunks = (num_radix_blocks + max_value - 1) / max_value;
    tmp_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_out, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_block_accumulated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_block_accumulated, max_chunks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    is_max_value =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                 max_chunks, allocate_gpu_memory, size_tracker);
    auto is_max_value_f = [max_value](Torus x) -> Torus {
      return x == max_value;
    };

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], is_max_value->get_lut(0, 0),
        is_max_value->get_degree(0), is_max_value->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, is_max_value_f, gpu_memory_allocated);

    is_max_value->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_out,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   tmp_block_accumulated, gpu_memory_allocated);
    is_max_value->release(streams, gpu_indexes, gpu_count);
    delete is_max_value;
    delete tmp_out;
    delete tmp_block_accumulated;
  }
};

template <typename Torus> struct int_comparison_eq_buffer {
  int_radix_params params;
  COMPARISON_TYPE op;

  int_radix_lut<Torus> *operator_lut;
  int_radix_lut<Torus> *is_non_zero_lut;
  int_radix_lut<Torus> *scalar_comparison_luts;

  int_are_all_block_true_buffer<Torus> *are_all_block_true_buffer;
  bool gpu_memory_allocated;

  int_comparison_eq_buffer(cudaStream_t const *streams,
                           uint32_t const *gpu_indexes, uint32_t gpu_count,
                           COMPARISON_TYPE op, int_radix_params params,
                           uint32_t num_radix_blocks, bool allocate_gpu_memory,
                           uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->op = op;

    are_all_block_true_buffer = new int_are_all_block_true_buffer<Torus>(
        streams, gpu_indexes, gpu_count, op, params, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    // Operator LUT
    auto operator_f = [op](Torus lhs, Torus rhs) -> Torus {
      if (op == COMPARISON_TYPE::EQ) {
        // EQ
        return (lhs == rhs);
      } else {
        // NE
        return (lhs != rhs);
      }
    };
    operator_lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                            params, 1, num_radix_blocks,
                                            allocate_gpu_memory, size_tracker);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], operator_lut->get_lut(0, 0),
        operator_lut->get_degree(0), operator_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, operator_f, gpu_memory_allocated);

    operator_lut->broadcast_lut(streams, gpu_indexes, 0);

    // f(x) -> x == 0
    Torus total_modulus = params.message_modulus * params.carry_modulus;
    auto is_non_zero_lut_f = [total_modulus](Torus x) -> Torus {
      return (x % total_modulus) != 0;
    };

    is_non_zero_lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], is_non_zero_lut->get_lut(0, 0),
        is_non_zero_lut->get_degree(0), is_non_zero_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, is_non_zero_lut_f, gpu_memory_allocated);

    is_non_zero_lut->broadcast_lut(streams, gpu_indexes, 0);

    // Scalar may have up to num_radix_blocks blocks
    scalar_comparison_luts = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, total_modulus,
        num_radix_blocks, allocate_gpu_memory, size_tracker);

    for (int i = 0; i < total_modulus; i++) {
      auto lut_f = [i, operator_f](Torus x) -> Torus {
        return operator_f(i, x);
      };

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], scalar_comparison_luts->get_lut(0, i),
          scalar_comparison_luts->get_degree(i),
          scalar_comparison_luts->get_max_degree(i), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          lut_f, gpu_memory_allocated);
    }

    scalar_comparison_luts->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    operator_lut->release(streams, gpu_indexes, gpu_count);
    delete operator_lut;
    is_non_zero_lut->release(streams, gpu_indexes, gpu_count);
    delete is_non_zero_lut;
    scalar_comparison_luts->release(streams, gpu_indexes, gpu_count);
    delete scalar_comparison_luts;
    are_all_block_true_buffer->release(streams, gpu_indexes, gpu_count);
    delete are_all_block_true_buffer;
  }
};

template <typename Torus> struct int_tree_sign_reduction_buffer {
  int_radix_params params;

  std::function<Torus(Torus, Torus)> block_selector_f;

  int_radix_lut<Torus> *tree_inner_leaf_lut;
  int_radix_lut<Torus> *tree_last_leaf_lut;

  int_radix_lut<Torus> *tree_last_leaf_scalar_lut;

  CudaRadixCiphertextFFI *tmp_x;
  CudaRadixCiphertextFFI *tmp_y;
  bool gpu_memory_allocated;

  int_tree_sign_reduction_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, std::function<Torus(Torus)> operator_f,
      int_radix_params params, uint32_t num_radix_blocks,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;

    Torus big_size = (params.big_lwe_dimension + 1) * sizeof(Torus);

    block_selector_f = [](Torus msb, Torus lsb) -> Torus {
      if (msb == IS_EQUAL) // EQUAL
        return lsb;
      else
        return msb;
    };

    tmp_x = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_x, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_y = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_y, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    // LUTs
    tree_inner_leaf_lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    tree_last_leaf_lut =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1, 1,
                                 allocate_gpu_memory, size_tracker);

    tree_last_leaf_scalar_lut =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1, 1,
                                 allocate_gpu_memory, size_tracker);
    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], tree_inner_leaf_lut->get_lut(0, 0),
        tree_inner_leaf_lut->get_degree(0),
        tree_inner_leaf_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        block_selector_f, gpu_memory_allocated);

    tree_inner_leaf_lut->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_x,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_y,
                                   gpu_memory_allocated);
    tree_inner_leaf_lut->release(streams, gpu_indexes, gpu_count);
    delete tree_inner_leaf_lut;
    tree_last_leaf_lut->release(streams, gpu_indexes, gpu_count);
    delete tree_last_leaf_lut;
    tree_last_leaf_scalar_lut->release(streams, gpu_indexes, gpu_count);
    delete tree_last_leaf_scalar_lut;

    delete tmp_x;
    delete tmp_y;
  }
};

template <typename Torus> struct int_comparison_diff_buffer {
  int_radix_params params;
  COMPARISON_TYPE op;

  CudaRadixCiphertextFFI *tmp_packed;

  std::function<Torus(Torus)> operator_f;

  int_tree_sign_reduction_buffer<Torus> *tree_buffer;

  CudaRadixCiphertextFFI *tmp_signs_a;
  CudaRadixCiphertextFFI *tmp_signs_b;
  int_radix_lut<Torus> *reduce_signs_lut;
  bool gpu_memory_allocated;

  int_comparison_diff_buffer(cudaStream_t const *streams,
                             uint32_t const *gpu_indexes, uint32_t gpu_count,
                             COMPARISON_TYPE op, int_radix_params params,
                             uint32_t num_radix_blocks,
                             bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->op = op;

    operator_f = [op](Torus x) -> Torus {
      switch (op) {
      case GT:
        return x == IS_SUPERIOR;
      case GE:
        return (x == IS_SUPERIOR) || (x == IS_EQUAL);
      case LT:
        return x == IS_INFERIOR;
      case LE:
        return (x == IS_INFERIOR) || (x == IS_EQUAL);
      default:
        // We don't need a default case but we need to return something
        return 42;
      }
    };

    Torus big_size = (params.big_lwe_dimension + 1) * sizeof(Torus);

    tmp_packed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_packed, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tree_buffer = new int_tree_sign_reduction_buffer<Torus>(
        streams, gpu_indexes, gpu_count, operator_f, params, num_radix_blocks,
        allocate_gpu_memory, size_tracker);
    tmp_signs_a = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_signs_a, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_signs_b = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_signs_b, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    // LUTs
    reduce_signs_lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_radix_blocks,
        allocate_gpu_memory, size_tracker);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_packed,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_signs_a,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_signs_b,
                                   gpu_memory_allocated);
    tree_buffer->release(streams, gpu_indexes, gpu_count);
    delete tree_buffer;
    reduce_signs_lut->release(streams, gpu_indexes, gpu_count);
    delete reduce_signs_lut;

    delete tmp_packed;
    delete tmp_signs_a;
    delete tmp_signs_b;
  }
};

template <typename Torus> struct int_comparison_buffer {
  COMPARISON_TYPE op;

  int_radix_params params;

  //////////////////
  int_radix_lut<Torus> *identity_lut;
  std::function<Torus(Torus)> identity_lut_f;

  int_radix_lut<Torus> *is_zero_lut;

  int_comparison_eq_buffer<Torus> *eq_buffer;
  int_comparison_diff_buffer<Torus> *diff_buffer;

  CudaRadixCiphertextFFI *tmp_block_comparisons;
  CudaRadixCiphertextFFI *tmp_lwe_array_out;
  CudaRadixCiphertextFFI *tmp_trivial_sign_block;

  // Scalar EQ / NE
  CudaRadixCiphertextFFI *tmp_packed_input;

  // Max Min
  int_cmux_buffer<Torus> *cmux_buffer;

  // Signed LUT
  int_radix_lut<Torus> *signed_lut;
  bool is_signed;

  // Used for scalar comparisons
  int_radix_lut<Torus> *signed_msb_lut;
  cudaStream_t *lsb_streams;
  cudaStream_t *msb_streams;
  uint32_t active_gpu_count;
  bool gpu_memory_allocated;

  int_comparison_buffer(cudaStream_t const *streams,
                        uint32_t const *gpu_indexes, uint32_t gpu_count,
                        COMPARISON_TYPE op, int_radix_params params,
                        uint32_t num_radix_blocks, bool is_signed,
                        bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->op = op;
    this->is_signed = is_signed;

    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);

    identity_lut_f = [](Torus x) -> Torus { return x; };

    lsb_streams =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    msb_streams =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    for (uint j = 0; j < active_gpu_count; j++) {
      lsb_streams[j] = cuda_create_stream(gpu_indexes[j]);
      msb_streams[j] = cuda_create_stream(gpu_indexes[j]);
    }

    // +1 to have space for signed comparison
    tmp_lwe_array_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_lwe_array_out, num_radix_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tmp_packed_input = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_packed_input, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    // Block comparisons
    tmp_block_comparisons = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_block_comparisons, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    // Cleaning LUT
    identity_lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                            params, 1, num_radix_blocks,
                                            allocate_gpu_memory, size_tracker);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], identity_lut->get_lut(0, 0),
        identity_lut->get_degree(0), identity_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, identity_lut_f, gpu_memory_allocated);

    identity_lut->broadcast_lut(streams, gpu_indexes, 0);

    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    auto is_zero_f = [total_modulus](Torus x) -> Torus {
      return (x % total_modulus) == 0;
    };

    is_zero_lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                           params, 1, num_radix_blocks,
                                           allocate_gpu_memory, size_tracker);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], is_zero_lut->get_lut(0, 0),
        is_zero_lut->get_degree(0), is_zero_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, is_zero_f, gpu_memory_allocated);

    is_zero_lut->broadcast_lut(streams, gpu_indexes, 0);

    switch (op) {
    case COMPARISON_TYPE::MAX:
    case COMPARISON_TYPE::MIN:
      cmux_buffer = new int_cmux_buffer<Torus>(
          streams, gpu_indexes, gpu_count,
          [op](Torus x) -> Torus {
            if (op == COMPARISON_TYPE::MAX)
              return (x == IS_SUPERIOR);
            else
              return (x == IS_INFERIOR);
          },
          params, num_radix_blocks, allocate_gpu_memory, size_tracker);
    case COMPARISON_TYPE::GT:
    case COMPARISON_TYPE::GE:
    case COMPARISON_TYPE::LT:
    case COMPARISON_TYPE::LE:
      diff_buffer = new int_comparison_diff_buffer<Torus>(
          streams, gpu_indexes, gpu_count, op, params, num_radix_blocks,
          allocate_gpu_memory, size_tracker);
    case COMPARISON_TYPE::EQ:
    case COMPARISON_TYPE::NE:
      eq_buffer = new int_comparison_eq_buffer<Torus>(
          streams, gpu_indexes, gpu_count, op, params, num_radix_blocks,
          allocate_gpu_memory, size_tracker);
      break;
    default:
      PANIC("Unsupported comparison operation.")
    }

    if (is_signed) {

      tmp_trivial_sign_block = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], tmp_trivial_sign_block, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      signed_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   1, allocate_gpu_memory, size_tracker);
      signed_msb_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   1, allocate_gpu_memory, size_tracker);

      auto message_modulus = (int)params.message_modulus;
      uint32_t sign_bit_pos = log2(message_modulus) - 1;
      std::function<Torus(Torus, Torus)> signed_lut_f =
          [sign_bit_pos](Torus x, Torus y) -> Torus {
        auto x_sign_bit = x >> sign_bit_pos;
        auto y_sign_bit = y >> sign_bit_pos;

        // The block that has its sign bit set is going
        // to be ordered as 'greater' by the cmp fn.
        // However, we are dealing with signed number,
        // so in reality, it is the smaller of the two.
        // i.e the cmp result is reversed
        if (x_sign_bit == y_sign_bit) {
          // Both have either sign bit set or unset,
          // cmp will give correct result
          if (x < y)
            return (Torus)(IS_INFERIOR);
          else if (x == y)
            return (Torus)(IS_EQUAL);
          else
            return (Torus)(IS_SUPERIOR);
        } else {
          if (x < y)
            return (Torus)(IS_SUPERIOR);
          else if (x == y)
            return (Torus)(IS_EQUAL);
          else
            return (Torus)(IS_INFERIOR);
        }
        PANIC("Cuda error: sign_lut creation failed due to wrong function.")
      };

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], signed_lut->get_lut(0, 0),
          signed_lut->get_degree(0), signed_lut->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, signed_lut_f, gpu_memory_allocated);

      signed_lut->broadcast_lut(streams, gpu_indexes, 0);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    switch (op) {
    case COMPARISON_TYPE::MAX:
    case COMPARISON_TYPE::MIN:
      cmux_buffer->release(streams, gpu_indexes, gpu_count);
      delete (cmux_buffer);
    case COMPARISON_TYPE::GT:
    case COMPARISON_TYPE::GE:
    case COMPARISON_TYPE::LT:
    case COMPARISON_TYPE::LE:
      diff_buffer->release(streams, gpu_indexes, gpu_count);
      delete (diff_buffer);
    case COMPARISON_TYPE::EQ:
    case COMPARISON_TYPE::NE:
      eq_buffer->release(streams, gpu_indexes, gpu_count);
      delete (eq_buffer);
      break;
    default:
      PANIC("Unsupported comparison operation.")
    }
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   tmp_lwe_array_out, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   tmp_block_comparisons, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_packed_input,
                                   gpu_memory_allocated);
    identity_lut->release(streams, gpu_indexes, gpu_count);
    delete identity_lut;
    is_zero_lut->release(streams, gpu_indexes, gpu_count);
    delete is_zero_lut;
    delete tmp_lwe_array_out;
    delete tmp_block_comparisons;
    delete tmp_packed_input;

    if (is_signed) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     tmp_trivial_sign_block,
                                     gpu_memory_allocated);
      signed_lut->release(streams, gpu_indexes, gpu_count);
      delete signed_lut;
      signed_msb_lut->release(streams, gpu_indexes, gpu_count);
      delete signed_msb_lut;
      delete tmp_trivial_sign_block;
    }
    for (uint j = 0; j < active_gpu_count; j++) {
      cuda_destroy_stream(lsb_streams[j], gpu_indexes[j]);
      cuda_destroy_stream(msb_streams[j], gpu_indexes[j]);
    }
    free(lsb_streams);
    free(msb_streams);
  }
};

template <typename Torus> struct unsigned_int_div_rem_memory {
  int_radix_params params;
  uint32_t active_gpu_count;

  // memory objects for other operations
  int_logical_scalar_shift_buffer<Torus> *shift_mem_1;
  int_logical_scalar_shift_buffer<Torus> *shift_mem_2;
  int_borrow_prop_memory<Torus> *overflow_sub_mem;
  int_comparison_buffer<Torus> *comparison_buffer;

  // lookup tables
  int_radix_lut<Torus> **masking_luts_1;
  int_radix_lut<Torus> **masking_luts_2;
  int_radix_lut<Torus> *message_extract_lut_1;
  int_radix_lut<Torus> *message_extract_lut_2;
  int_radix_lut<Torus> **zero_out_if_overflow_did_not_happen;
  int_radix_lut<Torus> **zero_out_if_overflow_happened;
  int_radix_lut<Torus> **merge_overflow_flags_luts;

  // sub streams
  cudaStream_t *sub_streams_1;
  cudaStream_t *sub_streams_2;
  cudaStream_t *sub_streams_3;
  cudaStream_t *sub_streams_4;

  // temporary device buffers
  CudaRadixCiphertextFFI *remainder1;
  CudaRadixCiphertextFFI *remainder2;
  CudaRadixCiphertextFFI *numerator_block_stack;
  CudaRadixCiphertextFFI *numerator_block_1;
  CudaRadixCiphertextFFI *tmp_radix;
  CudaRadixCiphertextFFI *interesting_remainder1;
  CudaRadixCiphertextFFI *interesting_remainder2;
  CudaRadixCiphertextFFI *interesting_divisor;
  CudaRadixCiphertextFFI *divisor_ms_blocks;
  CudaRadixCiphertextFFI *new_remainder;
  CudaRadixCiphertextFFI *subtraction_overflowed;
  CudaRadixCiphertextFFI *did_not_overflow;
  CudaRadixCiphertextFFI *overflow_sum;
  CudaRadixCiphertextFFI *overflow_sum_radix;
  CudaRadixCiphertextFFI *tmp_1;
  CudaRadixCiphertextFFI *at_least_one_upper_block_is_non_zero;
  CudaRadixCiphertextFFI *cleaned_merged_interesting_remainder;

  Torus **first_indexes_for_overflow_sub;
  Torus **second_indexes_for_overflow_sub;
  Torus **scalars_for_overflow_sub;
  uint32_t max_indexes_to_erase;
  bool gpu_memory_allocated;

  // allocate and initialize if needed, temporary arrays used to calculate
  // cuda integer div_rem operation
  void init_temporary_buffers(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              uint32_t num_blocks, bool allocate_gpu_memory,
                              uint64_t &size_tracker) {

    // non boolean temporary arrays, with `num_blocks` blocks
    remainder1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], remainder1, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    remainder2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], remainder2, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    numerator_block_stack = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], numerator_block_stack, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    interesting_remainder2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], interesting_remainder2, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    interesting_divisor = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], interesting_divisor, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    divisor_ms_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], divisor_ms_blocks, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    new_remainder = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], new_remainder, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    cleaned_merged_interesting_remainder = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], cleaned_merged_interesting_remainder,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    tmp_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_1, num_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    // temporary arrays used as stacks
    tmp_radix = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp_radix, num_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    interesting_remainder1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], interesting_remainder1, num_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    numerator_block_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], numerator_block_1, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    // temporary arrays for boolean blocks
    subtraction_overflowed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], subtraction_overflowed, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    did_not_overflow = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], did_not_overflow, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    overflow_sum = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], overflow_sum, 1, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);
    overflow_sum_radix = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], overflow_sum_radix, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    at_least_one_upper_block_is_non_zero = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], at_least_one_upper_block_is_non_zero, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  // initialize lookup tables for div_rem operation
  void init_lookup_tables(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes, uint32_t gpu_count,
                          uint32_t num_blocks, bool allocate_gpu_memory,
                          uint64_t &size_tracker) {
    uint32_t num_bits_in_message = 31 - __builtin_clz(params.message_modulus);

    // create and generate masking_luts_1[] and masking_lut_2[]
    // both of them are equal but because they are used in two different
    // executions in parallel we need two different pbs_buffers.
    masking_luts_1 = new int_radix_lut<Torus> *[params.message_modulus - 1];
    masking_luts_2 = new int_radix_lut<Torus> *[params.message_modulus - 1];
    for (int i = 0; i < params.message_modulus - 1; i++) {
      uint32_t shifted_mask = i;
      std::function<Torus(Torus)> lut_f_masking =
          [shifted_mask](Torus x) -> Torus { return x & shifted_mask; };

      masking_luts_1[i] =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   1, allocate_gpu_memory, size_tracker);
      masking_luts_2[i] = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, num_blocks,
          allocate_gpu_memory, size_tracker);

      int_radix_lut<Torus> *luts[2] = {masking_luts_1[i], masking_luts_2[i]};

      for (int j = 0; j < 2; j++) {
        generate_device_accumulator<Torus>(
            streams[0], gpu_indexes[0], luts[j]->get_lut(0, 0),
            luts[j]->get_degree(0), luts[j]->get_max_degree(0),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, lut_f_masking,
            gpu_memory_allocated);
        luts[j]->broadcast_lut(streams, gpu_indexes, 0);
      }
    }

    // create and generate message_extract_lut_1 and message_extract_lut_2
    // both of them are equal but because they are used in two different
    // executions in parallel we need two different pbs_buffers.
    message_extract_lut_1 =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_blocks, allocate_gpu_memory, size_tracker);
    message_extract_lut_2 =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_blocks, allocate_gpu_memory, size_tracker);

    auto message_modulus = params.message_modulus;
    auto lut_f_message_extract = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };

    int_radix_lut<Torus> *luts[2] = {message_extract_lut_1,
                                     message_extract_lut_2};
    for (int j = 0; j < 2; j++) {
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], luts[j]->get_lut(0, 0),
          luts[j]->get_degree(0), luts[j]->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, lut_f_message_extract, gpu_memory_allocated);
      luts[j]->broadcast_lut(streams, gpu_indexes, 0);
    }

    // Give name to closures to improve readability
    auto overflow_happened = [](uint64_t overflow_sum) {
      return overflow_sum != 0;
    };
    auto overflow_did_not_happen = [&overflow_happened](uint64_t overflow_sum) {
      return !overflow_happened(overflow_sum);
    };

    // create and generate zero_out_if_overflow_did_not_happen
    zero_out_if_overflow_did_not_happen = new int_radix_lut<Torus> *[2];
    zero_out_if_overflow_did_not_happen[0] =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_blocks, allocate_gpu_memory, size_tracker);
    zero_out_if_overflow_did_not_happen[1] =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_blocks, allocate_gpu_memory, size_tracker);

    auto cur_lut_f = [&](Torus block, Torus overflow_sum) -> Torus {
      if (overflow_did_not_happen(overflow_sum)) {
        return 0;
      } else {
        return block;
      }
    };

    generate_device_accumulator_bivariate_with_factor<Torus>(
        streams[0], gpu_indexes[0],
        zero_out_if_overflow_did_not_happen[0]->get_lut(0, 0),
        zero_out_if_overflow_did_not_happen[0]->get_degree(0),
        zero_out_if_overflow_did_not_happen[0]->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, cur_lut_f, params.message_modulus - 2,
        gpu_memory_allocated);
    zero_out_if_overflow_did_not_happen[0]->broadcast_lut(streams, gpu_indexes,
                                                          0);
    generate_device_accumulator_bivariate_with_factor<Torus>(
        streams[0], gpu_indexes[0],
        zero_out_if_overflow_did_not_happen[1]->get_lut(0, 0),
        zero_out_if_overflow_did_not_happen[1]->get_degree(0),
        zero_out_if_overflow_did_not_happen[1]->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, cur_lut_f, params.message_modulus - 1,
        gpu_memory_allocated);
    zero_out_if_overflow_did_not_happen[1]->broadcast_lut(streams, gpu_indexes,
                                                          0);

    // create and generate zero_out_if_overflow_happened
    zero_out_if_overflow_happened = new int_radix_lut<Torus> *[2];
    zero_out_if_overflow_happened[0] =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_blocks, allocate_gpu_memory, size_tracker);
    zero_out_if_overflow_happened[1] =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_blocks, allocate_gpu_memory, size_tracker);

    auto overflow_happened_f = [&](Torus block, Torus overflow_sum) -> Torus {
      if (overflow_happened(overflow_sum)) {
        return 0;
      } else {
        return block;
      }
    };

    generate_device_accumulator_bivariate_with_factor<Torus>(
        streams[0], gpu_indexes[0],
        zero_out_if_overflow_happened[0]->get_lut(0, 0),
        zero_out_if_overflow_happened[0]->get_degree(0),
        zero_out_if_overflow_happened[0]->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, overflow_happened_f, params.message_modulus - 2,
        gpu_memory_allocated);
    zero_out_if_overflow_happened[0]->broadcast_lut(streams, gpu_indexes, 0);
    generate_device_accumulator_bivariate_with_factor<Torus>(
        streams[0], gpu_indexes[0],
        zero_out_if_overflow_happened[1]->get_lut(0, 0),
        zero_out_if_overflow_happened[1]->get_degree(0),
        zero_out_if_overflow_happened[1]->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, overflow_happened_f, params.message_modulus - 1,
        gpu_memory_allocated);
    zero_out_if_overflow_happened[1]->broadcast_lut(streams, gpu_indexes, 0);

    // merge_overflow_flags_luts
    merge_overflow_flags_luts = new int_radix_lut<Torus> *[num_bits_in_message];
    for (int i = 0; i < num_bits_in_message; i++) {
      auto lut_f_bit = [i](Torus x, Torus y) -> Torus {
        return (x == 0 && y == 0) << i;
      };

      merge_overflow_flags_luts[i] =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   1, allocate_gpu_memory, size_tracker);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0],
          merge_overflow_flags_luts[i]->get_lut(0, 0),
          merge_overflow_flags_luts[i]->get_degree(0),
          merge_overflow_flags_luts[i]->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, lut_f_bit, gpu_memory_allocated);
      merge_overflow_flags_luts[i]->broadcast_lut(streams, gpu_indexes, 0);
    }
  }

  unsigned_int_div_rem_memory(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              int_radix_params params, uint32_t num_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    active_gpu_count = get_active_gpu_count(2 * num_blocks, gpu_count);

    this->params = params;
    shift_mem_1 = new int_logical_scalar_shift_buffer<Torus>(
        streams, gpu_indexes, gpu_count, SHIFT_OR_ROTATE_TYPE::LEFT_SHIFT,
        params, 2 * num_blocks, allocate_gpu_memory, size_tracker);

    shift_mem_2 = new int_logical_scalar_shift_buffer<Torus>(
        streams, gpu_indexes, gpu_count, SHIFT_OR_ROTATE_TYPE::LEFT_SHIFT,
        params, 2 * num_blocks, allocate_gpu_memory, size_tracker);

    uint32_t compute_overflow = 1;
    overflow_sub_mem = new int_borrow_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_blocks, compute_overflow,
        allocate_gpu_memory, size_tracker);
    uint32_t group_size = overflow_sub_mem->group_size;
    bool use_seq = overflow_sub_mem->prop_simu_group_carries_mem
                       ->use_sequential_algorithm_to_resolve_group_carries;
    create_indexes_for_overflow_sub(streams, gpu_indexes, num_blocks,
                                    group_size, use_seq, allocate_gpu_memory,
                                    size_tracker);

    comparison_buffer = new int_comparison_buffer<Torus>(
        streams, gpu_indexes, gpu_count, COMPARISON_TYPE::NE, params,
        num_blocks, false, allocate_gpu_memory, size_tracker);

    init_lookup_tables(streams, gpu_indexes, gpu_count, num_blocks,
                       allocate_gpu_memory, size_tracker);
    init_temporary_buffers(streams, gpu_indexes, gpu_count, num_blocks,
                           allocate_gpu_memory, size_tracker);

    sub_streams_1 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    sub_streams_2 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    sub_streams_3 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    sub_streams_4 =
        (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
    for (uint j = 0; j < active_gpu_count; j++) {
      sub_streams_1[j] = cuda_create_stream(gpu_indexes[j]);
      sub_streams_2[j] = cuda_create_stream(gpu_indexes[j]);
      sub_streams_3[j] = cuda_create_stream(gpu_indexes[j]);
      sub_streams_4[j] = cuda_create_stream(gpu_indexes[j]);
    }
  }

  void create_indexes_for_overflow_sub(cudaStream_t const *streams,
                                       uint32_t const *gpu_indexes,
                                       uint32_t num_blocks, uint32_t group_size,
                                       bool use_seq, bool allocate_gpu_memory,
                                       uint64_t &size_tracker) {
    max_indexes_to_erase = num_blocks;

    first_indexes_for_overflow_sub =
        (Torus **)malloc(num_blocks * sizeof(Torus *));
    second_indexes_for_overflow_sub =
        (Torus **)malloc(num_blocks * sizeof(Torus *));
    scalars_for_overflow_sub = (Torus **)malloc(num_blocks * sizeof(Torus *));

    Torus *h_lut_indexes = (Torus *)malloc(num_blocks * sizeof(Torus));
    Torus *h_scalar = (Torus *)malloc(num_blocks * sizeof(Torus));

    // Extra indexes for the luts in first step
    for (int nb = 1; nb <= num_blocks; nb++) {
      first_indexes_for_overflow_sub[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams[0], gpu_indexes[0], size_tracker,
              allocate_gpu_memory);
      for (int index = 0; index < nb; index++) {
        uint32_t grouping_index = index / group_size;
        bool is_in_first_grouping = (grouping_index == 0);
        uint32_t index_in_grouping = index % group_size;
        bool is_last_index = (index == (nb - 1));
        if (is_last_index) {
          if (nb == 1) {
            h_lut_indexes[index] = 2 * group_size;
          } else {
            h_lut_indexes[index] = 2;
          }
        } else if (is_in_first_grouping) {
          h_lut_indexes[index] = index_in_grouping;
        } else {
          h_lut_indexes[index] = index_in_grouping + group_size;
        }
      }
      cuda_memcpy_with_size_tracking_async_to_gpu(
          first_indexes_for_overflow_sub[nb - 1], h_lut_indexes,
          nb * sizeof(Torus), streams[0], gpu_indexes[0], allocate_gpu_memory);
    }
    // Extra indexes for the luts in second step
    for (int nb = 1; nb <= num_blocks; nb++) {
      second_indexes_for_overflow_sub[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams[0], gpu_indexes[0], size_tracker,
              allocate_gpu_memory);
      scalars_for_overflow_sub[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams[0], gpu_indexes[0], size_tracker,
              allocate_gpu_memory);

      for (int index = 0; index < nb; index++) {
        uint32_t grouping_index = index / group_size;
        bool is_in_first_grouping = (grouping_index == 0);
        uint32_t index_in_grouping = index % group_size;

        if (is_in_first_grouping) {
          h_lut_indexes[index] = index_in_grouping;
        } else if (index_in_grouping == (group_size - 1)) {
          if (use_seq) {
            int inner_index = (grouping_index - 1) % (group_size - 1);
            h_lut_indexes[index] = inner_index + 2 * group_size;
          } else {
            h_lut_indexes[index] = 2 * group_size;
          }
        } else {
          h_lut_indexes[index] = index_in_grouping + group_size;
        }

        bool may_have_its_padding_bit_set =
            !is_in_first_grouping && (index_in_grouping == group_size - 1);

        if (may_have_its_padding_bit_set) {
          if (use_seq) {
            h_scalar[index] = 1 << ((grouping_index - 1) % (group_size - 1));
          } else {
            h_scalar[index] = 1;
          }
        } else {
          h_scalar[index] = 0;
        }
      }
      cuda_memcpy_with_size_tracking_async_to_gpu(
          second_indexes_for_overflow_sub[nb - 1], h_lut_indexes,
          nb * sizeof(Torus), streams[0], gpu_indexes[0], allocate_gpu_memory);
      cuda_memcpy_with_size_tracking_async_to_gpu(
          scalars_for_overflow_sub[nb - 1], h_scalar, nb * sizeof(Torus),
          streams[0], gpu_indexes[0], allocate_gpu_memory);
    }
    free(h_lut_indexes);
    free(h_scalar);
  };

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    uint32_t num_bits_in_message = 31 - __builtin_clz(params.message_modulus);

    // release and delete other operation memory objects
    shift_mem_1->release(streams, gpu_indexes, gpu_count);
    shift_mem_2->release(streams, gpu_indexes, gpu_count);
    overflow_sub_mem->release(streams, gpu_indexes, gpu_count);
    comparison_buffer->release(streams, gpu_indexes, gpu_count);
    delete shift_mem_1;
    delete shift_mem_2;
    delete overflow_sub_mem;
    delete comparison_buffer;

    // drop temporary buffers
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], remainder1,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], remainder2,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   numerator_block_stack, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   numerator_block_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_radix,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   interesting_remainder1,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   interesting_remainder2,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   interesting_divisor, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   divisor_ms_blocks, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], new_remainder,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   subtraction_overflowed,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], did_not_overflow,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], overflow_sum,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   overflow_sum_radix, gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_1,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   at_least_one_upper_block_is_non_zero,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   cleaned_merged_interesting_remainder,
                                   gpu_memory_allocated);
    // release and delete lookup tables

    // masking_luts_1 and masking_luts_2
    for (int i = 0; i < params.message_modulus - 1; i++) {
      masking_luts_1[i]->release(streams, gpu_indexes, gpu_count);
      masking_luts_2[i]->release(streams, gpu_indexes, gpu_count);

      delete masking_luts_1[i];
      delete masking_luts_2[i];
    }
    delete[] masking_luts_1;
    delete[] masking_luts_2;

    // message_extract_lut_1 and message_extract_lut_2
    message_extract_lut_1->release(streams, gpu_indexes, gpu_count);
    message_extract_lut_2->release(streams, gpu_indexes, gpu_count);

    delete message_extract_lut_1;
    delete message_extract_lut_2;

    // zero_out_if_overflow_did_not_happen
    zero_out_if_overflow_did_not_happen[0]->release(streams, gpu_indexes,
                                                    gpu_count);
    zero_out_if_overflow_did_not_happen[1]->release(streams, gpu_indexes,
                                                    gpu_count);

    delete zero_out_if_overflow_did_not_happen[0];
    delete zero_out_if_overflow_did_not_happen[1];

    delete[] zero_out_if_overflow_did_not_happen;

    // zero_out_if_overflow_happened
    zero_out_if_overflow_happened[0]->release(streams, gpu_indexes, gpu_count);
    zero_out_if_overflow_happened[1]->release(streams, gpu_indexes, gpu_count);

    delete zero_out_if_overflow_happened[0];
    delete zero_out_if_overflow_happened[1];

    delete[] zero_out_if_overflow_happened;

    // merge_overflow_flags_luts
    for (int i = 0; i < num_bits_in_message; i++) {
      merge_overflow_flags_luts[i]->release(streams, gpu_indexes, gpu_count);

      delete merge_overflow_flags_luts[i];
    }
    delete[] merge_overflow_flags_luts;

    // release sub streams
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_destroy_stream(sub_streams_1[i], gpu_indexes[i]);
      cuda_destroy_stream(sub_streams_2[i], gpu_indexes[i]);
      cuda_destroy_stream(sub_streams_3[i], gpu_indexes[i]);
      cuda_destroy_stream(sub_streams_4[i], gpu_indexes[i]);
    }
    free(sub_streams_1);
    free(sub_streams_2);
    free(sub_streams_3);
    free(sub_streams_4);

    // Delete temporary buffers
    delete remainder1;
    delete remainder2;
    delete numerator_block_stack;
    delete numerator_block_1;
    delete tmp_radix;
    delete interesting_remainder1;
    delete interesting_remainder2;
    delete interesting_divisor;
    delete divisor_ms_blocks;
    delete new_remainder;
    delete subtraction_overflowed;
    delete did_not_overflow;
    delete overflow_sum;
    delete overflow_sum_radix;
    delete tmp_1;
    delete at_least_one_upper_block_is_non_zero;
    delete cleaned_merged_interesting_remainder;

    for (int i = 0; i < max_indexes_to_erase; i++) {
      cuda_drop_with_size_tracking_async(first_indexes_for_overflow_sub[i],
                                         streams[0], gpu_indexes[0],
                                         gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(second_indexes_for_overflow_sub[i],
                                         streams[0], gpu_indexes[0],
                                         gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(scalars_for_overflow_sub[i],
                                         streams[0], gpu_indexes[0],
                                         gpu_memory_allocated);
    }
    free(first_indexes_for_overflow_sub);
    free(second_indexes_for_overflow_sub);
    free(scalars_for_overflow_sub);
  }
};

template <typename Torus> struct int_bitop_buffer {

  int_radix_params params;
  int_radix_lut<Torus> *lut;
  BITOP_TYPE op;
  bool gpu_memory_allocated;

  int_bitop_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                   uint32_t gpu_count, BITOP_TYPE op, int_radix_params params,
                   uint32_t num_radix_blocks, bool allocate_gpu_memory,
                   uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->op = op;
    this->params = params;

    switch (op) {
    case BITAND:
    case BITOR:
    case BITXOR:
      lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                     num_radix_blocks, allocate_gpu_memory,
                                     size_tracker);
      {
        auto lut_bivariate_f = [op](Torus lhs, Torus rhs) -> Torus {
          if (op == BITOP_TYPE::BITAND) {
            // AND
            return lhs & rhs;
          } else if (op == BITOP_TYPE::BITOR) {
            // OR
            return lhs | rhs;
          } else {
            // XOR
            return lhs ^ rhs;
          }
        };

        generate_device_accumulator_bivariate<Torus>(
            streams[0], gpu_indexes[0], lut->get_lut(0, 0), lut->get_degree(0),
            lut->get_max_degree(0), params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, lut_bivariate_f, gpu_memory_allocated);
        lut->broadcast_lut(streams, gpu_indexes, 0);
      }
      break;
    default:
      // Scalar OP
      lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params,
                                     params.message_modulus, num_radix_blocks,
                                     allocate_gpu_memory, size_tracker);

      for (int i = 0; i < params.message_modulus; i++) {
        auto rhs = i;

        auto lut_univariate_scalar_f = [op, rhs](Torus x) -> Torus {
          if (op == BITOP_TYPE::SCALAR_BITAND) {
            // AND
            return x & rhs;
          } else if (op == BITOP_TYPE::SCALAR_BITOR) {
            // OR
            return x | rhs;
          } else {
            // XOR
            return x ^ rhs;
          }
        };
        generate_device_accumulator<Torus>(
            streams[0], gpu_indexes[0], lut->get_lut(0, i), lut->get_degree(i),
            lut->get_max_degree(i), params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, lut_univariate_scalar_f,
            gpu_memory_allocated);
        lut->broadcast_lut(streams, gpu_indexes, 0);
      }
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    lut->release(streams, gpu_indexes, gpu_count);
    delete lut;
  }
};

template <typename Torus> struct int_scalar_mul_buffer {
  int_radix_params params;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_buffer;
  int_sum_ciphertexts_vec_memory<Torus> *sum_ciphertexts_vec_mem;
  CudaRadixCiphertextFFI *preshifted_buffer;
  CudaRadixCiphertextFFI *all_shifted_buffer;
  int_sc_prop_memory<Torus> *sc_prop_mem;
  bool anticipated_buffers_drop;
  bool gpu_memory_allocated;
  uint32_t num_ciphertext_bits;

  int_scalar_mul_buffer(cudaStream_t const *streams,
                        uint32_t const *gpu_indexes, uint32_t gpu_count,
                        int_radix_params params, uint32_t num_radix_blocks,
                        uint32_t num_scalar_bits, bool allocate_gpu_memory,
                        bool anticipated_buffer_drop, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->anticipated_buffers_drop = anticipated_buffer_drop;

    uint32_t msg_bits = (uint32_t)std::log2(params.message_modulus);
    num_ciphertext_bits = msg_bits * num_scalar_bits;

    //// Contains all shifted values of lhs for shift in range (0..msg_bits)
    //// The idea is that with these we can create all other shift that are
    /// in / range (0..total_bits) for free (block rotation)
    preshifted_buffer = new CudaRadixCiphertextFFI;
    uint64_t anticipated_drop_mem = 0;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], preshifted_buffer,
        msg_bits * num_radix_blocks, params.big_lwe_dimension,
        anticipated_drop_mem, allocate_gpu_memory);

    all_shifted_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], all_shifted_buffer,
        num_ciphertext_bits * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    if (num_ciphertext_bits * num_radix_blocks >= num_radix_blocks + 2)
      logical_scalar_shift_buffer = new int_logical_scalar_shift_buffer<Torus>(
          streams, gpu_indexes, gpu_count, LEFT_SHIFT, params, num_radix_blocks,
          allocate_gpu_memory, all_shifted_buffer, anticipated_drop_mem);
    else
      logical_scalar_shift_buffer = new int_logical_scalar_shift_buffer<Torus>(
          streams, gpu_indexes, gpu_count, LEFT_SHIFT, params, num_radix_blocks,
          allocate_gpu_memory, anticipated_drop_mem);

    uint64_t last_step_mem = 0;
    if (num_ciphertext_bits > 0) {
      sum_ciphertexts_vec_mem = new int_sum_ciphertexts_vec_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks,
          num_ciphertext_bits, true, allocate_gpu_memory, last_step_mem);
    }
    uint32_t uses_carry = 0;
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        requested_flag, uses_carry, allocate_gpu_memory, last_step_mem);
    if (anticipated_buffer_drop) {
      size_tracker += std::max(anticipated_drop_mem, last_step_mem);
    } else {
      size_tracker += anticipated_drop_mem + last_step_mem;
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                   all_shifted_buffer, gpu_memory_allocated);
    if (num_ciphertext_bits > 0) {
      sum_ciphertexts_vec_mem->release(streams, gpu_indexes, gpu_count);
      delete sum_ciphertexts_vec_mem;
    }
    sc_prop_mem->release(streams, gpu_indexes, gpu_count);
    delete sc_prop_mem;
    delete all_shifted_buffer;
    if (!anticipated_buffers_drop) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     preshifted_buffer, gpu_memory_allocated);
      logical_scalar_shift_buffer->release(streams, gpu_indexes, gpu_count);
      delete logical_scalar_shift_buffer;
      delete preshifted_buffer;
    }
  }
};

template <typename Torus> struct int_abs_buffer {
  int_radix_params params;

  int_arithmetic_scalar_shift_buffer<Torus> *arithmetic_scalar_shift_mem;
  int_sc_prop_memory<Torus> *scp_mem;
  int_bitop_buffer<Torus> *bitxor_mem;

  CudaRadixCiphertextFFI *mask;
  bool allocate_gpu_memory;

  int_abs_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                 uint32_t gpu_count, int_radix_params params,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory,
                 uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    arithmetic_scalar_shift_mem = new int_arithmetic_scalar_shift_buffer<Torus>(
        streams, gpu_indexes, gpu_count, SHIFT_OR_ROTATE_TYPE::RIGHT_SHIFT,
        params, num_radix_blocks, allocate_gpu_memory, size_tracker);
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    uint32_t uses_carry = 0;
    scp_mem = new int_sc_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        requested_flag, uses_carry, allocate_gpu_memory, size_tracker);
    bitxor_mem = new int_bitop_buffer<Torus>(
        streams, gpu_indexes, gpu_count, BITOP_TYPE::BITXOR, params,
        num_radix_blocks, allocate_gpu_memory, size_tracker);

    mask = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], mask, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    arithmetic_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
    scp_mem->release(streams, gpu_indexes, gpu_count);
    bitxor_mem->release(streams, gpu_indexes, gpu_count);

    delete arithmetic_scalar_shift_mem;
    delete scp_mem;
    delete bitxor_mem;

    release_radix_ciphertext_async(streams[0], gpu_indexes[0], mask,
                                   this->allocate_gpu_memory);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    delete mask;
  }
};

template <typename Torus> struct int_div_rem_memory {
  int_radix_params params;
  uint32_t active_gpu_count;
  bool is_signed;
  // memory objects for other operations
  unsigned_int_div_rem_memory<Torus> *unsigned_mem;
  int_abs_buffer<Torus> *abs_mem_1;
  int_abs_buffer<Torus> *abs_mem_2;
  int_sc_prop_memory<Torus> *scp_mem_1;
  int_sc_prop_memory<Torus> *scp_mem_2;
  int_cmux_buffer<Torus> *cmux_quotient_mem;
  int_cmux_buffer<Torus> *cmux_remainder_mem;

  // lookup tables
  int_radix_lut<Torus> *compare_signed_bits_lut;

  // sub streams
  cudaStream_t *sub_streams_1;
  cudaStream_t *sub_streams_2;
  cudaStream_t *sub_streams_3;

  // temporary device buffers
  CudaRadixCiphertextFFI *positive_numerator;
  CudaRadixCiphertextFFI *positive_divisor;
  CudaRadixCiphertextFFI *sign_bits_are_different;
  CudaRadixCiphertextFFI *negated_quotient;
  CudaRadixCiphertextFFI *negated_remainder;
  bool gpu_memory_allocated;

  int_div_rem_memory(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                     uint32_t gpu_count, int_radix_params params,
                     bool is_signed, uint32_t num_blocks,
                     bool allocate_gpu_memory, uint64_t &size_tracker) {

    gpu_memory_allocated = allocate_gpu_memory;
    this->active_gpu_count = get_active_gpu_count(2 * num_blocks, gpu_count);
    this->params = params;
    this->is_signed = is_signed;

    unsigned_mem = new unsigned_int_div_rem_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_blocks,
        allocate_gpu_memory, size_tracker);

    if (is_signed) {
      Torus sign_bit_pos = 31 - __builtin_clz(params.message_modulus) - 1;

      // init memory objects for other integer operations
      abs_mem_1 = new int_abs_buffer<Torus>(streams, gpu_indexes, gpu_count,
                                            params, num_blocks,
                                            allocate_gpu_memory, size_tracker);
      abs_mem_2 = new int_abs_buffer<Torus>(streams, gpu_indexes, gpu_count,
                                            params, num_blocks,
                                            allocate_gpu_memory, size_tracker);
      uint32_t requested_flag = outputFlag::FLAG_NONE;
      uint32_t uses_carry = 0;
      scp_mem_1 = new int_sc_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_blocks, requested_flag,
          uses_carry, allocate_gpu_memory, size_tracker);
      scp_mem_2 = new int_sc_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_blocks, requested_flag,
          uses_carry, allocate_gpu_memory, size_tracker);

      std::function<uint64_t(uint64_t)> quotient_predicate_lut_f =
          [](uint64_t x) -> uint64_t { return x == 1; };
      std::function<uint64_t(uint64_t)> remainder_predicate_lut_f =
          [sign_bit_pos](uint64_t x) -> uint64_t {
        return (x >> sign_bit_pos) == 1;
      };

      cmux_quotient_mem = new int_cmux_buffer<Torus>(
          streams, gpu_indexes, gpu_count, quotient_predicate_lut_f, params,
          num_blocks, allocate_gpu_memory, size_tracker);
      cmux_remainder_mem = new int_cmux_buffer<Torus>(
          streams, gpu_indexes, gpu_count, remainder_predicate_lut_f, params,
          num_blocks, allocate_gpu_memory, size_tracker);
      // init temporary memory buffers
      positive_numerator = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], positive_numerator, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      positive_divisor = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], positive_divisor, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      negated_quotient = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], negated_quotient, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      negated_remainder = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], negated_remainder, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      // init boolean temporary buffers
      sign_bits_are_different = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], sign_bits_are_different, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      // init sub streams
      sub_streams_1 =
          (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
      sub_streams_2 =
          (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
      sub_streams_3 =
          (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
      for (uint j = 0; j < active_gpu_count; j++) {
        sub_streams_1[j] = cuda_create_stream(gpu_indexes[j]);
        sub_streams_2[j] = cuda_create_stream(gpu_indexes[j]);
        sub_streams_3[j] = cuda_create_stream(gpu_indexes[j]);
      }

      // init lookup tables
      //  to extract and compare signed bits
      auto f_compare_extracted_signed_bits = [sign_bit_pos](Torus x,
                                                            Torus y) -> Torus {
        Torus x_sign_bit = (x >> sign_bit_pos) & 1;
        Torus y_sign_bit = (y >> sign_bit_pos) & 1;
        return (Torus)(x_sign_bit != y_sign_bit);
      };

      compare_signed_bits_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   1, allocate_gpu_memory, size_tracker);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], compare_signed_bits_lut->get_lut(0, 0),
          compare_signed_bits_lut->get_degree(0),
          compare_signed_bits_lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          f_compare_extracted_signed_bits, gpu_memory_allocated);
      compare_signed_bits_lut->broadcast_lut(streams, gpu_indexes, 0);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    unsigned_mem->release(streams, gpu_indexes, gpu_count);
    delete unsigned_mem;

    if (is_signed) {
      // release objects for other integer operations
      abs_mem_1->release(streams, gpu_indexes, gpu_count);
      abs_mem_2->release(streams, gpu_indexes, gpu_count);
      scp_mem_1->release(streams, gpu_indexes, gpu_count);
      scp_mem_2->release(streams, gpu_indexes, gpu_count);
      cmux_quotient_mem->release(streams, gpu_indexes, gpu_count);
      cmux_remainder_mem->release(streams, gpu_indexes, gpu_count);

      delete abs_mem_1;
      delete abs_mem_2;
      delete scp_mem_1;
      delete scp_mem_2;
      delete cmux_quotient_mem;
      delete cmux_remainder_mem;

      // drop temporary buffers
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     positive_numerator, gpu_memory_allocated);
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     positive_divisor, gpu_memory_allocated);
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     sign_bits_are_different,
                                     gpu_memory_allocated);
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     negated_quotient, gpu_memory_allocated);
      release_radix_ciphertext_async(streams[0], gpu_indexes[0],
                                     negated_remainder, gpu_memory_allocated);
      // release lookup tables
      compare_signed_bits_lut->release(streams, gpu_indexes, gpu_count);
      delete compare_signed_bits_lut;

      // release sub streams
      for (uint i = 0; i < active_gpu_count; i++) {
        cuda_destroy_stream(sub_streams_1[i], gpu_indexes[i]);
        cuda_destroy_stream(sub_streams_2[i], gpu_indexes[i]);
        cuda_destroy_stream(sub_streams_3[i], gpu_indexes[i]);
      }
      free(sub_streams_1);
      free(sub_streams_2);
      free(sub_streams_3);

      // delete temporary buffers
      delete positive_numerator;
      delete positive_divisor;
      delete sign_bits_are_different;
      delete negated_quotient;
      delete negated_remainder;
    }
  }
};

template <typename Torus> struct int_scalar_mul_high_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem;

  CudaRadixCiphertextFFI *tmp;

  int_scalar_mul_high_buffer(cudaStream_t const *streams,
                             uint32_t const *gpu_indexes, uint32_t gpu_count,
                             const int_radix_params params,
                             uint32_t num_radix_blocks,
                             uint32_t num_scalar_bits,
                             const bool allocate_gpu_memory,
                             uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
        streams, gpu_indexes, gpu_count, RIGHT_SHIFT, params,
        2 * num_radix_blocks, allocate_gpu_memory, size_tracker);

    this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
        streams, gpu_indexes, gpu_count, params, 2 * num_radix_blocks,
        num_scalar_bits, allocate_gpu_memory, true, size_tracker);

    this->tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    logical_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
    delete logical_scalar_shift_mem;

    scalar_mul_mem->release(streams, gpu_indexes, gpu_count);
    delete scalar_mul_mem;

    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp,
                                   allocate_gpu_memory);
    delete tmp;
  }
};

template <typename Torus> struct int_sub_and_propagate {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *neg_rhs_array;

  int_sc_prop_memory<Torus> *sc_prop_mem;

  int_sub_and_propagate(cudaStream_t const *streams,
                        uint32_t const *gpu_indexes, uint32_t gpu_count,
                        const int_radix_params params,
                        uint32_t num_radix_blocks, uint32_t requested_flag_in,
                        bool allocate_gpu_memory, uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        requested_flag_in, (uint32_t)0, allocate_gpu_memory, size_tracker);

    this->neg_rhs_array = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], neg_rhs_array, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    sc_prop_mem->release(streams, gpu_indexes, gpu_count);
    delete sc_prop_mem;

    release_radix_ciphertext_async(streams[0], gpu_indexes[0], neg_rhs_array,
                                   allocate_gpu_memory);
    delete neg_rhs_array;
  }
};

template <typename Torus> struct int_extend_radix_with_sign_msb_buffer {

  int_radix_params params;
  bool allocate_gpu_memory;

  int_radix_lut<Torus> *lut = nullptr;

  CudaRadixCiphertextFFI *last_block = nullptr;
  CudaRadixCiphertextFFI *padding_block = nullptr;

  int_extend_radix_with_sign_msb_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, const int_radix_params params,
      uint32_t num_radix_blocks, uint32_t num_additional_blocks,
      const bool allocate_gpu_memory, uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    if (num_additional_blocks != 0) {
      this->lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count,
                                           params, 1, num_radix_blocks,
                                           allocate_gpu_memory, size_tracker);

      uint32_t bits_per_block = std::log2(params.message_modulus);
      uint32_t msg_modulus = params.message_modulus;

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut->get_lut(0, 0), lut->get_degree(0),
          lut->get_max_degree(0), params.glwe_dimension, params.polynomial_size,
          params.message_modulus, params.carry_modulus,
          [msg_modulus, bits_per_block](Torus x) {
            const auto xm = x % msg_modulus;
            const auto sign_bit = (xm >> (bits_per_block - 1)) & 1;
            return (Torus)((msg_modulus - 1) * sign_bit);
          },
          allocate_gpu_memory);

      this->last_block = new CudaRadixCiphertextFFI;

      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], last_block, 1, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);

      this->padding_block = new CudaRadixCiphertextFFI;

      create_zero_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], padding_block, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    if (lut != nullptr) {
      lut->release(streams, gpu_indexes, gpu_count);
      delete lut;
    }
    if (last_block != nullptr) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], last_block,
                                     allocate_gpu_memory);
      delete last_block;
    }
    if (padding_block != nullptr) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], padding_block,
                                     allocate_gpu_memory);
      delete padding_block;
    }
  }
};

template <typename Torus> struct int_unsigned_scalar_div_mem {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *tmp_ffi = nullptr;

  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem = nullptr;
  int_scalar_mul_high_buffer<Torus> *scalar_mul_high_mem = nullptr;
  int_sc_prop_memory<Torus> *scp_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem = nullptr;

  int_unsigned_scalar_div_mem(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              const int_radix_params params,
                              uint32_t num_radix_blocks,
                              const CudaScalarDivisorFFI *scalar_divisor_ffi,
                              const bool allocate_gpu_memory,
                              uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    if (!scalar_divisor_ffi->is_abs_divisor_one) {
      if (scalar_divisor_ffi->is_divisor_pow2) {

        logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
            streams, gpu_indexes, gpu_count, RIGHT_SHIFT, params,
            num_radix_blocks, allocate_gpu_memory, size_tracker);

      } else if (scalar_divisor_ffi->divisor_has_more_bits_than_numerator) {

        tmp_ffi = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams[0], gpu_indexes[0], tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      } else if (scalar_divisor_ffi
                     ->is_chosen_multiplier_geq_two_pow_numerator) {

        logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
            streams, gpu_indexes, gpu_count, RIGHT_SHIFT, params,
            num_radix_blocks, allocate_gpu_memory, size_tracker);
        scalar_mul_high_mem = new int_scalar_mul_high_buffer<Torus>(
            streams, gpu_indexes, gpu_count, params, num_radix_blocks,
            scalar_divisor_ffi->active_bits, allocate_gpu_memory, size_tracker);
        scp_mem = new int_sc_prop_memory<Torus>(
            streams, gpu_indexes, gpu_count, params, num_radix_blocks,
            FLAG_NONE, (uint32_t)0, allocate_gpu_memory, size_tracker);
        sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
            streams, gpu_indexes, gpu_count, params, num_radix_blocks,
            FLAG_NONE, allocate_gpu_memory, size_tracker);
        tmp_ffi = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams[0], gpu_indexes[0], tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      } else {

        logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
            streams, gpu_indexes, gpu_count, RIGHT_SHIFT, params,
            num_radix_blocks, allocate_gpu_memory, size_tracker);
        scalar_mul_high_mem = new int_scalar_mul_high_buffer<Torus>(
            streams, gpu_indexes, gpu_count, params, num_radix_blocks,
            scalar_divisor_ffi->active_bits, allocate_gpu_memory, size_tracker);
      }
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    if (logical_scalar_shift_mem != nullptr) {
      logical_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
      delete logical_scalar_shift_mem;
    }
    if (scalar_mul_high_mem != nullptr) {
      scalar_mul_high_mem->release(streams, gpu_indexes, gpu_count);
      delete scalar_mul_high_mem;
    }
    if (scp_mem != nullptr) {
      scp_mem->release(streams, gpu_indexes, gpu_count);
      delete scp_mem;
    }
    if (sub_and_propagate_mem != nullptr) {
      sub_and_propagate_mem->release(streams, gpu_indexes, gpu_count);
      delete sub_and_propagate_mem;
    }
    if (tmp_ffi != nullptr) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_ffi,
                                     allocate_gpu_memory);
      delete tmp_ffi;
    }
  }
};

template <typename Torus> struct int_signed_scalar_mul_high_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem;
  int_extend_radix_with_sign_msb_buffer<Torus> *extend_radix_mem;

  CudaRadixCiphertextFFI *tmp;

  int_signed_scalar_mul_high_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, const int_radix_params params,
      uint32_t num_radix_blocks, uint32_t num_scalar_bits,
      const bool allocate_gpu_memory, uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
        streams, gpu_indexes, gpu_count, RIGHT_SHIFT, params,
        2 * num_radix_blocks, allocate_gpu_memory, size_tracker);

    this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
        streams, gpu_indexes, gpu_count, params, 2 * num_radix_blocks,
        num_scalar_bits, allocate_gpu_memory, true, size_tracker);

    this->tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], tmp, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->extend_radix_mem = new int_extend_radix_with_sign_msb_buffer<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        num_radix_blocks, allocate_gpu_memory, size_tracker);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    logical_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
    delete logical_scalar_shift_mem;

    scalar_mul_mem->release(streams, gpu_indexes, gpu_count);
    delete scalar_mul_mem;

    release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp,
                                   allocate_gpu_memory);
    delete tmp;

    extend_radix_mem->release(streams, gpu_indexes, gpu_count);
    delete extend_radix_mem;
  }
};

template <typename Torus> struct int_signed_scalar_div_mem {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *tmp_ffi = nullptr;
  CudaRadixCiphertextFFI *xsign_ffi = nullptr;

  int_arithmetic_scalar_shift_buffer<Torus> *arithmetic_scalar_shift_mem =
      nullptr;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem = nullptr;
  int_signed_scalar_mul_high_buffer<Torus> *scalar_mul_high_mem = nullptr;
  int_sc_prop_memory<Torus> *scp_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem = nullptr;

  int_signed_scalar_div_mem(cudaStream_t const *streams,
                            uint32_t const *gpu_indexes, uint32_t gpu_count,
                            const int_radix_params params,
                            uint32_t num_radix_blocks,
                            const CudaScalarDivisorFFI *scalar_divisor_ffi,
                            const bool allocate_gpu_memory,
                            uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    if (!scalar_divisor_ffi->chosen_multiplier_has_more_bits_than_numerator) {

      if (scalar_divisor_ffi->is_abs_divisor_one &&
          scalar_divisor_ffi->is_divisor_negative) {
        tmp_ffi = new CudaRadixCiphertextFFI;

        create_zero_radix_ciphertext_async<Torus>(
            streams[0], gpu_indexes[0], tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      } else if (!scalar_divisor_ffi->is_abs_divisor_one) {

        tmp_ffi = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams[0], gpu_indexes[0], tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

        arithmetic_scalar_shift_mem =
            new int_arithmetic_scalar_shift_buffer<Torus>(
                streams, gpu_indexes, gpu_count, RIGHT_SHIFT, params,
                num_radix_blocks, allocate_gpu_memory, size_tracker);

        if (scalar_divisor_ffi->is_divisor_pow2) {

          logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
              streams, gpu_indexes, gpu_count, RIGHT_SHIFT, params,
              num_radix_blocks, allocate_gpu_memory, size_tracker);
          scp_mem = new int_sc_prop_memory<Torus>(
              streams, gpu_indexes, gpu_count, params, num_radix_blocks,
              FLAG_NONE, (uint32_t)0, allocate_gpu_memory, size_tracker);

        } else {

          xsign_ffi = new CudaRadixCiphertextFFI;
          create_zero_radix_ciphertext_async<Torus>(
              streams[0], gpu_indexes[0], xsign_ffi, num_radix_blocks,
              params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

          scalar_mul_high_mem = new int_signed_scalar_mul_high_buffer<Torus>(
              streams, gpu_indexes, gpu_count, params, num_radix_blocks,
              scalar_divisor_ffi->active_bits, allocate_gpu_memory,
              size_tracker);

          sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
              streams, gpu_indexes, gpu_count, params, num_radix_blocks,
              FLAG_NONE, allocate_gpu_memory, size_tracker);

          if (scalar_divisor_ffi->is_chosen_multiplier_geq_two_pow_numerator) {
            scp_mem = new int_sc_prop_memory<Torus>(
                streams, gpu_indexes, gpu_count, params, num_radix_blocks,
                FLAG_NONE, (uint32_t)0, allocate_gpu_memory, size_tracker);
          }
        }
      }
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    if (arithmetic_scalar_shift_mem != nullptr) {
      arithmetic_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
      delete arithmetic_scalar_shift_mem;
    }
    if (logical_scalar_shift_mem != nullptr) {
      logical_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
      delete logical_scalar_shift_mem;
    }
    if (scalar_mul_high_mem != nullptr) {
      scalar_mul_high_mem->release(streams, gpu_indexes, gpu_count);
      delete scalar_mul_high_mem;
    }
    if (scp_mem != nullptr) {
      scp_mem->release(streams, gpu_indexes, gpu_count);
      delete scp_mem;
    }
    if (sub_and_propagate_mem != nullptr) {
      sub_and_propagate_mem->release(streams, gpu_indexes, gpu_count);
      delete sub_and_propagate_mem;
    }
    if (tmp_ffi != nullptr) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], tmp_ffi,
                                     allocate_gpu_memory);
      delete tmp_ffi;
    }
    if (xsign_ffi != nullptr) {
      release_radix_ciphertext_async(streams[0], gpu_indexes[0], xsign_ffi,
                                     allocate_gpu_memory);
      delete xsign_ffi;
    }
  }
};

template <typename Torus> struct int_unsigned_scalar_div_rem_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *numerator_ct;

  int_unsigned_scalar_div_mem<Torus> *unsigned_div_mem;
  int_bitop_buffer<Torus> *bitop_mem = nullptr;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem = nullptr;

  int_unsigned_scalar_div_rem_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, const int_radix_params params,
      uint32_t num_radix_blocks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
      uint32_t const active_bits_divisor, const bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->numerator_ct = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], numerator_ct, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->unsigned_div_mem = new int_unsigned_scalar_div_mem<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        scalar_divisor_ffi, allocate_gpu_memory, size_tracker);

    if (scalar_divisor_ffi->is_divisor_pow2) {
      this->bitop_mem = new int_bitop_buffer<Torus>(
          streams, gpu_indexes, gpu_count, SCALAR_BITAND, params,
          num_radix_blocks, allocate_gpu_memory, size_tracker);
    } else {
      if (!scalar_divisor_ffi->is_divisor_zero &&
          !scalar_divisor_ffi->is_abs_divisor_one && num_radix_blocks != 0) {
        this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
            streams, gpu_indexes, gpu_count, params, num_radix_blocks,
            active_bits_divisor, allocate_gpu_memory, true, size_tracker);
      }
      this->sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks, FLAG_NONE,
          allocate_gpu_memory, size_tracker);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    release_radix_ciphertext_async(streams[0], gpu_indexes[0], numerator_ct,
                                   allocate_gpu_memory);
    delete numerator_ct;

    unsigned_div_mem->release(streams, gpu_indexes, gpu_count);
    delete unsigned_div_mem;

    if (bitop_mem != nullptr) {
      bitop_mem->release(streams, gpu_indexes, gpu_count);
      delete bitop_mem;
    }
    if (scalar_mul_mem != nullptr) {
      scalar_mul_mem->release(streams, gpu_indexes, gpu_count);
      delete scalar_mul_mem;
    }
    if (sub_and_propagate_mem != nullptr) {
      sub_and_propagate_mem->release(streams, gpu_indexes, gpu_count);
      delete sub_and_propagate_mem;
    }
  }
};

template <typename Torus> struct int_signed_scalar_div_rem_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *numerator_ct;

  int_signed_scalar_div_mem<Torus> *signed_div_mem;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem = nullptr;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem;
  int_sc_prop_memory<Torus> *scp_mem;

  int_signed_scalar_div_rem_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, const int_radix_params params,
      uint32_t num_radix_blocks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
      uint32_t const active_bits_divisor, const bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->numerator_ct = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], numerator_ct, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->signed_div_mem = new int_signed_scalar_div_mem<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        scalar_divisor_ffi, allocate_gpu_memory, size_tracker);

    this->scp_mem = new int_sc_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks, FLAG_NONE,
        (uint32_t)0, allocate_gpu_memory, size_tracker);

    bool is_divisor_one = scalar_divisor_ffi->is_abs_divisor_one &&
                          !scalar_divisor_ffi->is_divisor_negative;

    if (!scalar_divisor_ffi->is_divisor_negative &&
        scalar_divisor_ffi->is_divisor_pow2) {
      this->logical_scalar_shift_mem =
          new int_logical_scalar_shift_buffer<Torus>(
              streams, gpu_indexes, gpu_count, LEFT_SHIFT, params,
              num_radix_blocks, allocate_gpu_memory, size_tracker);

    } else if (!scalar_divisor_ffi->is_divisor_zero && !is_divisor_one &&
               num_radix_blocks != 0) {
      this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks,
          active_bits_divisor, allocate_gpu_memory, true, size_tracker);
    }

    this->sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks, FLAG_NONE,
        allocate_gpu_memory, size_tracker);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    release_radix_ciphertext_async(streams[0], gpu_indexes[0], numerator_ct,
                                   allocate_gpu_memory);
    delete numerator_ct;

    signed_div_mem->release(streams, gpu_indexes, gpu_count);
    delete signed_div_mem;

    scp_mem->release(streams, gpu_indexes, gpu_count);
    delete scp_mem;

    if (logical_scalar_shift_mem != nullptr) {
      logical_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
      delete logical_scalar_shift_mem;
    }
    if (scalar_mul_mem != nullptr) {
      scalar_mul_mem->release(streams, gpu_indexes, gpu_count);
      delete scalar_mul_mem;
    }
    sub_and_propagate_mem->release(streams, gpu_indexes, gpu_count);
    delete sub_and_propagate_mem;
  }
};

void update_degrees_after_bitand(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks);
void update_degrees_after_bitor(uint64_t *output_degrees,
                                uint64_t *lwe_array_1_degrees,
                                uint64_t *lwe_array_2_degrees,
                                uint32_t num_radix_blocks);
void update_degrees_after_bitxor(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks);
void update_degrees_after_scalar_bitand(uint64_t *output_degrees,
                                        uint64_t const *clear_degrees,
                                        uint64_t const *input_degrees,
                                        uint32_t num_clear_blocks);
void update_degrees_after_scalar_bitor(uint64_t *output_degrees,
                                       uint64_t const *clear_degrees,
                                       uint64_t const *input_degrees,
                                       uint32_t num_clear_blocks);
void update_degrees_after_scalar_bitxor(uint64_t *output_degrees,
                                        uint64_t const *clear_degrees,
                                        uint64_t const *input_degrees,
                                        uint32_t num_clear_blocks);
std::pair<bool, bool> get_invert_flags(COMPARISON_TYPE compare);
void reverseArray(uint64_t arr[], size_t n);
#endif // CUDA_INTEGER_UTILITIES_H
