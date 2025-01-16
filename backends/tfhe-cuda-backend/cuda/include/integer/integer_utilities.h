#ifndef CUDA_INTEGER_UTILITIES_H
#define CUDA_INTEGER_UTILITIES_H

#include "integer.h"
#include "integer/radix_ciphertext.cuh"
#include "integer/radix_ciphertext.h"
#include "keyswitch.h"
#include "pbs/programmable_bootstrap.cuh"
#include <cassert>
#include <cmath>
#include <functional>

template <typename Torus>
__global__ void radix_blocks_rotate_right(Torus *dst, Torus *src,
                                          uint32_t value, uint32_t blocks_count,
                                          uint32_t lwe_size);
void generate_ids_update_degrees(int *terms_degree, size_t *h_lwe_idx_in,
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
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t message_modulus,
    uint32_t carry_modulus, std::function<Torus(Torus, Torus)> f);

template <typename Torus>
void generate_device_accumulator_bivariate_with_factor(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc_bivariate,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t message_modulus,
    uint32_t carry_modulus, std::function<Torus(Torus, Torus)> f, int factor);

template <typename Torus>
void generate_device_accumulator_with_encoding(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_message_modulus, uint32_t input_carry_modulus,
    uint32_t output_message_modulus, uint32_t output_carry_modulus,
    std::function<Torus(Torus)> f);

/*
 *  generate univariate accumulator (lut) for device pointer
 *    stream - cuda stream
 *    acc - device pointer for univariate accumulator
 *    ...
 *    f - evaluating function with one Torus input
 */
template <typename Torus>
void generate_device_accumulator(cudaStream_t stream, uint32_t gpu_index,
                                 Torus *acc, uint32_t glwe_dimension,
                                 uint32_t polynomial_size,
                                 uint32_t message_modulus,
                                 uint32_t carry_modulus,
                                 std::function<Torus(Torus)> f);

template <typename Torus>
void generate_many_lut_device_accumulator(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t message_modulus,
    uint32_t carry_modulus, std::vector<std::function<Torus(Torus)>> &f);

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

  int_radix_params(){};

  int_radix_params(PBS_TYPE pbs_type, uint32_t glwe_dimension,
                   uint32_t polynomial_size, uint32_t big_lwe_dimension,
                   uint32_t small_lwe_dimension, uint32_t ks_level,
                   uint32_t ks_base_log, uint32_t pbs_level,
                   uint32_t pbs_base_log, uint32_t grouping_factor,
                   uint32_t message_modulus, uint32_t carry_modulus)
      : pbs_type(pbs_type), glwe_dimension(glwe_dimension),
        polynomial_size(polynomial_size), big_lwe_dimension(big_lwe_dimension),
        small_lwe_dimension(small_lwe_dimension), ks_level(ks_level),
        ks_base_log(ks_base_log), pbs_level(pbs_level),
        pbs_base_log(pbs_base_log), grouping_factor(grouping_factor),
        message_modulus(message_modulus), carry_modulus(carry_modulus){};

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

  int active_gpu_count;
  bool mem_reuse = false;

  // There will be one buffer on each GPU in multi-GPU computations
  // (same for tmp lwe arrays)
  std::vector<int8_t *> buffer;

  // These arrays will all reside on GPU 0
  // lut could actually be allocated & initialized GPU per GPU but this is not
  // done at the moment
  std::vector<Torus *> lut_vec;
  std::vector<Torus *> lut_indexes_vec;
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
  Torus *tmp_lwe_before_ks;

  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec;

  int_radix_lut(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                uint32_t gpu_count, int_radix_params params, uint32_t num_luts,
                uint32_t num_radix_blocks, bool allocate_gpu_memory) {

    this->params = params;
    this->num_blocks = num_radix_blocks;
    this->num_luts = num_luts;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    ///////////////
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    for (uint i = 0; i < active_gpu_count; i++) {
      cudaSetDevice(i);
      int8_t *gpu_pbs_buffer;
      auto num_blocks_on_gpu =
          get_num_inputs_on_gpu(num_radix_blocks, i, active_gpu_count);

      execute_scratch_pbs<Torus>(
          streams[i], gpu_indexes[i], &gpu_pbs_buffer, params.glwe_dimension,
          params.small_lwe_dimension, params.polynomial_size, params.pbs_level,
          params.grouping_factor, num_blocks_on_gpu, params.pbs_type,
          allocate_gpu_memory);
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      buffer.push_back(gpu_pbs_buffer);
    }

    if (allocate_gpu_memory) {
      // Allocate LUT
      // LUT is used as a trivial encryption and must be initialized outside
      // this constructor
      for (uint i = 0; i < active_gpu_count; i++) {
        auto lut = (Torus *)cuda_malloc_async(num_luts * lut_buffer_size,
                                              streams[i], gpu_indexes[i]);
        auto lut_indexes = (Torus *)cuda_malloc_async(
            lut_indexes_size, streams[i], gpu_indexes[i]);
        // lut_indexes is initialized to 0 by default
        // if a different behavior is wanted, it should be rewritten later
        cuda_memset_async(lut_indexes, 0, lut_indexes_size, streams[i],
                          gpu_indexes[i]);

        lut_vec.push_back(lut);
        lut_indexes_vec.push_back(lut_indexes);

        cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      }

      // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
      // by default
      lwe_indexes_in = (Torus *)cuda_malloc_async(
          num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
      lwe_indexes_out = (Torus *)cuda_malloc_async(
          num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
      lwe_trivial_indexes = (Torus *)cuda_malloc_async(
          num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);

      h_lwe_indexes_in = (Torus *)malloc(num_radix_blocks * sizeof(Torus));
      h_lwe_indexes_out = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

      for (int i = 0; i < num_radix_blocks; i++)
        h_lwe_indexes_in[i] = i;

      cuda_memcpy_async_to_gpu(lwe_indexes_in, h_lwe_indexes_in,
                               num_radix_blocks * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
      cuda_memcpy_async_to_gpu(lwe_indexes_out, h_lwe_indexes_in,
                               num_radix_blocks * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
      cuda_memcpy_async_to_gpu(lwe_trivial_indexes, h_lwe_indexes_in,
                               num_radix_blocks * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
      memcpy(h_lwe_indexes_out, h_lwe_indexes_in,
             num_radix_blocks * sizeof(Torus));

      /// With multiple GPUs we allocate arrays to be pushed to the vectors and
      /// copy data on each GPU then when we gather data to GPU 0 we can copy
      /// back to the original indexing
      multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                                lwe_array_in_vec, num_radix_blocks,
                                params.big_lwe_dimension + 1);
      multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                                lwe_after_ks_vec, num_radix_blocks,
                                params.small_lwe_dimension + 1);
      multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                                lwe_after_pbs_vec, num_radix_blocks,
                                params.big_lwe_dimension + 1);
      multi_gpu_alloc_array_async(streams, gpu_indexes, active_gpu_count,
                                  lwe_trivial_indexes_vec, num_radix_blocks);
      cuda_synchronize_stream(streams[0], gpu_indexes[0]);
      multi_gpu_copy_array_async(streams, gpu_indexes, active_gpu_count,
                                 lwe_trivial_indexes_vec, lwe_trivial_indexes,
                                 num_radix_blocks);

      // Keyswitch
      Torus big_size =
          (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
      Torus small_size =
          (params.small_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
      tmp_lwe_before_ks =
          (Torus *)cuda_malloc_async(big_size, streams[0], gpu_indexes[0]);
    }
  }

  // constructor to reuse memory
  int_radix_lut(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                uint32_t gpu_count, int_radix_params params, uint32_t num_luts,
                uint32_t num_radix_blocks, int_radix_lut *base_lut_object) {

    this->params = params;
    this->num_blocks = num_radix_blocks;
    this->num_luts = num_luts;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    // base lut object should have bigger or equal memory than current one
    assert(num_radix_blocks <= base_lut_object->num_blocks);
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
      auto lut = (Torus *)cuda_malloc_async(num_luts * lut_buffer_size,
                                            streams[i], gpu_indexes[i]);
      auto lut_indexes = (Torus *)cuda_malloc_async(lut_indexes_size,
                                                    streams[i], gpu_indexes[i]);
      // lut_indexes is initialized to 0 by default
      // if a different behavior is wanted, it should be rewritten later
      cuda_memset_async(lut_indexes, 0, lut_indexes_size, streams[i],
                        gpu_indexes[i]);

      lut_vec.push_back(lut);
      lut_indexes_vec.push_back(lut_indexes);

      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }

    // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
    // by default
    lwe_indexes_in = (Torus *)cuda_malloc_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    lwe_indexes_out = (Torus *)cuda_malloc_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    lwe_trivial_indexes = (Torus *)cuda_malloc_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);

    h_lwe_indexes_in = (Torus *)malloc(num_radix_blocks * sizeof(Torus));
    h_lwe_indexes_out = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes_in[i] = i;

    cuda_memcpy_async_to_gpu(lwe_indexes_in, h_lwe_indexes_in,
                             num_radix_blocks * sizeof(Torus), streams[0],
                             gpu_indexes[0]);
    cuda_memcpy_async_to_gpu(lwe_indexes_out, h_lwe_indexes_in,
                             num_radix_blocks * sizeof(Torus), streams[0],
                             gpu_indexes[0]);
    cuda_memcpy_async_to_gpu(lwe_trivial_indexes, h_lwe_indexes_in,
                             num_radix_blocks * sizeof(Torus), streams[0],
                             gpu_indexes[0]);
    memcpy(h_lwe_indexes_out, h_lwe_indexes_in,
           num_radix_blocks * sizeof(Torus));
  }

  // Construction for many luts
  int_radix_lut(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                uint32_t gpu_count, int_radix_params params, uint32_t num_luts,
                uint32_t num_radix_blocks, uint32_t num_many_lut,
                bool allocate_gpu_memory) {

    this->params = params;
    this->num_blocks = num_radix_blocks;
    this->num_luts = num_luts;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    ///////////////
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    for (uint i = 0; i < active_gpu_count; i++) {
      cudaSetDevice(i);
      int8_t *gpu_pbs_buffer;
      auto num_blocks_on_gpu =
          get_num_inputs_on_gpu(num_radix_blocks, i, active_gpu_count);

      execute_scratch_pbs<Torus>(
          streams[i], gpu_indexes[i], &gpu_pbs_buffer, params.glwe_dimension,
          params.small_lwe_dimension, params.polynomial_size, params.pbs_level,
          params.grouping_factor, num_blocks_on_gpu, params.pbs_type,
          allocate_gpu_memory);
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      buffer.push_back(gpu_pbs_buffer);
    }

    if (allocate_gpu_memory) {
      // Allocate LUT
      // LUT is used as a trivial encryption and must be initialized outside
      // this constructor
      for (uint i = 0; i < active_gpu_count; i++) {
        auto lut = (Torus *)cuda_malloc_async(num_luts * lut_buffer_size,
                                              streams[i], gpu_indexes[i]);
        auto lut_indexes = (Torus *)cuda_malloc_async(
            lut_indexes_size, streams[i], gpu_indexes[i]);
        // lut_indexes is initialized to 0 by default
        // if a different behavior is wanted, it should be rewritten later
        cuda_memset_async(lut_indexes, 0, lut_indexes_size, streams[i],
                          gpu_indexes[i]);

        lut_vec.push_back(lut);
        lut_indexes_vec.push_back(lut_indexes);

        cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      }

      // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
      // by default
      lwe_indexes_in = (Torus *)cuda_malloc_async(
          num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
      lwe_indexes_out = (Torus *)cuda_malloc_async(
          num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
      lwe_trivial_indexes = (Torus *)cuda_malloc_async(
          num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);

      h_lwe_indexes_in = (Torus *)malloc(num_radix_blocks * sizeof(Torus));
      h_lwe_indexes_out = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

      for (int i = 0; i < num_radix_blocks; i++)
        h_lwe_indexes_in[i] = i;

      cuda_memcpy_async_to_gpu(lwe_indexes_in, h_lwe_indexes_in,
                               num_radix_blocks * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
      cuda_memcpy_async_to_gpu(lwe_indexes_out, h_lwe_indexes_in,
                               num_radix_blocks * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
      cuda_memcpy_async_to_gpu(lwe_trivial_indexes, h_lwe_indexes_in,
                               num_radix_blocks * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
      memcpy(h_lwe_indexes_out, h_lwe_indexes_in,
             num_radix_blocks * sizeof(Torus));

      /// With multiple GPUs we allocate arrays to be pushed to the vectors and
      /// copy data on each GPU then when we gather data to GPU 0 we can copy
      /// back to the original indexing
      multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                                lwe_array_in_vec, num_radix_blocks,
                                params.big_lwe_dimension + 1);
      multi_gpu_alloc_lwe_async(streams, gpu_indexes, active_gpu_count,
                                lwe_after_ks_vec, num_radix_blocks,
                                params.small_lwe_dimension + 1);
      multi_gpu_alloc_lwe_many_lut_output_async(
          streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
          num_radix_blocks, num_many_lut, params.big_lwe_dimension + 1);
      multi_gpu_alloc_array_async(streams, gpu_indexes, active_gpu_count,
                                  lwe_trivial_indexes_vec, num_radix_blocks);
      cuda_synchronize_stream(streams[0], gpu_indexes[0]);
      multi_gpu_copy_array_async(streams, gpu_indexes, active_gpu_count,
                                 lwe_trivial_indexes_vec, lwe_trivial_indexes,
                                 num_radix_blocks);

      // Keyswitch
      Torus big_size =
          (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
      Torus small_size =
          (params.small_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
      tmp_lwe_before_ks =
          (Torus *)cuda_malloc_async(big_size, streams[0], gpu_indexes[0]);
    }
  }

  // Return a pointer to idx-ith lut at gpu_index's global memory
  Torus *get_lut(uint32_t gpu_index, size_t idx) {
    auto lut = lut_vec[gpu_index];
    size_t lut_size = (params.glwe_dimension + 1) * params.polynomial_size;

    assert(lut != nullptr);
    return &lut[idx * lut_size];
  }

  // Return a pointer to idx-ith lut indexes at gpu_index's global memory
  Torus *get_lut_indexes(uint32_t gpu_index, size_t ind) {
    auto lut_indexes = lut_indexes_vec[gpu_index];
    return &lut_indexes[ind];
  }

  // If this function is called we assume the lwe_indexes_(in/out) are not the
  // trivial anymore and thus we disable optimizations
  void set_lwe_indexes(cudaStream_t stream, uint32_t gpu_index,
                       Torus *h_indexes_in, Torus *h_indexes_out) {

    memcpy(h_lwe_indexes_in, h_indexes_in, num_blocks * sizeof(Torus));
    memcpy(h_lwe_indexes_out, h_indexes_out, num_blocks * sizeof(Torus));

    cuda_memcpy_async_to_gpu(lwe_indexes_in, h_lwe_indexes_in,
                             num_blocks * sizeof(Torus), stream, gpu_index);
    cuda_memcpy_async_to_gpu(lwe_indexes_out, h_lwe_indexes_out,
                             num_blocks * sizeof(Torus), stream, gpu_index);

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
        cuda_memcpy_async_gpu_to_gpu(dst_lut, src_lut,
                                     num_luts * lut_size * sizeof(Torus),
                                     streams[i], gpu_indexes[i]);
        cuda_memcpy_async_gpu_to_gpu(dst_lut_indexes, src_lut_indexes,
                                     num_blocks * sizeof(Torus), streams[i],
                                     gpu_indexes[i]);
      }
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_drop_async(lut_vec[i], streams[i], gpu_indexes[i]);
      cuda_drop_async(lut_indexes_vec[i], streams[i], gpu_indexes[i]);
    }

    cuda_drop_async(lwe_indexes_in, streams[0], gpu_indexes[0]);
    cuda_drop_async(lwe_indexes_out, streams[0], gpu_indexes[0]);
    cuda_drop_async(lwe_trivial_indexes, streams[0], gpu_indexes[0]);

    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    lut_vec.clear();
    lut_indexes_vec.clear();
    free(h_lwe_indexes_in);
    free(h_lwe_indexes_out);

    if (!mem_reuse) {
      cuda_drop_async(tmp_lwe_before_ks, streams[0], gpu_indexes[0]);
      cuda_synchronize_stream(streams[0], gpu_indexes[0]);
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
      buffer.clear();

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
    }
  }
};
template <typename Torus> struct int_bit_extract_luts_buffer {
  int_radix_params params;
  int_radix_lut<Torus> *lut;

  // With offset
  int_bit_extract_luts_buffer(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              int_radix_params params, uint32_t bits_per_block,
                              uint32_t final_offset, uint32_t num_radix_blocks,
                              bool allocate_gpu_memory) {
    this->params = params;

    lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, bits_per_block,
        bits_per_block * num_radix_blocks, allocate_gpu_memory);

    if (allocate_gpu_memory) {
      for (int i = 0; i < bits_per_block; i++) {

        auto operator_f = [i, final_offset](Torus x) -> Torus {
          Torus y = (x >> i) & 1;
          return y << final_offset;
        };

        generate_device_accumulator<Torus>(
            streams[0], gpu_indexes[0], lut->get_lut(0, i),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, operator_f);
      }

      /**
       * we have bits_per_blocks LUTs that should be used for all bits in all
       * blocks
       */
      Torus *h_lut_indexes =
          (Torus *)malloc(num_radix_blocks * bits_per_block * sizeof(Torus));
      for (int j = 0; j < num_radix_blocks; j++) {
        for (int i = 0; i < bits_per_block; i++)
          h_lut_indexes[i + j * bits_per_block] = i;
      }
      cuda_memcpy_async_to_gpu(lut->get_lut_indexes(0, 0), h_lut_indexes,
                               num_radix_blocks * bits_per_block *
                                   sizeof(Torus),
                               streams[0], gpu_indexes[0]);
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
      free(h_lut_indexes);
      free(h_lwe_indexes_in);
      free(h_lwe_indexes_out);
    }
  }

  // Without offset
  int_bit_extract_luts_buffer(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              int_radix_params params, uint32_t bits_per_block,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory)
      : int_bit_extract_luts_buffer(streams, gpu_indexes, gpu_count, params,
                                    bits_per_block, 0, num_radix_blocks,
                                    allocate_gpu_memory) {}

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

  Torus *tmp_bits;
  Torus *tmp_shift_bits;
  Torus *tmp_rotated;
  Torus *tmp_input_bits_a;
  Torus *tmp_input_bits_b;
  Torus *tmp_mux_inputs;

  int_bit_extract_luts_buffer<Torus> *bit_extract_luts;
  int_bit_extract_luts_buffer<Torus> *bit_extract_luts_with_offset_2;
  int_radix_lut<Torus> *mux_lut;
  int_radix_lut<Torus> *cleaning_lut;

  Torus offset;

  int_shift_and_rotate_buffer(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
                              int_radix_params params,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory) {
    this->shift_type = shift_type;
    this->is_signed = is_signed;
    this->params = params;

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
        num_radix_blocks, allocate_gpu_memory);
    bit_extract_luts_with_offset_2 = new int_bit_extract_luts_buffer<Torus>(
        streams, gpu_indexes, gpu_count, params, bits_per_block, 2,
        num_radix_blocks, allocate_gpu_memory);

    mux_lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params,
                                       1, bits_per_block * num_radix_blocks,
                                       allocate_gpu_memory);
    cleaning_lut =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_radix_blocks, allocate_gpu_memory);

    if (allocate_gpu_memory) {
      tmp_bits = (Torus *)cuda_malloc_async(bits_per_block * num_radix_blocks *
                                                (params.big_lwe_dimension + 1) *
                                                sizeof(Torus),
                                            streams[0], gpu_indexes[0]);
      cuda_memset_async(tmp_bits, 0,
                        bits_per_block * num_radix_blocks *
                            (params.big_lwe_dimension + 1) * sizeof(Torus),
                        streams[0], gpu_indexes[0]);
      tmp_shift_bits = (Torus *)cuda_malloc_async(
          max_num_bits_that_tell_shift * num_radix_blocks *
              (params.big_lwe_dimension + 1) * sizeof(Torus),
          streams[0], gpu_indexes[0]);
      cuda_memset_async(tmp_shift_bits, 0,
                        max_num_bits_that_tell_shift * num_radix_blocks *
                            (params.big_lwe_dimension + 1) * sizeof(Torus),
                        streams[0], gpu_indexes[0]);

      tmp_rotated = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          streams[0], gpu_indexes[0]);
      cuda_memset_async(tmp_rotated, 0,
                        bits_per_block * num_radix_blocks *
                            (params.big_lwe_dimension + 1) * sizeof(Torus),
                        streams[0], gpu_indexes[0]);

      tmp_input_bits_a = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          streams[0], gpu_indexes[0]);
      cuda_memset_async(tmp_input_bits_a, 0,
                        bits_per_block * num_radix_blocks *
                            (params.big_lwe_dimension + 1) * sizeof(Torus),
                        streams[0], gpu_indexes[0]);
      tmp_input_bits_b = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          streams[0], gpu_indexes[0]);
      cuda_memset_async(tmp_input_bits_b, 0,
                        bits_per_block * num_radix_blocks *
                            (params.big_lwe_dimension + 1) * sizeof(Torus),
                        streams[0], gpu_indexes[0]);
      tmp_mux_inputs = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          streams[0], gpu_indexes[0]);
      cuda_memset_async(tmp_mux_inputs, 0,
                        bits_per_block * num_radix_blocks *
                            (params.big_lwe_dimension + 1) * sizeof(Torus),
                        streams[0], gpu_indexes[0]);

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
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, mux_lut_f);
      mux_lut->broadcast_lut(streams, gpu_indexes, 0);

      auto cleaning_lut_f = [](Torus x) -> Torus { return x; };
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], cleaning_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, cleaning_lut_f);
      cleaning_lut->broadcast_lut(streams, gpu_indexes, 0);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(tmp_bits, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_shift_bits, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_rotated, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_input_bits_a, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_input_bits_b, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_mux_inputs, streams[0], gpu_indexes[0]);

    bit_extract_luts->release(streams, gpu_indexes, gpu_count);
    bit_extract_luts_with_offset_2->release(streams, gpu_indexes, gpu_count);
    mux_lut->release(streams, gpu_indexes, gpu_count);
    cleaning_lut->release(streams, gpu_indexes, gpu_count);

    delete (bit_extract_luts);
    delete (bit_extract_luts_with_offset_2);
    delete (mux_lut);
    delete (cleaning_lut);
  }
};

template <typename Torus> struct int_fullprop_buffer {
  int_radix_params params;

  int_radix_lut<Torus> *lut;

  Torus *tmp_small_lwe_vector;
  Torus *tmp_big_lwe_vector;

  int_fullprop_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                      uint32_t gpu_count, int_radix_params params,
                      bool allocate_gpu_memory) {
    this->params = params;
    lut = new int_radix_lut<Torus>(streams, gpu_indexes, 1, params, 2, 2,
                                   allocate_gpu_memory);

    if (allocate_gpu_memory) {

      // LUTs
      auto lut_f_message = [params](Torus x) -> Torus {
        return x % params.message_modulus;
      };
      auto lut_f_carry = [params](Torus x) -> Torus {
        return x / params.message_modulus;
      };

      //
      Torus *lut_buffer_message = lut->get_lut(0, 0);
      Torus *lut_buffer_carry = lut->get_lut(0, 1);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut_buffer_message, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          lut_f_message);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut_buffer_carry, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          lut_f_carry);

      Torus lwe_indexes_size = 2 * sizeof(Torus);
      Torus *h_lwe_indexes = (Torus *)malloc(lwe_indexes_size);
      for (int i = 0; i < 2; i++)
        h_lwe_indexes[i] = i;
      Torus *lwe_indexes = lut->get_lut_indexes(0, 0);
      cuda_memcpy_async_to_gpu(lwe_indexes, h_lwe_indexes, lwe_indexes_size,
                               streams[0], gpu_indexes[0]);

      lut->broadcast_lut(streams, gpu_indexes, 0);

      // Temporary arrays
      Torus small_vector_size =
          2 * (params.small_lwe_dimension + 1) * sizeof(Torus);
      Torus big_vector_size =
          2 * (params.glwe_dimension * params.polynomial_size + 1) *
          sizeof(Torus);

      tmp_small_lwe_vector = (Torus *)cuda_malloc_async(
          small_vector_size, streams[0], gpu_indexes[0]);
      tmp_big_lwe_vector = (Torus *)cuda_malloc_async(
          big_vector_size, streams[0], gpu_indexes[0]);
      cuda_synchronize_stream(streams[0], gpu_indexes[0]);
      free(h_lwe_indexes);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    lut->release(streams, gpu_indexes, 1);
    delete lut;

    cuda_drop_async(tmp_small_lwe_vector, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_big_lwe_vector, streams[0], gpu_indexes[0]);
  }
};

template <typename Torus> struct int_legacy_sc_prop_memory {
  Torus *generates_or_propagates;
  Torus *step_output;

  // luts_array[2] = {lut_does_block_generate_carry,
  // lut_does_block_generate_or_propagate}
  int_radix_lut<Torus> *luts_array;
  int_radix_lut<Torus> *luts_carry_propagation_sum;
  int_radix_lut<Torus> *message_acc;

  int_radix_params params;

  int_legacy_sc_prop_memory(cudaStream_t const *streams,
                            uint32_t const *gpu_indexes, uint32_t gpu_count,
                            int_radix_params params, uint32_t num_radix_blocks,
                            bool allocate_gpu_memory) {
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    // allocate memory for intermediate calculations
    generates_or_propagates = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    step_output = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(generates_or_propagates, 0,
                      num_radix_blocks * big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);
    cuda_memset_async(step_output, 0, num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);

    // declare functions for lut generation
    auto f_lut_does_block_generate_carry = [message_modulus](Torus x) -> Torus {
      if (x >= message_modulus)
        return OUTPUT_CARRY::GENERATED;
      return OUTPUT_CARRY::NONE;
    };

    auto f_lut_does_block_generate_or_propagate =
        [message_modulus](Torus x) -> Torus {
      if (x >= message_modulus)
        return OUTPUT_CARRY::GENERATED;
      else if (x == (message_modulus - 1))
        return OUTPUT_CARRY::PROPAGATED;
      return OUTPUT_CARRY::NONE;
    };

    auto f_luts_carry_propagation_sum = [](Torus msb, Torus lsb) -> Torus {
      if (msb == OUTPUT_CARRY::PROPAGATED)
        return lsb;
      return msb;
    };

    auto f_message_acc = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };

    // create lut objects
    luts_array =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                 num_radix_blocks, allocate_gpu_memory);
    luts_carry_propagation_sum =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_radix_blocks, luts_array);
    message_acc =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_radix_blocks, luts_array);

    auto lut_does_block_generate_carry = luts_array->get_lut(0, 0);
    auto lut_does_block_generate_or_propagate = luts_array->get_lut(0, 1);

    // generate luts (aka accumulators)
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_does_block_generate_carry,
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_carry);
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_does_block_generate_or_propagate,
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_or_propagate);
    cuda_set_value_async<Torus>(streams[0], gpu_indexes[0],
                                luts_array->get_lut_indexes(0, 1), 1,
                                num_radix_blocks - 1);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], luts_carry_propagation_sum->get_lut(0, 0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_luts_carry_propagation_sum);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], message_acc->get_lut(0, 0), glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_message_acc);

    luts_array->broadcast_lut(streams, gpu_indexes, 0);
    luts_carry_propagation_sum->broadcast_lut(streams, gpu_indexes, 0);
    message_acc->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(generates_or_propagates, streams[0], gpu_indexes[0]);
    cuda_drop_async(step_output, streams[0], gpu_indexes[0]);

    luts_array->release(streams, gpu_indexes, gpu_count);
    luts_carry_propagation_sum->release(streams, gpu_indexes, gpu_count);
    message_acc->release(streams, gpu_indexes, gpu_count);

    delete luts_array;
    delete luts_carry_propagation_sum;
    delete message_acc;
  }
};

template <typename Torus> struct int_overflowing_sub_memory {
  Torus *generates_or_propagates;
  Torus *step_output;

  int_radix_lut<Torus> *luts_array;
  int_radix_lut<Torus> *luts_borrow_propagation_sum;
  int_radix_lut<Torus> *message_acc;

  int_radix_params params;

  int_overflowing_sub_memory(cudaStream_t const *streams,
                             uint32_t const *gpu_indexes, uint32_t gpu_count,
                             int_radix_params params, uint32_t num_radix_blocks,
                             bool allocate_gpu_memory) {
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    // allocate memory for intermediate calculations
    generates_or_propagates = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    step_output = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(generates_or_propagates, 0,
                      num_radix_blocks * big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);
    cuda_memset_async(step_output, 0, num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);

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
    luts_array =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                 num_radix_blocks, allocate_gpu_memory);
    luts_borrow_propagation_sum =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_radix_blocks, luts_array);
    message_acc =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_radix_blocks, luts_array);

    auto lut_does_block_generate_carry = luts_array->get_lut(0, 0);
    auto lut_does_block_generate_or_propagate = luts_array->get_lut(0, 1);

    // generate luts (aka accumulators)
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_does_block_generate_carry,
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_carry);
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_does_block_generate_or_propagate,
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_or_propagate);
    cuda_set_value_async<Torus>(streams[0], gpu_indexes[0],
                                luts_array->get_lut_indexes(0, 1), 1,
                                num_radix_blocks - 1);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], luts_borrow_propagation_sum->get_lut(0, 0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_luts_borrow_propagation_sum);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], message_acc->get_lut(0, 0), glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_message_acc);

    luts_array->broadcast_lut(streams, gpu_indexes, 0);
    luts_borrow_propagation_sum->broadcast_lut(streams, gpu_indexes, 0);
    message_acc->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(generates_or_propagates, streams[0], gpu_indexes[0]);
    cuda_drop_async(step_output, streams[0], gpu_indexes[0]);

    luts_array->release(streams, gpu_indexes, gpu_count);
    luts_borrow_propagation_sum->release(streams, gpu_indexes, gpu_count);
    message_acc->release(streams, gpu_indexes, gpu_count);

    delete luts_array;
    delete luts_borrow_propagation_sum;
    delete message_acc;
  }
};

template <typename Torus> struct int_sum_ciphertexts_vec_memory {
  Torus *new_blocks;
  Torus *new_blocks_copy;
  Torus *old_blocks;
  Torus *small_lwe_vector;
  int_radix_params params;

  int32_t *d_smart_copy_in;
  int32_t *d_smart_copy_out;

  bool mem_reuse = false;

  int_sum_ciphertexts_vec_memory(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count, int_radix_params params,
                                 uint32_t num_blocks_in_radix,
                                 uint32_t max_num_radix_in_vec,
                                 bool allocate_gpu_memory) {
    this->params = params;

    int max_pbs_count = num_blocks_in_radix * max_num_radix_in_vec;

    // allocate gpu memory for intermediate buffers
    new_blocks = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.big_lwe_dimension + 1) * sizeof(Torus),
        streams[0], gpu_indexes[0]);
    new_blocks_copy = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.big_lwe_dimension + 1) * sizeof(Torus),
        streams[0], gpu_indexes[0]);
    old_blocks = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.big_lwe_dimension + 1) * sizeof(Torus),
        streams[0], gpu_indexes[0]);
    small_lwe_vector = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.small_lwe_dimension + 1) * sizeof(Torus),
        streams[0], gpu_indexes[0]);
    cuda_memset_async(new_blocks, 0,
                      max_pbs_count * (params.big_lwe_dimension + 1) *
                          sizeof(Torus),
                      streams[0], gpu_indexes[0]);
    cuda_memset_async(new_blocks_copy, 0,
                      max_pbs_count * (params.big_lwe_dimension + 1) *
                          sizeof(Torus),
                      streams[0], gpu_indexes[0]);
    cuda_memset_async(old_blocks, 0,
                      max_pbs_count * (params.big_lwe_dimension + 1) *
                          sizeof(Torus),
                      streams[0], gpu_indexes[0]);
    cuda_memset_async(small_lwe_vector, 0,
                      max_pbs_count * (params.small_lwe_dimension + 1) *
                          sizeof(Torus),
                      streams[0], gpu_indexes[0]);

    d_smart_copy_in = (int32_t *)cuda_malloc_async(
        max_pbs_count * sizeof(int32_t), streams[0], gpu_indexes[0]);
    d_smart_copy_out = (int32_t *)cuda_malloc_async(
        max_pbs_count * sizeof(int32_t), streams[0], gpu_indexes[0]);
    cuda_memset_async(d_smart_copy_in, 0, max_pbs_count * sizeof(int32_t),
                      streams[0], gpu_indexes[0]);
    cuda_memset_async(d_smart_copy_out, 0, max_pbs_count * sizeof(int32_t),
                      streams[0], gpu_indexes[0]);
  }

  int_sum_ciphertexts_vec_memory(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count, int_radix_params params,
                                 uint32_t num_blocks_in_radix,
                                 uint32_t max_num_radix_in_vec,
                                 Torus *new_blocks, Torus *old_blocks,
                                 Torus *small_lwe_vector) {
    mem_reuse = true;
    this->params = params;

    int max_pbs_count = num_blocks_in_radix * max_num_radix_in_vec;

    // assign  gpu memory for intermediate buffers
    this->new_blocks = new_blocks;
    this->old_blocks = old_blocks;
    this->small_lwe_vector = small_lwe_vector;
    new_blocks_copy = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.big_lwe_dimension + 1) * sizeof(Torus),
        streams[0], gpu_indexes[0]);
    cuda_memset_async(new_blocks_copy, 0,
                      max_pbs_count * (params.big_lwe_dimension + 1) *
                          sizeof(Torus),
                      streams[0], gpu_indexes[0]);

    d_smart_copy_in = (int32_t *)cuda_malloc_async(
        max_pbs_count * sizeof(int32_t), streams[0], gpu_indexes[0]);
    d_smart_copy_out = (int32_t *)cuda_malloc_async(
        max_pbs_count * sizeof(int32_t), streams[0], gpu_indexes[0]);
    cuda_memset_async(d_smart_copy_in, 0, max_pbs_count * sizeof(int32_t),
                      streams[0], gpu_indexes[0]);
    cuda_memset_async(d_smart_copy_out, 0, max_pbs_count * sizeof(int32_t),
                      streams[0], gpu_indexes[0]);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(d_smart_copy_in, streams[0], gpu_indexes[0]);
    cuda_drop_async(d_smart_copy_out, streams[0], gpu_indexes[0]);

    if (!mem_reuse) {
      cuda_drop_async(new_blocks, streams[0], gpu_indexes[0]);
      cuda_drop_async(old_blocks, streams[0], gpu_indexes[0]);
      cuda_drop_async(small_lwe_vector, streams[0], gpu_indexes[0]);
    }

    cuda_drop_async(new_blocks_copy, streams[0], gpu_indexes[0]);
  }
};
// For sequential algorithm in group propagation
template <typename Torus> struct int_seq_group_prop_memory {

  Torus *group_resolved_carries;
  int_radix_lut<Torus> *lut_sequential_algorithm;
  uint32_t grouping_size;

  int_seq_group_prop_memory(cudaStream_t const *streams,
                            uint32_t const *gpu_indexes, uint32_t gpu_count,
                            int_radix_params params, uint32_t group_size,
                            uint32_t big_lwe_size_bytes,
                            bool allocate_gpu_memory) {

    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    grouping_size = group_size;
    group_resolved_carries = (Torus *)cuda_malloc_async(
        (grouping_size)*big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(group_resolved_carries, 0,
                      (grouping_size)*big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);

    int num_seq_luts = grouping_size - 1;
    Torus *h_seq_lut_indexes = (Torus *)malloc(num_seq_luts * sizeof(Torus));
    lut_sequential_algorithm = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, num_seq_luts, num_seq_luts,
        allocate_gpu_memory);
    for (int index = 0; index < num_seq_luts; index++) {
      auto f_lut_sequential = [index](Torus propa_cum_sum_block) {
        return (propa_cum_sum_block >> (index + 1)) & 1;
      };
      auto seq_lut = lut_sequential_algorithm->get_lut(0, index);
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], seq_lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_lut_sequential);
      h_seq_lut_indexes[index] = index;
    }
    Torus *seq_lut_indexes = lut_sequential_algorithm->get_lut_indexes(0, 0);
    cuda_memcpy_async_to_gpu(seq_lut_indexes, h_seq_lut_indexes,
                             num_seq_luts * sizeof(Torus), streams[0],
                             gpu_indexes[0]);

    lut_sequential_algorithm->broadcast_lut(streams, gpu_indexes, 0);
    free(h_seq_lut_indexes);
  };
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(group_resolved_carries, streams[0], gpu_indexes[0]);
    lut_sequential_algorithm->release(streams, gpu_indexes, gpu_count);
    delete lut_sequential_algorithm;
  };
};

// For hillis steele algorithm in group propagation
template <typename Torus> struct int_hs_group_prop_memory {

  int_radix_lut<Torus> *lut_hillis_steele;
  uint32_t grouping_size;

  int_hs_group_prop_memory(cudaStream_t const *streams,
                           uint32_t const *gpu_indexes, uint32_t gpu_count,
                           int_radix_params params, uint32_t num_groups,
                           uint32_t big_lwe_size_bytes,
                           bool allocate_gpu_memory) {

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
                                 num_groups, allocate_gpu_memory);

    auto hillis_steele_lut = lut_hillis_steele->get_lut(0, 0);
    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], hillis_steele_lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_lut_hillis_steele);

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
  Torus *shifted_blocks_and_states;
  Torus *shifted_blocks;
  Torus *block_states;

  int_radix_lut<Torus> *luts_array_first_step;

  int_shifted_blocks_and_states_memory(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t num_many_lut, uint32_t grouping_size, bool allocate_gpu_memory) {

    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    shifted_blocks_and_states = (Torus *)cuda_malloc_async(
        num_many_lut * num_radix_blocks * big_lwe_size_bytes, streams[0],
        gpu_indexes[0]);
    cuda_memset_async(shifted_blocks_and_states, 0,
                      num_many_lut * num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);
    shifted_blocks = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(shifted_blocks, 0, num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);
    block_states = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(block_states, 0, num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);

    uint32_t num_luts_first_step = 2 * grouping_size + 1;

    luts_array_first_step = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, num_luts_first_step,
        num_radix_blocks, num_many_lut, allocate_gpu_memory);

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

    generate_many_lut_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], first_block_lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_first_grouping_luts);

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
      generate_many_lut_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_grouping_luts);
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

      generate_many_lut_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_grouping_luts);
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

    std::vector<std::function<Torus(Torus)>> f_last_grouping_luts = {
        f_last_block_state, f_shift_block};

    generate_many_lut_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], last_block_lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_last_grouping_luts);

    // Generate the indexes to switch between luts within the pbs
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus *h_lut_indexes = (Torus *)malloc(lut_indexes_size);

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
    cuda_memcpy_async_to_gpu(lut_indexes, h_lut_indexes, lut_indexes_size,
                             streams[0], gpu_indexes[0]);
    // Do I need to do something else for the multi-gpu?

    luts_array_first_step->broadcast_lut(streams, gpu_indexes, 0);

    free(h_lut_indexes);
  };
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    cuda_drop_async(shifted_blocks_and_states, streams[0], gpu_indexes[0]);
    cuda_drop_async(shifted_blocks, streams[0], gpu_indexes[0]);
    cuda_drop_async(block_states, streams[0], gpu_indexes[0]);

    luts_array_first_step->release(streams, gpu_indexes, gpu_count);
    delete luts_array_first_step;
  };
};

// compute_propagation simulator and group carries
template <typename Torus> struct int_prop_simu_group_carries_memory {
  Torus *scalar_array_cum_sum;
  Torus *propagation_cum_sums;
  Torus *simulators;
  Torus *grouping_pgns;
  Torus *prepared_blocks;

  Torus *resolved_carries;

  int_radix_lut<Torus> *luts_array_second_step;

  int_seq_group_prop_memory<Torus> *seq_group_prop_mem;
  int_hs_group_prop_memory<Torus> *hs_group_prop_mem;

  uint32_t group_size;
  bool use_sequential_algorithm_to_resolver_group_carries;

  int_prop_simu_group_carries_memory(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t grouping_size, uint32_t num_groups, bool allocate_gpu_memory) {

    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    uint32_t block_modulus = message_modulus * carry_modulus;
    uint32_t num_bits_in_block = std::log2(block_modulus);

    group_size = grouping_size;

    scalar_array_cum_sum = (Torus *)cuda_malloc_async(
        num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    cuda_memset_async(scalar_array_cum_sum, 0, num_radix_blocks * sizeof(Torus),
                      streams[0], gpu_indexes[0]);
    propagation_cum_sums = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(propagation_cum_sums, 0,
                      num_radix_blocks * big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);
    simulators = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(simulators, 0, num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);

    grouping_pgns = (Torus *)cuda_malloc_async(num_groups * big_lwe_size_bytes,
                                               streams[0], gpu_indexes[0]);
    cuda_memset_async(grouping_pgns, 0, num_groups * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);

    prepared_blocks =
        (Torus *)cuda_malloc_async((num_radix_blocks + 1) * big_lwe_size_bytes,
                                   streams[0], gpu_indexes[0]);
    cuda_memset_async(prepared_blocks, 0,
                      (num_radix_blocks + 1) * big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);

    resolved_carries = (Torus *)cuda_malloc_async(
        (num_groups + 1) * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(resolved_carries, 0,
                      (num_groups + 1) * big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);

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

    use_sequential_algorithm_to_resolver_group_carries =
        sequential_depth <= hillis_steel_depth;
    uint32_t num_extra_luts = 0;
    if (use_sequential_algorithm_to_resolver_group_carries) {
      num_extra_luts = (grouping_size - 1);
    } else {
      num_extra_luts = 1;
    }

    uint32_t num_luts_second_step = 2 * grouping_size + num_extra_luts;
    luts_array_second_step = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, num_luts_second_step,
        num_radix_blocks, allocate_gpu_memory);

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

      auto lut = luts_array_second_step->get_lut(0, lut_id);
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_first_grouping_inner_propagation);
    }

    auto f_first_grouping_outer_propagation =
        [num_bits_in_block](Torus block) -> Torus {
      return (block >> (num_bits_in_block - 1)) & 1;
    };

    int lut_id = grouping_size - 1;
    auto lut_first_group_outer = luts_array_second_step->get_lut(0, lut_id);
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut_first_group_outer, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_first_grouping_outer_propagation);

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

      auto lut = luts_array_second_step->get_lut(0, lut_id);
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_other_groupings_inner_propagation);
    }

    if (use_sequential_algorithm_to_resolver_group_carries) {
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

        auto lut = luts_array_second_step->get_lut(0, lut_id);
        generate_device_accumulator<Torus>(
            streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
            message_modulus, carry_modulus, f_group_propagation);
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

      auto lut = luts_array_second_step->get_lut(0, lut_id);
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_group_propagation);
    }

    Torus *h_second_lut_indexes = (Torus *)malloc(lut_indexes_size);

    Torus *h_scalar_array_cum_sum =
        (Torus *)malloc(num_radix_blocks * sizeof(Torus));

    for (int index = 0; index < num_radix_blocks; index++) {
      uint32_t grouping_index = index / grouping_size;
      bool is_in_first_grouping = (grouping_index == 0);
      uint32_t index_in_grouping = index % grouping_size;

      if (is_in_first_grouping) {
        h_second_lut_indexes[index] = index_in_grouping;
      } else if (index_in_grouping == (grouping_size - 1)) {
        if (use_sequential_algorithm_to_resolver_group_carries) {
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
        if (use_sequential_algorithm_to_resolver_group_carries) {
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
    cuda_memcpy_async_to_gpu(second_lut_indexes, h_second_lut_indexes,
                             lut_indexes_size, streams[0], gpu_indexes[0]);

    cuda_memcpy_async_to_gpu(scalar_array_cum_sum, h_scalar_array_cum_sum,
                             num_radix_blocks * sizeof(Torus), streams[0],
                             gpu_indexes[0]);
    luts_array_second_step->broadcast_lut(streams, gpu_indexes, 0);

    if (use_sequential_algorithm_to_resolver_group_carries) {

      seq_group_prop_mem = new int_seq_group_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, grouping_size,
          big_lwe_size_bytes, true);

    } else {
      hs_group_prop_mem = new int_hs_group_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_groups,
          big_lwe_size_bytes, true);
    }

    free(h_scalar_array_cum_sum);
    free(h_second_lut_indexes);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes, Torus *new_lut_indexes,
                          Torus *new_scalars, uint32_t new_num_blocks) {
    Torus *lut_indexes = luts_array_second_step->get_lut_indexes(0, 0);
    cuda_memcpy_async_gpu_to_gpu(lut_indexes, new_lut_indexes,
                                 new_num_blocks * sizeof(Torus), streams[0],
                                 gpu_indexes[0]);

    luts_array_second_step->broadcast_lut(streams, gpu_indexes, 0);

    cuda_memcpy_async_gpu_to_gpu(scalar_array_cum_sum, new_scalars,
                                 new_num_blocks * sizeof(Torus), streams[0],
                                 gpu_indexes[0]);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(scalar_array_cum_sum, streams[0], gpu_indexes[0]);
    cuda_drop_async(propagation_cum_sums, streams[0], gpu_indexes[0]);
    cuda_drop_async(simulators, streams[0], gpu_indexes[0]);
    cuda_drop_async(grouping_pgns, streams[0], gpu_indexes[0]);
    cuda_drop_async(prepared_blocks, streams[0], gpu_indexes[0]);
    cuda_drop_async(resolved_carries, streams[0], gpu_indexes[0]);

    luts_array_second_step->release(streams, gpu_indexes, gpu_count);

    if (use_sequential_algorithm_to_resolver_group_carries) {
      seq_group_prop_mem->release(streams, gpu_indexes, gpu_count);
      delete seq_group_prop_mem;
    } else {
      hs_group_prop_mem->release(streams, gpu_indexes, gpu_count);
      delete hs_group_prop_mem;
    }

    delete luts_array_second_step;
  };
};

template <typename Torus> struct int_sc_prop_memory {
  uint32_t num_many_lut;
  uint32_t lut_stride;

  uint32_t num_groups;
  Torus *output_flag;
  Torus *last_lhs;
  Torus *last_rhs;
  int_radix_lut<Torus> *lut_message_extract;

  int_radix_lut<Torus> *lut_overflow_flag_prep;

  int_shifted_blocks_and_states_memory<Torus> *shifted_blocks_state_mem;
  int_prop_simu_group_carries_memory<Torus> *prop_simu_group_carries_mem;

  int_radix_params params;
  bool use_sequential_algorithm_to_resolver_group_carries;
  uint32_t requested_flag;

  uint32_t active_gpu_count;

  cudaEvent_t *incoming_events1;
  cudaEvent_t *incoming_events2;
  cudaEvent_t *outgoing_events1;
  cudaEvent_t *outgoing_events2;
  cudaEvent_t *outgoing_events3;
  cudaEvent_t *outgoing_events4;

  int_sc_prop_memory(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                     uint32_t gpu_count, int_radix_params params,
                     uint32_t num_radix_blocks, uint32_t requested_flag_in,
                     uint32_t uses_carry, bool allocate_gpu_memory) {
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
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
        grouping_size, true);

    prop_simu_group_carries_mem = new int_prop_simu_group_carries_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        grouping_size, num_groups, true);

    //  Step 3 elements
    lut_message_extract =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                 num_radix_blocks + 1, allocate_gpu_memory);
    // lut for the first block in the first grouping
    auto f_message_extract = [message_modulus](Torus block) -> Torus {
      return (block >> 1) % message_modulus;
    };

    auto extract_lut = lut_message_extract->get_lut(0, 0);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], extract_lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_message_extract);

    lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);

    // This store a single block that with be used to store the overflow or
    // carry results
    output_flag =
        (Torus *)cuda_malloc_async(big_lwe_size_bytes * (num_radix_blocks + 1),
                                   streams[0], gpu_indexes[0]);
    cuda_memset_async(output_flag, 0, big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);

    if (requested_flag == outputFlag::FLAG_OVERFLOW) {
      last_lhs = (Torus *)cuda_malloc_async(big_lwe_size_bytes, streams[0],
                                            gpu_indexes[0]);
      last_rhs = (Torus *)cuda_malloc_async(big_lwe_size_bytes, streams[0],
                                            gpu_indexes[0]);
      cuda_memset_async(last_lhs, 0, big_lwe_size_bytes, streams[0],
                        gpu_indexes[0]);
      cuda_memset_async(last_rhs, 0, big_lwe_size_bytes, streams[0],
                        gpu_indexes[0]);

      // For step 1 overflow should be enable only if flag overflow
      uint32_t num_bits_in_message = std::log2(message_modulus);
      lut_overflow_flag_prep = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);

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

      auto overflow_flag_prep_lut = lut_overflow_flag_prep->get_lut(0, 0);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], overflow_flag_prep_lut, glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_overflow_fp);

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
      auto overflow_flag_last = lut_message_extract->get_lut(0, 1);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], overflow_flag_last, glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_overflow_last);

      Torus *h_lut_indexes =
          (Torus *)malloc((num_radix_blocks + 1) * sizeof(Torus));
      for (int index = 0; index < num_radix_blocks + 1; index++) {
        if (index < num_radix_blocks) {
          h_lut_indexes[index] = 0;
        } else {
          h_lut_indexes[index] = 1;
        }
      }
      cuda_memcpy_async_to_gpu(
          lut_message_extract->get_lut_indexes(0, 0), h_lut_indexes,
          (num_radix_blocks + 1) * sizeof(Torus), streams[0], gpu_indexes[0]);

      lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);
      free(h_lut_indexes);
    }
    if (requested_flag == outputFlag::FLAG_CARRY) { // Carry case

      auto f_carry_last = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };
      auto carry_flag_last = lut_message_extract->get_lut(0, 1);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], carry_flag_last, glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_carry_last);

      Torus *h_lut_indexes =
          (Torus *)malloc((num_radix_blocks + 1) * sizeof(Torus));
      for (int index = 0; index < num_radix_blocks + 1; index++) {
        if (index < num_radix_blocks) {
          h_lut_indexes[index] = 0;
        } else {
          h_lut_indexes[index] = 1;
        }
      }
      cuda_memcpy_async_to_gpu(
          lut_message_extract->get_lut_indexes(0, 0), h_lut_indexes,
          (num_radix_blocks + 1) * sizeof(Torus), streams[0], gpu_indexes[0]);

      lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);
      free(h_lut_indexes);
    }

    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);

    incoming_events1 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    incoming_events2 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    outgoing_events1 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    outgoing_events2 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    outgoing_events3 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));
    outgoing_events4 =
        (cudaEvent_t *)malloc(active_gpu_count * sizeof(cudaEvent_t));

    for (uint j = 0; j < active_gpu_count; j++) {
      incoming_events1[j] = cuda_create_event(gpu_indexes[j]);
      incoming_events2[j] = cuda_create_event(gpu_indexes[j]);
      outgoing_events1[j] = cuda_create_event(gpu_indexes[j]);
      outgoing_events2[j] = cuda_create_event(gpu_indexes[j]);
      outgoing_events3[j] = cuda_create_event(gpu_indexes[j]);
      outgoing_events4[j] = cuda_create_event(gpu_indexes[j]);
    }
  };

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    shifted_blocks_state_mem->release(streams, gpu_indexes, gpu_count);
    prop_simu_group_carries_mem->release(streams, gpu_indexes, gpu_count);
    cuda_drop_async(output_flag, streams[0], gpu_indexes[0]);
    lut_message_extract->release(streams, gpu_indexes, gpu_count);
    delete lut_message_extract;

    if (requested_flag == outputFlag::FLAG_OVERFLOW) { // In case of overflow
      lut_overflow_flag_prep->release(streams, gpu_indexes, gpu_count);
      delete lut_overflow_flag_prep;
      cuda_drop_async(last_lhs, streams[0], gpu_indexes[0]);
      cuda_drop_async(last_rhs, streams[0], gpu_indexes[0]);
    }

    // release events
    for (uint j = 0; j < active_gpu_count; j++) {
      cuda_event_destroy(incoming_events1[j], gpu_indexes[j]);
      cuda_event_destroy(incoming_events2[j], gpu_indexes[j]);
      cuda_event_destroy(outgoing_events1[j], gpu_indexes[j]);
      cuda_event_destroy(outgoing_events2[j], gpu_indexes[j]);
      cuda_event_destroy(outgoing_events3[j], gpu_indexes[j]);
      cuda_event_destroy(outgoing_events4[j], gpu_indexes[j]);
    }
    free(incoming_events1);
    free(incoming_events2);
    free(outgoing_events1);
    free(outgoing_events2);
    free(outgoing_events3);
    free(outgoing_events4);
  };
};

template <typename Torus> struct int_shifted_blocks_and_borrow_states_memory {
  Torus *shifted_blocks_and_borrow_states;
  Torus *shifted_blocks;
  Torus *borrow_states;

  int_radix_lut<Torus> *luts_array_first_step;

  int_shifted_blocks_and_borrow_states_memory(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t num_many_lut, uint32_t grouping_size, bool allocate_gpu_memory) {

    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    shifted_blocks_and_borrow_states = (Torus *)cuda_malloc_async(
        num_many_lut * num_radix_blocks * big_lwe_size_bytes, streams[0],
        gpu_indexes[0]);
    cuda_memset_async(shifted_blocks_and_borrow_states, 0,
                      num_many_lut * num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);
    shifted_blocks = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(shifted_blocks, 0, num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);
    borrow_states = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    cuda_memset_async(borrow_states, 0, num_radix_blocks * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);

    uint32_t num_luts_first_step = 2 * grouping_size + 1;

    luts_array_first_step = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, num_luts_first_step,
        num_radix_blocks, num_many_lut, allocate_gpu_memory);

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

    generate_many_lut_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], first_block_lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_first_grouping_luts);

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
      generate_many_lut_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_grouping_luts);
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

      generate_many_lut_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], lut, glwe_dimension, polynomial_size,
          message_modulus, carry_modulus, f_grouping_luts);
    }

    auto f_last_block_state = [message_modulus](Torus block) -> Torus {
      if (block < message_modulus)
        return 2 << 1; // Generates a borrow
      else
        return 0; // Nothing
    };

    uint32_t lut_id = num_luts_first_step - 1; // The last lut of the first step

    auto last_block_lut = luts_array_first_step->get_lut(0, lut_id);

    std::vector<std::function<Torus(Torus)>> f_last_grouping_luts = {
        f_last_block_state, f_shift_block};

    generate_many_lut_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], last_block_lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_last_grouping_luts);

    // Generate the indexes to switch between luts within the pbs
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus *h_lut_indexes = (Torus *)malloc(lut_indexes_size);

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
    cuda_memcpy_async_to_gpu(lut_indexes, h_lut_indexes, lut_indexes_size,
                             streams[0], gpu_indexes[0]);
    // Do I need to do something else for the multi-gpu?

    luts_array_first_step->broadcast_lut(streams, gpu_indexes, 0);

    free(h_lut_indexes);
  };

  // needed for the division to update the lut indexes
  void update_lut_indexes(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes, Torus *new_lut_indexes,
                          uint32_t new_num_blocks) {
    Torus *lut_indexes = luts_array_first_step->get_lut_indexes(0, 0);
    cuda_memcpy_async_gpu_to_gpu(lut_indexes, new_lut_indexes,
                                 new_num_blocks * sizeof(Torus), streams[0],
                                 gpu_indexes[0]);
    luts_array_first_step->broadcast_lut(streams, gpu_indexes, 0);
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    cuda_drop_async(shifted_blocks_and_borrow_states, streams[0],
                    gpu_indexes[0]);
    cuda_drop_async(shifted_blocks, streams[0], gpu_indexes[0]);
    cuda_drop_async(borrow_states, streams[0], gpu_indexes[0]);

    luts_array_first_step->release(streams, gpu_indexes, gpu_count);
    delete luts_array_first_step;
  };
};

template <typename Torus> struct int_borrow_prop_memory {
  uint32_t num_many_lut;
  uint32_t lut_stride;

  uint32_t group_size;
  uint32_t num_groups;
  Torus *overflow_block;

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
  int_borrow_prop_memory(cudaStream_t const *streams,
                         uint32_t const *gpu_indexes, uint32_t gpu_count,
                         int_radix_params params, uint32_t num_radix_blocks,
                         uint32_t compute_overflow_in,
                         bool allocate_gpu_memory) {
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
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
            num_many_lut, grouping_size, true);

    prop_simu_group_carries_mem = new int_prop_simu_group_carries_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        grouping_size, num_groups, true);

    overflow_block = (Torus *)cuda_malloc_async(big_lwe_size_bytes, streams[0],
                                                gpu_indexes[0]);
    cuda_memset_async(overflow_block, 0, big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);

    lut_message_extract =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                 num_radix_blocks, allocate_gpu_memory);
    // lut for the first block in the first grouping
    auto f_message_extract = [message_modulus](Torus block) -> Torus {
      return (block >> 1) % message_modulus;
    };

    auto extract_lut = lut_message_extract->get_lut(0, 0);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], extract_lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus, f_message_extract);

    lut_message_extract->broadcast_lut(streams, gpu_indexes, 0);

    if (compute_overflow) {
      lut_borrow_flag =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);
      // lut for the first block in the first grouping
      auto f_borrow_flag = [](Torus block) -> Torus {
        return ((block >> 2) & 1);
      };

      auto borrow_flag_lut = lut_borrow_flag->get_lut(0, 0);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], borrow_flag_lut, glwe_dimension,
          polynomial_size, message_modulus, carry_modulus, f_borrow_flag);

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
    cuda_drop_async(overflow_block, streams[0], gpu_indexes[0]);

    lut_message_extract->release(streams, gpu_indexes, gpu_count);
    delete lut_message_extract;
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

  Torus *tmp;

  cudaStream_t *true_streams;
  cudaStream_t *false_streams;
  uint32_t active_gpu_count;

  int_zero_out_if_buffer(cudaStream_t const *streams,
                         uint32_t const *gpu_indexes, uint32_t gpu_count,
                         int_radix_params params, uint32_t num_radix_blocks,
                         bool allocate_gpu_memory) {
    this->params = params;
    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);

    Torus big_size =
        (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
    if (allocate_gpu_memory) {
      tmp = (Torus *)cuda_malloc_async(big_size, streams[0], gpu_indexes[0]);
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
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(tmp, streams[0], gpu_indexes[0]);
    for (uint j = 0; j < active_gpu_count; j++) {
      cuda_destroy_stream(true_streams[j], gpu_indexes[j]);
      cuda_destroy_stream(false_streams[j], gpu_indexes[j]);
    }
    free(true_streams);
    free(false_streams);
  }
};

template <typename Torus> struct int_mul_memory {
  Torus *vector_result_sb;
  Torus *block_mul_res;
  Torus *small_lwe_vector;

  int_radix_lut<Torus> *luts_array; // lsb msb
  int_radix_lut<Torus> *zero_out_predicate_lut;

  int_sum_ciphertexts_vec_memory<Torus> *sum_ciphertexts_mem;
  int_sc_prop_memory<Torus> *sc_prop_mem;
  int_zero_out_if_buffer<Torus> *zero_out_mem;

  int_radix_params params;
  bool boolean_mul = false;

  int_mul_memory(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                 uint32_t gpu_count, int_radix_params params,
                 bool const is_boolean_left, bool const is_boolean_right,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory) {
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
      zero_out_predicate_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);
      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], zero_out_predicate_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, zero_out_predicate_lut_f);
      zero_out_predicate_lut->broadcast_lut(streams, gpu_indexes, 0);

      zero_out_mem = new int_zero_out_if_buffer<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks,
          allocate_gpu_memory);

      return;
    }

    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto lwe_dimension = params.small_lwe_dimension;

    // 'vector_result_lsb' contains blocks from all possible shifts of
    // radix_lwe_left excluding zero ciphertext blocks
    int lsb_vector_block_count = num_radix_blocks * (num_radix_blocks + 1) / 2;

    // 'vector_result_msb' contains blocks from all possible shifts of
    // radix_lwe_left except the last blocks of each shift
    int msb_vector_block_count = num_radix_blocks * (num_radix_blocks - 1) / 2;

    int total_block_count = lsb_vector_block_count + msb_vector_block_count;

    // allocate memory for intermediate buffers
    vector_result_sb = (Torus *)cuda_malloc_async(
        2 * total_block_count * (polynomial_size * glwe_dimension + 1) *
            sizeof(Torus),
        streams[0], gpu_indexes[0]);
    block_mul_res = (Torus *)cuda_malloc_async(
        2 * total_block_count * (polynomial_size * glwe_dimension + 1) *
            sizeof(Torus),
        streams[0], gpu_indexes[0]);
    small_lwe_vector = (Torus *)cuda_malloc_async(
        total_block_count * (lwe_dimension + 1) * sizeof(Torus), streams[0],
        gpu_indexes[0]);

    // create int_radix_lut objects for lsb, msb, message, carry
    // luts_array -> lut = {lsb_acc, msb_acc}
    luts_array =
        new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                 total_block_count, allocate_gpu_memory);
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
        streams[0], gpu_indexes[0], lsb_acc, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, lut_f_lsb);
    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], msb_acc, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, lut_f_msb);

    // lut_indexes_vec for luts_array should be reinitialized
    // first lsb_vector_block_count value should reference to lsb_acc
    // last msb_vector_block_count values should reference to msb_acc
    // for message and carry default lut_indexes_vec is fine
    cuda_set_value_async<Torus>(
        streams[0], gpu_indexes[0],
        luts_array->get_lut_indexes(0, lsb_vector_block_count), 1,
        msb_vector_block_count);

    luts_array->broadcast_lut(streams, gpu_indexes, 0);
    // create memory object for sum ciphertexts
    sum_ciphertexts_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        2 * num_radix_blocks, block_mul_res, vector_result_sb,
        small_lwe_vector);
    uint32_t uses_carry = 0;
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_radix_blocks,
        requested_flag, uses_carry, allocate_gpu_memory);
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
    cuda_drop_async(vector_result_sb, streams[0], gpu_indexes[0]);
    cuda_drop_async(block_mul_res, streams[0], gpu_indexes[0]);
    cuda_drop_async(small_lwe_vector, streams[0], gpu_indexes[0]);

    luts_array->release(streams, gpu_indexes, gpu_count);
    sum_ciphertexts_mem->release(streams, gpu_indexes, gpu_count);
    sc_prop_mem->release(streams, gpu_indexes, gpu_count);

    delete luts_array;
    delete sum_ciphertexts_mem;
    delete sc_prop_mem;
  }
};

template <typename Torus> struct int_logical_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  Torus *tmp_rotated;

  bool reuse_memory = false;

  int_logical_scalar_shift_buffer(cudaStream_t const *streams,
                                  uint32_t const *gpu_indexes,
                                  uint32_t gpu_count,
                                  SHIFT_OR_ROTATE_TYPE shift_type,
                                  int_radix_params params,
                                  uint32_t num_radix_blocks,
                                  bool allocate_gpu_memory) {
    this->shift_type = shift_type;
    this->params = params;

    if (allocate_gpu_memory) {
      uint32_t max_amount_of_pbs = num_radix_blocks;
      uint32_t big_lwe_size = params.big_lwe_dimension + 1;
      uint32_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

      tmp_rotated = (Torus *)cuda_malloc_async((max_amount_of_pbs + 2) *
                                                   big_lwe_size_bytes,
                                               streams[0], gpu_indexes[0]);

      cuda_memset_async(tmp_rotated, 0,
                        (max_amount_of_pbs + 2) * big_lwe_size_bytes,
                        streams[0], gpu_indexes[0]);

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
        auto cur_lut_bivariate =
            new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                     num_radix_blocks, allocate_gpu_memory);

        uint32_t shift_within_block = s_w_b;

        std::function<Torus(Torus, Torus)> shift_lut_f;

        if (shift_type == LEFT_SHIFT) {
          shift_lut_f = [shift_within_block,
                         params](Torus current_block,
                                 Torus previous_block) -> Torus {
            current_block = current_block << shift_within_block;
            previous_block = previous_block << shift_within_block;

            Torus message_of_current_block =
                current_block % params.message_modulus;
            Torus carry_of_previous_block =
                previous_block / params.message_modulus;
            return message_of_current_block + carry_of_previous_block;
          };
        } else {
          shift_lut_f = [num_bits_in_block, shift_within_block, params](
                            Torus current_block, Torus next_block) -> Torus {
            // left shift so as not to lose
            // bits when shifting right afterwards
            next_block <<= num_bits_in_block;
            next_block >>= shift_within_block;

            // The way of getting carry / message is reversed compared
            // to the usual way but its normal:
            // The message is in the upper bits, the carry in lower bits
            Torus message_of_current_block =
                current_block >> shift_within_block;
            Torus carry_of_previous_block = next_block % params.message_modulus;

            return message_of_current_block + carry_of_previous_block;
          };
        }

        // right shift
        generate_device_accumulator_bivariate<Torus>(
            streams[0], gpu_indexes[0], cur_lut_bivariate->get_lut(0, 0),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, shift_lut_f);
        cur_lut_bivariate->broadcast_lut(streams, gpu_indexes, 0);

        lut_buffers_bivariate.push_back(cur_lut_bivariate);
      }
    }
  }

  int_logical_scalar_shift_buffer(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, SHIFT_OR_ROTATE_TYPE shift_type,
      int_radix_params params, uint32_t num_radix_blocks,
      bool allocate_gpu_memory, Torus *pre_allocated_buffer) {
    this->shift_type = shift_type;
    this->params = params;
    tmp_rotated = pre_allocated_buffer;
    reuse_memory = true;

    uint32_t max_amount_of_pbs = num_radix_blocks;
    uint32_t big_lwe_size = params.big_lwe_dimension + 1;
    uint32_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
    cuda_memset_async(tmp_rotated, 0,
                      (max_amount_of_pbs + 2) * big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);
    if (allocate_gpu_memory) {

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
        auto cur_lut_bivariate =
            new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                     num_radix_blocks, allocate_gpu_memory);

        uint32_t shift_within_block = s_w_b;

        std::function<Torus(Torus, Torus)> shift_lut_f;

        if (shift_type == LEFT_SHIFT) {
          shift_lut_f = [shift_within_block,
                         params](Torus current_block,
                                 Torus previous_block) -> Torus {
            current_block = current_block << shift_within_block;
            previous_block = previous_block << shift_within_block;

            Torus message_of_current_block =
                current_block % params.message_modulus;
            Torus carry_of_previous_block =
                previous_block / params.message_modulus;
            return message_of_current_block + carry_of_previous_block;
          };
        } else {
          shift_lut_f = [num_bits_in_block, shift_within_block, params](
                            Torus current_block, Torus next_block) -> Torus {
            // left shift so as not to lose
            // bits when shifting right afterwards
            next_block <<= num_bits_in_block;
            next_block >>= shift_within_block;

            // The way of getting carry / message is reversed compared
            // to the usual way but its normal:
            // The message is in the upper bits, the carry in lower bits
            Torus message_of_current_block =
                current_block >> shift_within_block;
            Torus carry_of_previous_block = next_block % params.message_modulus;

            return message_of_current_block + carry_of_previous_block;
          };
        }

        // right shift
        generate_device_accumulator_bivariate<Torus>(
            streams[0], gpu_indexes[0], cur_lut_bivariate->get_lut(0, 0),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, shift_lut_f);
        cur_lut_bivariate->broadcast_lut(streams, gpu_indexes, 0);

        lut_buffers_bivariate.push_back(cur_lut_bivariate);
      }
    }
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    for (auto &buffer : lut_buffers_bivariate) {
      buffer->release(streams, gpu_indexes, gpu_count);
      delete buffer;
    }
    lut_buffers_bivariate.clear();

    if (!reuse_memory)
      cuda_drop_async(tmp_rotated, streams[0], gpu_indexes[0]);
  }
};

template <typename Torus> struct int_arithmetic_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_univariate;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  Torus *tmp_rotated;

  cudaStream_t *local_streams_1;
  cudaStream_t *local_streams_2;
  uint32_t active_gpu_count;

  int_arithmetic_scalar_shift_buffer(cudaStream_t const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count,
                                     SHIFT_OR_ROTATE_TYPE shift_type,
                                     int_radix_params params,
                                     uint32_t num_radix_blocks,
                                     bool allocate_gpu_memory) {
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

    if (allocate_gpu_memory) {
      uint32_t big_lwe_size = params.big_lwe_dimension + 1;
      uint32_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

      tmp_rotated = (Torus *)cuda_malloc_async((num_radix_blocks + 3) *
                                                   big_lwe_size_bytes,
                                               streams[0], gpu_indexes[0]);

      cuda_memset_async(tmp_rotated, 0,
                        (num_radix_blocks + 3) * big_lwe_size_bytes, streams[0],
                        gpu_indexes[0]);

      uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

      // LUT
      // pregenerate lut vector and indexes lut

      // lut to shift the last block
      // calculate lut for each 'shift_within_block'
      // so that in case an application calls scratches only once for a whole
      // circuit it can reuse memory for different shift values
      // With two bits of message this is actually only one LUT.
      for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
        auto shift_last_block_lut_univariate = new int_radix_lut<Torus>(
            streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);

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
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, last_block_lut_f);
        shift_last_block_lut_univariate->broadcast_lut(streams, gpu_indexes, 0);

        lut_buffers_univariate.push_back(shift_last_block_lut_univariate);
      }

      auto padding_block_lut_univariate = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);

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
          streams[0], gpu_indexes[0],
          padding_block_lut_univariate->get_lut(0, 0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          padding_block_lut_f);
      padding_block_lut_univariate->broadcast_lut(streams, gpu_indexes, 0);

      lut_buffers_univariate.push_back(padding_block_lut_univariate);

      // lut to shift the first blocks
      // calculate lut for each 'shift_within_block'
      // so that in case an application calls scratches only once for a whole
      // circuit it can reuse memory for different shift values
      // NB: with two bits of message, this is actually only one LUT.
      for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
        auto shift_blocks_lut_bivariate =
            new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                     num_radix_blocks, allocate_gpu_memory);

        uint32_t shift_within_block = s_w_b;

        std::function<Torus(Torus, Torus)> blocks_lut_f;
        blocks_lut_f = [num_bits_in_block, shift_within_block, params](
                           Torus current_block, Torus next_block) -> Torus {
          // left shift so as not to lose
          // bits when shifting right after
          next_block <<= num_bits_in_block;
          next_block >>= shift_within_block;

          // The way of getting carry / message is reversed compared
          // to the usual way but its normal:
          // The message is in the upper bits, the carry in lower bits
          uint32_t message_of_current_block =
              current_block >> shift_within_block;
          uint32_t carry_of_previous_block =
              next_block % params.message_modulus;

          return message_of_current_block + carry_of_previous_block;
        };

        generate_device_accumulator_bivariate<Torus>(
            streams[0], gpu_indexes[0],
            shift_blocks_lut_bivariate->get_lut(0, 0), params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, blocks_lut_f);
        shift_blocks_lut_bivariate->broadcast_lut(streams, gpu_indexes, 0);

        lut_buffers_bivariate.push_back(shift_blocks_lut_bivariate);
      }
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

    cuda_drop_async(tmp_rotated, streams[0], gpu_indexes[0]);
  }
};

template <typename Torus> struct int_cmux_buffer {
  int_radix_lut<Torus> *predicate_lut;
  int_radix_lut<Torus> *message_extract_lut;

  CudaRadixCiphertextFFI *buffer_in = new CudaRadixCiphertextFFI;
  CudaRadixCiphertextFFI *buffer_out = new CudaRadixCiphertextFFI;
  CudaRadixCiphertextFFI *condition_array = new CudaRadixCiphertextFFI;

  int_radix_params params;

  int_cmux_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                  uint32_t gpu_count,
                  std::function<Torus(Torus)> predicate_lut_f,
                  int_radix_params params, uint32_t num_radix_blocks,
                  bool allocate_gpu_memory) {

    this->params = params;

    if (allocate_gpu_memory) {
      create_trivial_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], buffer_in, 2 * num_radix_blocks,
          params.big_lwe_dimension);
      create_trivial_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], buffer_out, 2 * num_radix_blocks,
          params.big_lwe_dimension);
      create_trivial_radix_ciphertext_async<Torus>(
          streams[0], gpu_indexes[0], condition_array, 2 * num_radix_blocks,
          params.big_lwe_dimension);

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

      predicate_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                   2 * num_radix_blocks, allocate_gpu_memory);

      message_extract_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], predicate_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, inverted_lut_f);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], predicate_lut->get_lut(0, 1),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, lut_f);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], message_extract_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, message_extract_lut_f);
      Torus *h_lut_indexes =
          (Torus *)malloc(2 * num_radix_blocks * sizeof(Torus));
      for (int index = 0; index < 2 * num_radix_blocks; index++) {
        if (index < num_radix_blocks) {
          h_lut_indexes[index] = 0;
        } else {
          h_lut_indexes[index] = 1;
        }
      }
      cuda_memcpy_async_to_gpu(
          predicate_lut->get_lut_indexes(0, 0), h_lut_indexes,
          2 * num_radix_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);

      predicate_lut->broadcast_lut(streams, gpu_indexes, 0);
      message_extract_lut->broadcast_lut(streams, gpu_indexes, 0);
      free(h_lut_indexes);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    predicate_lut->release(streams, gpu_indexes, gpu_count);
    delete predicate_lut;
    message_extract_lut->release(streams, gpu_indexes, gpu_count);
    delete message_extract_lut;

    release_radix_ciphertext(streams[0], gpu_indexes[0], buffer_in);
    delete buffer_in;
    release_radix_ciphertext(streams[0], gpu_indexes[0], buffer_out);
    delete buffer_out;
    release_radix_ciphertext(streams[0], gpu_indexes[0], condition_array);
    delete condition_array;
  }
};

template <typename Torus> struct int_are_all_block_true_buffer {
  COMPARISON_TYPE op;
  int_radix_params params;

  Torus *tmp_out;
  Torus *tmp_block_accumulated;

  // This map store LUTs that checks the equality between some input and values
  // of interest in are_all_block_true(), as with max_value (the maximum message
  // value).
  int_radix_lut<Torus> *is_max_value;

  int_are_all_block_true_buffer(cudaStream_t const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                COMPARISON_TYPE op, int_radix_params params,
                                uint32_t num_radix_blocks,
                                bool allocate_gpu_memory) {
    this->params = params;
    this->op = op;

    if (allocate_gpu_memory) {
      Torus total_modulus = params.message_modulus * params.carry_modulus;
      uint32_t max_value = (total_modulus - 1) / (params.message_modulus - 1);

      int max_chunks = (num_radix_blocks + max_value - 1) / max_value;
      tmp_block_accumulated = (Torus *)cuda_malloc_async(
          (params.big_lwe_dimension + 1) * max_chunks * sizeof(Torus),
          streams[0], gpu_indexes[0]);
      tmp_out = (Torus *)cuda_malloc_async((params.big_lwe_dimension + 1) *
                                               num_radix_blocks * sizeof(Torus),
                                           streams[0], gpu_indexes[0]);
      is_max_value =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                   max_chunks, allocate_gpu_memory);
      auto is_max_value_f = [max_value](Torus x) -> Torus {
        return x == max_value;
      };

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], is_max_value->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, is_max_value_f);

      is_max_value->broadcast_lut(streams, gpu_indexes, 0);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    is_max_value->release(streams, gpu_indexes, gpu_count);
    delete (is_max_value);

    cuda_drop_async(tmp_block_accumulated, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_out, streams[0], gpu_indexes[0]);
  }
};

template <typename Torus> struct int_comparison_eq_buffer {
  int_radix_params params;
  COMPARISON_TYPE op;

  int_radix_lut<Torus> *operator_lut;
  int_radix_lut<Torus> *is_non_zero_lut;
  int_radix_lut<Torus> *scalar_comparison_luts;

  int_are_all_block_true_buffer<Torus> *are_all_block_true_buffer;

  int_comparison_eq_buffer(cudaStream_t const *streams,
                           uint32_t const *gpu_indexes, uint32_t gpu_count,
                           COMPARISON_TYPE op, int_radix_params params,
                           uint32_t num_radix_blocks,
                           bool allocate_gpu_memory) {
    this->params = params;
    this->op = op;

    if (allocate_gpu_memory) {

      are_all_block_true_buffer = new int_are_all_block_true_buffer<Torus>(
          streams, gpu_indexes, gpu_count, op, params, num_radix_blocks,
          allocate_gpu_memory);

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
      operator_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], operator_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, operator_f);

      operator_lut->broadcast_lut(streams, gpu_indexes, 0);

      // f(x) -> x == 0
      Torus total_modulus = params.message_modulus * params.carry_modulus;
      auto is_non_zero_lut_f = [total_modulus](Torus x) -> Torus {
        return (x % total_modulus) != 0;
      };

      is_non_zero_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], is_non_zero_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, is_non_zero_lut_f);

      is_non_zero_lut->broadcast_lut(streams, gpu_indexes, 0);

      // Scalar may have up to num_radix_blocks blocks
      scalar_comparison_luts = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, total_modulus,
          num_radix_blocks, allocate_gpu_memory);

      for (int i = 0; i < total_modulus; i++) {
        auto lut_f = [i, operator_f](Torus x) -> Torus {
          return operator_f(i, x);
        };

        Torus *lut = scalar_comparison_luts->get_lut(0, i);

        generate_device_accumulator<Torus>(
            streams[0], gpu_indexes[0], lut, params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, lut_f);
      }

      scalar_comparison_luts->broadcast_lut(streams, gpu_indexes, 0);
    }
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

  Torus *tmp_x;
  Torus *tmp_y;

  int_tree_sign_reduction_buffer(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count,
                                 std::function<Torus(Torus)> operator_f,
                                 int_radix_params params,
                                 uint32_t num_radix_blocks,
                                 bool allocate_gpu_memory) {
    this->params = params;

    Torus big_size = (params.big_lwe_dimension + 1) * sizeof(Torus);

    block_selector_f = [](Torus msb, Torus lsb) -> Torus {
      if (msb == IS_EQUAL) // EQUAL
        return lsb;
      else
        return msb;
    };

    if (allocate_gpu_memory) {
      tmp_x = (Torus *)cuda_malloc_async(big_size * num_radix_blocks,
                                         streams[0], gpu_indexes[0]);
      tmp_y = (Torus *)cuda_malloc_async(big_size * num_radix_blocks,
                                         streams[0], gpu_indexes[0]);
      // LUTs
      tree_inner_leaf_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);

      tree_last_leaf_lut = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);

      tree_last_leaf_scalar_lut = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);
      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], tree_inner_leaf_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, block_selector_f);

      tree_inner_leaf_lut->broadcast_lut(streams, gpu_indexes, 0);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    tree_inner_leaf_lut->release(streams, gpu_indexes, gpu_count);
    delete tree_inner_leaf_lut;
    tree_last_leaf_lut->release(streams, gpu_indexes, gpu_count);
    delete tree_last_leaf_lut;
    tree_last_leaf_scalar_lut->release(streams, gpu_indexes, gpu_count);
    delete tree_last_leaf_scalar_lut;

    cuda_drop_async(tmp_x, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_y, streams[0], gpu_indexes[0]);
  }
};

template <typename Torus> struct int_comparison_diff_buffer {
  int_radix_params params;
  COMPARISON_TYPE op;

  Torus *tmp_packed;

  std::function<Torus(Torus)> operator_f;

  int_tree_sign_reduction_buffer<Torus> *tree_buffer;

  Torus *tmp_signs_a;
  Torus *tmp_signs_b;
  int_radix_lut<Torus> *reduce_signs_lut;

  int_comparison_diff_buffer(cudaStream_t const *streams,
                             uint32_t const *gpu_indexes, uint32_t gpu_count,
                             COMPARISON_TYPE op, int_radix_params params,
                             uint32_t num_radix_blocks,
                             bool allocate_gpu_memory) {
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
    if (allocate_gpu_memory) {

      Torus big_size = (params.big_lwe_dimension + 1) * sizeof(Torus);

      tmp_packed = (Torus *)cuda_malloc_async(big_size * num_radix_blocks,
                                              streams[0], gpu_indexes[0]);

      tree_buffer = new int_tree_sign_reduction_buffer<Torus>(
          streams, gpu_indexes, gpu_count, operator_f, params, num_radix_blocks,
          allocate_gpu_memory);
      tmp_signs_a = (Torus *)cuda_malloc_async(big_size * num_radix_blocks,
                                               streams[0], gpu_indexes[0]);
      tmp_signs_b = (Torus *)cuda_malloc_async(big_size * num_radix_blocks,
                                               streams[0], gpu_indexes[0]);
      // LUTs
      reduce_signs_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    tree_buffer->release(streams, gpu_indexes, gpu_count);
    delete tree_buffer;
    reduce_signs_lut->release(streams, gpu_indexes, gpu_count);
    delete reduce_signs_lut;

    cuda_drop_async(tmp_packed, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_signs_a, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_signs_b, streams[0], gpu_indexes[0]);
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

  Torus *tmp_block_comparisons;
  Torus *tmp_lwe_array_out;
  Torus *tmp_trivial_sign_block;

  // Scalar EQ / NE
  Torus *tmp_packed_input;

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

  int_comparison_buffer(cudaStream_t const *streams,
                        uint32_t const *gpu_indexes, uint32_t gpu_count,
                        COMPARISON_TYPE op, int_radix_params params,
                        uint32_t num_radix_blocks, bool is_signed,
                        bool allocate_gpu_memory) {
    this->params = params;
    this->op = op;
    this->is_signed = is_signed;

    active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);

    identity_lut_f = [](Torus x) -> Torus { return x; };

    auto big_lwe_size = params.big_lwe_dimension + 1;

    if (allocate_gpu_memory) {
      lsb_streams =
          (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
      msb_streams =
          (cudaStream_t *)malloc(active_gpu_count * sizeof(cudaStream_t));
      for (uint j = 0; j < active_gpu_count; j++) {
        lsb_streams[j] = cuda_create_stream(gpu_indexes[j]);
        msb_streams[j] = cuda_create_stream(gpu_indexes[j]);
      }

      // +1 to have space for signed comparison
      tmp_lwe_array_out = (Torus *)cuda_malloc_async(
          big_lwe_size * (num_radix_blocks + 1) * sizeof(Torus), streams[0],
          gpu_indexes[0]);

      tmp_packed_input = (Torus *)cuda_malloc_async(
          big_lwe_size * 2 * num_radix_blocks * sizeof(Torus), streams[0],
          gpu_indexes[0]);

      // Block comparisons
      tmp_block_comparisons = (Torus *)cuda_malloc_async(
          big_lwe_size * num_radix_blocks * sizeof(Torus), streams[0],
          gpu_indexes[0]);

      // Cleaning LUT
      identity_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], identity_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, identity_lut_f);

      identity_lut->broadcast_lut(streams, gpu_indexes, 0);

      uint32_t total_modulus = params.message_modulus * params.carry_modulus;
      auto is_zero_f = [total_modulus](Torus x) -> Torus {
        return (x % total_modulus) == 0;
      };

      is_zero_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], is_zero_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, is_zero_f);

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
            params, num_radix_blocks, allocate_gpu_memory);
      case COMPARISON_TYPE::GT:
      case COMPARISON_TYPE::GE:
      case COMPARISON_TYPE::LT:
      case COMPARISON_TYPE::LE:
        diff_buffer = new int_comparison_diff_buffer<Torus>(
            streams, gpu_indexes, gpu_count, op, params, num_radix_blocks,
            allocate_gpu_memory);
      case COMPARISON_TYPE::EQ:
      case COMPARISON_TYPE::NE:
        eq_buffer = new int_comparison_eq_buffer<Torus>(
            streams, gpu_indexes, gpu_count, op, params, num_radix_blocks,
            allocate_gpu_memory);
        break;
      default:
        PANIC("Unsupported comparison operation.")
      }

      if (is_signed) {

        tmp_trivial_sign_block = (Torus *)cuda_malloc_async(
            big_lwe_size * sizeof(Torus), streams[0], gpu_indexes[0]);

        signed_lut = new int_radix_lut<Torus>(
            streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);
        signed_msb_lut = new int_radix_lut<Torus>(
            streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);

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
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, signed_lut_f);

        signed_lut->broadcast_lut(streams, gpu_indexes, 0);
      }
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
    identity_lut->release(streams, gpu_indexes, gpu_count);
    delete identity_lut;
    is_zero_lut->release(streams, gpu_indexes, gpu_count);
    delete is_zero_lut;
    cuda_drop_async(tmp_lwe_array_out, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_block_comparisons, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_packed_input, streams[0], gpu_indexes[0]);

    if (is_signed) {
      cuda_drop_async(tmp_trivial_sign_block, streams[0], gpu_indexes[0]);
      signed_lut->release(streams, gpu_indexes, gpu_count);
      delete (signed_lut);
      signed_msb_lut->release(streams, gpu_indexes, gpu_count);
      delete (signed_msb_lut);
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
  Torus *remainder1;
  Torus *remainder2;
  Torus *numerator_block_stack;
  Torus *numerator_block_1;
  Torus *tmp_radix;
  Torus *interesting_remainder1;
  Torus *interesting_remainder2;
  Torus *interesting_divisor;
  Torus *divisor_ms_blocks;
  Torus *new_remainder;
  Torus *subtraction_overflowed;
  Torus *did_not_overflow;
  Torus *overflow_sum;
  Torus *overflow_sum_radix;
  Torus *tmp_1;
  Torus *at_least_one_upper_block_is_non_zero;
  Torus *cleaned_merged_interesting_remainder;

  Torus **first_indexes_for_overflow_sub;
  Torus **second_indexes_for_overflow_sub;
  Torus **scalars_for_overflow_sub;
  uint32_t max_indexes_to_erase;

  // allocate and initialize if needed, temporary arrays used to calculate
  // cuda integer div_rem operation
  void init_temporary_buffers(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              uint32_t num_blocks) {
    uint32_t big_lwe_size = params.big_lwe_dimension + 1;

    // non boolean temporary arrays, with `num_blocks` blocks
    remainder1 = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    remainder2 = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    numerator_block_stack = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    interesting_remainder2 = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    interesting_divisor = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    divisor_ms_blocks = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    new_remainder = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    cleaned_merged_interesting_remainder = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    tmp_1 = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);

    // temporary arrays used as stacks
    tmp_radix = (Torus *)cuda_malloc_async(big_lwe_size * (num_blocks + 1) *
                                               sizeof(Torus),
                                           streams[0], gpu_indexes[0]);
    interesting_remainder1 = (Torus *)cuda_malloc_async(
        big_lwe_size * (num_blocks + 1) * sizeof(Torus), streams[0],
        gpu_indexes[0]);
    numerator_block_1 = (Torus *)cuda_malloc_async(
        big_lwe_size * 2 * sizeof(Torus), streams[0], gpu_indexes[0]);

    // temporary arrays for boolean blocks
    subtraction_overflowed = (Torus *)cuda_malloc_async(
        big_lwe_size * 1 * sizeof(Torus), streams[0], gpu_indexes[0]);
    did_not_overflow = (Torus *)cuda_malloc_async(
        big_lwe_size * 1 * sizeof(Torus), streams[0], gpu_indexes[0]);
    overflow_sum = (Torus *)cuda_malloc_async(big_lwe_size * 1 * sizeof(Torus),
                                              streams[0], gpu_indexes[0]);
    overflow_sum_radix = (Torus *)cuda_malloc_async(
        big_lwe_size * num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    at_least_one_upper_block_is_non_zero = (Torus *)cuda_malloc_async(
        big_lwe_size * 1 * sizeof(Torus), streams[0], gpu_indexes[0]);
  }

  // initialize lookup tables for div_rem operation
  void init_lookup_tables(cudaStream_t const *streams,
                          uint32_t const *gpu_indexes, uint32_t gpu_count,
                          uint32_t num_blocks) {
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

      masking_luts_1[i] = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, 1, true);
      masking_luts_2[i] = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, num_blocks, true);

      int_radix_lut<Torus> *luts[2] = {masking_luts_1[i], masking_luts_2[i]};

      for (int j = 0; j < 2; j++) {
        generate_device_accumulator<Torus>(
            streams[0], gpu_indexes[0], luts[j]->get_lut(0, 0),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, lut_f_masking);
        luts[j]->broadcast_lut(streams, gpu_indexes, 0);
      }
    }

    // create and generate message_extract_lut_1 and message_extract_lut_2
    // both of them are equal but because they are used in two different
    // executions in parallel we need two different pbs_buffers.
    message_extract_lut_1 = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_blocks, true);
    message_extract_lut_2 = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_blocks, true);

    auto message_modulus = params.message_modulus;
    auto lut_f_message_extract = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };

    int_radix_lut<Torus> *luts[2] = {message_extract_lut_1,
                                     message_extract_lut_2};
    for (int j = 0; j < 2; j++) {
      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], luts[j]->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, lut_f_message_extract);
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
    zero_out_if_overflow_did_not_happen[0] = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_blocks, true);
    zero_out_if_overflow_did_not_happen[1] = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_blocks, true);

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
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, cur_lut_f, 2);
    zero_out_if_overflow_did_not_happen[0]->broadcast_lut(streams, gpu_indexes,
                                                          0);
    generate_device_accumulator_bivariate_with_factor<Torus>(
        streams[0], gpu_indexes[0],
        zero_out_if_overflow_did_not_happen[1]->get_lut(0, 0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, cur_lut_f, 3);
    zero_out_if_overflow_did_not_happen[1]->broadcast_lut(streams, gpu_indexes,
                                                          0);

    // create and generate zero_out_if_overflow_happened
    zero_out_if_overflow_happened = new int_radix_lut<Torus> *[2];
    zero_out_if_overflow_happened[0] = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_blocks, true);
    zero_out_if_overflow_happened[1] = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, num_blocks, true);

    auto overflow_happened_f = [&](Torus block, Torus overflow_sum) -> Torus {
      if (overflow_happened(overflow_sum)) {
        return 0;
      } else {
        return block;
      }
    };

    generate_device_accumulator_bivariate_with_factor<Torus>(
        streams[0], gpu_indexes[0],
        zero_out_if_overflow_happened[0]->get_lut(0, 0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        overflow_happened_f, 2);
    zero_out_if_overflow_happened[0]->broadcast_lut(streams, gpu_indexes, 0);
    generate_device_accumulator_bivariate_with_factor<Torus>(
        streams[0], gpu_indexes[0],
        zero_out_if_overflow_happened[1]->get_lut(0, 0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        overflow_happened_f, 3);
    zero_out_if_overflow_happened[1]->broadcast_lut(streams, gpu_indexes, 0);

    // merge_overflow_flags_luts
    merge_overflow_flags_luts = new int_radix_lut<Torus> *[num_bits_in_message];
    for (int i = 0; i < num_bits_in_message; i++) {
      auto lut_f_bit = [i](Torus x, Torus y) -> Torus {
        return (x == 0 && y == 0) << i;
      };

      merge_overflow_flags_luts[i] = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, 1, true);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0],
          merge_overflow_flags_luts[i]->get_lut(0, 0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          lut_f_bit);
      merge_overflow_flags_luts[i]->broadcast_lut(streams, gpu_indexes, 0);
    }
  }

  unsigned_int_div_rem_memory(cudaStream_t const *streams,
                              uint32_t const *gpu_indexes, uint32_t gpu_count,
                              int_radix_params params, uint32_t num_blocks,
                              bool allocate_gpu_memory) {
    active_gpu_count = get_active_gpu_count(2 * num_blocks, gpu_count);

    this->params = params;
    shift_mem_1 = new int_logical_scalar_shift_buffer<Torus>(
        streams, gpu_indexes, gpu_count, SHIFT_OR_ROTATE_TYPE::LEFT_SHIFT,
        params, 2 * num_blocks, true);

    shift_mem_2 = new int_logical_scalar_shift_buffer<Torus>(
        streams, gpu_indexes, gpu_count, SHIFT_OR_ROTATE_TYPE::LEFT_SHIFT,
        params, 2 * num_blocks, true);

    uint32_t compute_overflow = 1;
    overflow_sub_mem = new int_borrow_prop_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_blocks, compute_overflow,
        true);
    uint32_t group_size = overflow_sub_mem->group_size;
    bool use_seq = overflow_sub_mem->prop_simu_group_carries_mem
                       ->use_sequential_algorithm_to_resolver_group_carries;
    create_indexes_for_overflow_sub(streams, gpu_indexes, num_blocks,
                                    group_size, use_seq);

    comparison_buffer = new int_comparison_buffer<Torus>(
        streams, gpu_indexes, gpu_count, COMPARISON_TYPE::NE, params,
        num_blocks, false, true);

    init_lookup_tables(streams, gpu_indexes, gpu_count, num_blocks);
    init_temporary_buffers(streams, gpu_indexes, gpu_count, num_blocks);

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
                                       bool use_seq) {
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
      cudaMalloc((void **)&first_indexes_for_overflow_sub[nb - 1],
                 nb * sizeof(Torus));
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
      cuda_memcpy_async_to_gpu(first_indexes_for_overflow_sub[nb - 1],
                               h_lut_indexes, nb * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
    }
    // Extra indexes for the luts in second step
    for (int nb = 1; nb <= num_blocks; nb++) {
      cudaMalloc((void **)&second_indexes_for_overflow_sub[nb - 1],
                 nb * sizeof(Torus));
      cudaMalloc((void **)&scalars_for_overflow_sub[nb - 1],
                 nb * sizeof(Torus));

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
      cuda_memcpy_async_to_gpu(second_indexes_for_overflow_sub[nb - 1],
                               h_lut_indexes, nb * sizeof(Torus), streams[0],
                               gpu_indexes[0]);
      cuda_memcpy_async_to_gpu(scalars_for_overflow_sub[nb - 1], h_scalar,
                               nb * sizeof(Torus), streams[0], gpu_indexes[0]);
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

    // drop temporary buffers
    cuda_drop_async(remainder1, streams[0], gpu_indexes[0]);
    cuda_drop_async(remainder2, streams[0], gpu_indexes[0]);
    cuda_drop_async(numerator_block_stack, streams[0], gpu_indexes[0]);
    cuda_drop_async(numerator_block_1, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_radix, streams[0], gpu_indexes[0]);
    cuda_drop_async(interesting_remainder1, streams[0], gpu_indexes[0]);
    cuda_drop_async(interesting_remainder2, streams[0], gpu_indexes[0]);
    cuda_drop_async(interesting_divisor, streams[0], gpu_indexes[0]);
    cuda_drop_async(divisor_ms_blocks, streams[0], gpu_indexes[0]);
    cuda_drop_async(new_remainder, streams[0], gpu_indexes[0]);
    cuda_drop_async(subtraction_overflowed, streams[0], gpu_indexes[0]);
    cuda_drop_async(did_not_overflow, streams[0], gpu_indexes[0]);
    cuda_drop_async(overflow_sum, streams[0], gpu_indexes[0]);
    cuda_drop_async(overflow_sum_radix, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_1, streams[0], gpu_indexes[0]);
    cuda_drop_async(at_least_one_upper_block_is_non_zero, streams[0],
                    gpu_indexes[0]);
    cuda_drop_async(cleaned_merged_interesting_remainder, streams[0],
                    gpu_indexes[0]);

    for (int i = 0; i < max_indexes_to_erase; i++) {
      cuda_drop_async(first_indexes_for_overflow_sub[i], streams[0],
                      gpu_indexes[0]);
      cuda_drop_async(second_indexes_for_overflow_sub[i], streams[0],
                      gpu_indexes[0]);
      cuda_drop_async(scalars_for_overflow_sub[i], streams[0], gpu_indexes[0]);
    }
    free(first_indexes_for_overflow_sub);
    free(second_indexes_for_overflow_sub);
    free(scalars_for_overflow_sub);
  }
};

template <typename Torus> struct int_last_block_inner_propagate_memory {

  int_radix_lut<Torus> *last_block_inner_propagation_lut;
  int_radix_params params;

  int_last_block_inner_propagate_memory(
      cudaStream_t const *streams, uint32_t const *gpu_indexes,
      uint32_t gpu_count, int_radix_params params, SIGNED_OPERATION op,
      uint32_t num_radix_blocks, bool allocate_gpu_memory) {

    this->params = params;
    auto message_modulus = params.message_modulus;
    uint32_t bits_of_message =
        static_cast<uint32_t>(std::log2(params.message_modulus));
    Torus message_bit_mask = (1 << bits_of_message) - 1;

    // declare lambda function for last_block_inner_propagation_lut generation
    auto f_last_block_inner_propagation_lut =
        [op, message_modulus, message_bit_mask,
         bits_of_message](Torus lhs_block, Torus rhs_block) -> Torus {
      uint64_t rhs_block_modified;
      if (op == SIGNED_OPERATION::SUBTRACTION) {
        // Subtraction is done by adding the negation
        // Negation(x) = bit_flip(x) + 1
        // Only add the flipped value, the +1 will be resolved by carry
        // propagation computation
        uint64_t flipped_rhs = ~rhs_block;

        // Remove the last bit, it's not interesting in this step
        rhs_block_modified = (flipped_rhs << 1) & message_bit_mask;
      } else {
        rhs_block_modified = (rhs_block << 1) & message_bit_mask;
      }

      uint64_t lhs_block_modified = (lhs_block << 1) & message_bit_mask;

      // whole_result contains the result of addition with
      // the carry being in the first bit of carry space
      // the message space contains the message, but with one 0
      // on the right (LSB)
      uint64_t whole_result = lhs_block_modified + rhs_block_modified;
      uint64_t carry = whole_result >> bits_of_message;
      uint64_t result = (whole_result & message_bit_mask) >> 1;
      OUTPUT_CARRY propagation_result;
      if (carry == 1) {
        // Addition of bits before the last one generates a carry
        propagation_result = OUTPUT_CARRY::GENERATED;
      } else if (result == ((message_modulus - 1) >> 1)) {
        // Addition of bits before the last one puts the bits
        // in a state that makes it so that an input carry into the last block
        // gets propagated to the last bit.
        propagation_result = OUTPUT_CARRY::PROPAGATED;
      } else {
        propagation_result = OUTPUT_CARRY::NONE;
      }

      // Shift the propagation result in the carry part
      // to have less noise growth later
      return (static_cast<uint64_t>(propagation_result) << bits_of_message);
    };

    last_block_inner_propagation_lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);

    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0],
        last_block_inner_propagation_lut->get_lut(0, 0), params.glwe_dimension,
        params.polynomial_size, message_modulus, params.carry_modulus,
        f_last_block_inner_propagation_lut);
    last_block_inner_propagation_lut->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    last_block_inner_propagation_lut->release(streams, gpu_indexes, gpu_count);
    delete last_block_inner_propagation_lut;
  }
};

template <typename Torus> struct int_resolve_signed_overflow_memory {

  int_radix_lut<Torus> *resolve_overflow_lut;
  int_radix_params params;

  Torus *x;

  int_resolve_signed_overflow_memory(cudaStream_t const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count,
                                     int_radix_params params,
                                     bool allocate_gpu_memory) {

    this->params = params;

    auto message_modulus = params.message_modulus;

    uint32_t bits_of_message =
        static_cast<uint32_t>(std::log2(message_modulus));

    x = (Torus *)cuda_malloc_async((params.big_lwe_dimension + 1) *
                                       sizeof(Torus),
                                   streams[0], gpu_indexes[0]);

    // declare lambda function for resolve_overflow_lut generation
    auto f_resolve_overflow_lut = [bits_of_message](Torus x) -> Torus {
      Torus carry_propagation = x >> bits_of_message;
      Torus output_carry_of_block = (x >> 1) & 1;
      Torus input_carry_of_block = x & 1;

      // Resolve the carry that the last bit actually receives as input
      Torus input_carry_to_last_bit;
      if (carry_propagation == OUTPUT_CARRY::PROPAGATED) {
        input_carry_to_last_bit = input_carry_of_block;
      } else if (carry_propagation == OUTPUT_CARRY::GENERATED) {
        input_carry_to_last_bit = 1;
      } else {
        input_carry_to_last_bit = 0;
      };

      return input_carry_to_last_bit != output_carry_of_block;
    };

    resolve_overflow_lut = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 1, 1, allocate_gpu_memory);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], resolve_overflow_lut->get_lut(0, 0),
        params.glwe_dimension, params.polynomial_size, message_modulus,
        params.carry_modulus, f_resolve_overflow_lut);
    resolve_overflow_lut->broadcast_lut(streams, gpu_indexes, 0);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    resolve_overflow_lut->release(streams, gpu_indexes, gpu_count);
    delete resolve_overflow_lut;
    cuda_drop_async(x, streams[0], gpu_indexes[0]);
  }
};

template <typename Torus> struct int_bitop_buffer {

  int_radix_params params;
  int_radix_lut<Torus> *lut;

  int_bitop_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                   uint32_t gpu_count, BITOP_TYPE op, int_radix_params params,
                   uint32_t num_radix_blocks, bool allocate_gpu_memory) {

    this->params = params;

    switch (op) {
    case BITAND:
    case BITOR:
    case BITXOR:
      lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                     num_radix_blocks, allocate_gpu_memory);
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
            streams[0], gpu_indexes[0], lut->get_lut(0, 0),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, lut_bivariate_f);
        lut->broadcast_lut(streams, gpu_indexes, 0);
      }
      break;
    default:
      // Scalar OP
      lut = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params,
                                     params.message_modulus, num_radix_blocks,
                                     allocate_gpu_memory);

      for (int i = 0; i < params.message_modulus; i++) {
        auto lut_block = lut->get_lut(0, i);
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
            streams[0], gpu_indexes[0], lut_block, params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, lut_univariate_scalar_f);
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
  Torus *preshifted_buffer;
  Torus *all_shifted_buffer;
  int_sc_prop_memory<Torus> *sc_prop_mem;
  bool anticipated_buffers_drop;

  int_scalar_mul_buffer(cudaStream_t const *streams,
                        uint32_t const *gpu_indexes, uint32_t gpu_count,
                        int_radix_params params, uint32_t num_radix_blocks,
                        bool allocate_gpu_memory,
                        bool anticipated_buffer_drop) {
    this->params = params;
    this->anticipated_buffers_drop = anticipated_buffer_drop;

    if (allocate_gpu_memory) {
      uint32_t msg_bits = (uint32_t)std::log2(params.message_modulus);
      uint32_t lwe_size = params.big_lwe_dimension + 1;
      uint32_t lwe_size_bytes = lwe_size * sizeof(Torus);
      size_t num_ciphertext_bits = msg_bits * num_radix_blocks;

      //// Contains all shifted values of lhs for shift in range (0..msg_bits)
      //// The idea is that with these we can create all other shift that are
      /// in / range (0..total_bits) for free (block rotation)
      preshifted_buffer = (Torus *)cuda_malloc_async(
          num_ciphertext_bits * lwe_size_bytes, streams[0], gpu_indexes[0]);

      all_shifted_buffer = (Torus *)cuda_malloc_async(
          num_ciphertext_bits * num_radix_blocks * lwe_size_bytes, streams[0],
          gpu_indexes[0]);

      cuda_memset_async(preshifted_buffer, 0,
                        num_ciphertext_bits * lwe_size_bytes, streams[0],
                        gpu_indexes[0]);

      cuda_memset_async(all_shifted_buffer, 0,
                        num_ciphertext_bits * num_radix_blocks * lwe_size_bytes,
                        streams[0], gpu_indexes[0]);

      logical_scalar_shift_buffer = new int_logical_scalar_shift_buffer<Torus>(
          streams, gpu_indexes, gpu_count, LEFT_SHIFT, params, num_radix_blocks,
          allocate_gpu_memory, all_shifted_buffer);

      sum_ciphertexts_vec_mem = new int_sum_ciphertexts_vec_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks,
          num_ciphertext_bits, allocate_gpu_memory);
      uint32_t uses_carry = 0;
      uint32_t requested_flag = outputFlag::FLAG_NONE;
      sc_prop_mem = new int_sc_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks,
          requested_flag, uses_carry, allocate_gpu_memory);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    sum_ciphertexts_vec_mem->release(streams, gpu_indexes, gpu_count);
    sc_prop_mem->release(streams, gpu_indexes, gpu_count);
    delete sum_ciphertexts_vec_mem;
    delete sc_prop_mem;
    cuda_drop_async(all_shifted_buffer, streams[0], gpu_indexes[0]);
    if (!anticipated_buffers_drop) {
      cuda_drop_async(preshifted_buffer, streams[0], gpu_indexes[0]);
      logical_scalar_shift_buffer->release(streams, gpu_indexes, gpu_count);
      delete (logical_scalar_shift_buffer);
    }
  }
};

template <typename Torus> struct int_abs_buffer {
  int_radix_params params;

  int_arithmetic_scalar_shift_buffer<Torus> *arithmetic_scalar_shift_mem;
  int_sc_prop_memory<Torus> *scp_mem;
  int_bitop_buffer<Torus> *bitxor_mem;

  CudaRadixCiphertextFFI *mask = new CudaRadixCiphertextFFI;
  int_abs_buffer(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                 uint32_t gpu_count, int_radix_params params,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory) {
    this->params = params;

    if (allocate_gpu_memory) {
      arithmetic_scalar_shift_mem =
          new int_arithmetic_scalar_shift_buffer<Torus>(
              streams, gpu_indexes, gpu_count,
              SHIFT_OR_ROTATE_TYPE::RIGHT_SHIFT, params, num_radix_blocks,
              allocate_gpu_memory);
      uint32_t requested_flag = outputFlag::FLAG_NONE;
      uint32_t uses_carry = 0;
      scp_mem = new int_sc_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_radix_blocks,
          requested_flag, uses_carry, allocate_gpu_memory);
      bitxor_mem = new int_bitop_buffer<Torus>(
          streams, gpu_indexes, gpu_count, BITOP_TYPE::BITXOR, params,
          num_radix_blocks, allocate_gpu_memory);

      create_trivial_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                                   mask, num_radix_blocks,
                                                   params.big_lwe_dimension);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    arithmetic_scalar_shift_mem->release(streams, gpu_indexes, gpu_count);
    scp_mem->release(streams, gpu_indexes, gpu_count);
    bitxor_mem->release(streams, gpu_indexes, gpu_count);

    delete arithmetic_scalar_shift_mem;
    delete scp_mem;
    delete bitxor_mem;

    release_radix_ciphertext(streams[0], gpu_indexes[0], mask);
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
  Torus *positive_numerator;
  Torus *positive_divisor;
  Torus *sign_bits_are_different;
  Torus *negated_quotient;
  Torus *negated_remainder;

  int_div_rem_memory(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                     uint32_t gpu_count, int_radix_params params,
                     bool is_signed, uint32_t num_blocks,
                     bool allocate_gpu_memory) {

    this->active_gpu_count = get_active_gpu_count(2 * num_blocks, gpu_count);
    this->params = params;
    this->is_signed = is_signed;

    unsigned_mem = new unsigned_int_div_rem_memory<Torus>(
        streams, gpu_indexes, gpu_count, params, num_blocks,
        allocate_gpu_memory);

    if (is_signed) {
      uint32_t big_lwe_size = params.big_lwe_dimension + 1;
      Torus sign_bit_pos = 31 - __builtin_clz(params.message_modulus) - 1;

      // init memory objects for other integer operations
      abs_mem_1 =
          new int_abs_buffer<Torus>(streams, gpu_indexes, gpu_count, params,
                                    num_blocks, allocate_gpu_memory);
      abs_mem_2 =
          new int_abs_buffer<Torus>(streams, gpu_indexes, gpu_count, params,
                                    num_blocks, allocate_gpu_memory);
      uint32_t requested_flag = outputFlag::FLAG_NONE;
      uint32_t uses_carry = 0;
      scp_mem_1 = new int_sc_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_blocks, requested_flag,
          uses_carry, allocate_gpu_memory);
      scp_mem_2 = new int_sc_prop_memory<Torus>(
          streams, gpu_indexes, gpu_count, params, num_blocks, requested_flag,
          uses_carry, allocate_gpu_memory);

      std::function<uint64_t(uint64_t)> quotient_predicate_lut_f =
          [](uint64_t x) -> uint64_t { return x == 1; };
      std::function<uint64_t(uint64_t)> remainder_predicate_lut_f =
          [sign_bit_pos](uint64_t x) -> uint64_t {
        return (x >> sign_bit_pos) == 1;
      };

      cmux_quotient_mem = new int_cmux_buffer<Torus>(
          streams, gpu_indexes, gpu_count, quotient_predicate_lut_f, params,
          num_blocks, allocate_gpu_memory);
      cmux_remainder_mem = new int_cmux_buffer<Torus>(
          streams, gpu_indexes, gpu_count, remainder_predicate_lut_f, params,
          num_blocks, allocate_gpu_memory);
      // init temporary memory buffers
      positive_numerator =
          (Torus *)cuda_malloc_async(big_lwe_size * num_blocks * sizeof(Torus),
                                     streams[0], gpu_indexes[0]);
      positive_divisor =
          (Torus *)cuda_malloc_async(big_lwe_size * num_blocks * sizeof(Torus),
                                     streams[0], gpu_indexes[0]);
      negated_quotient =
          (Torus *)cuda_malloc_async(big_lwe_size * num_blocks * sizeof(Torus),
                                     streams[0], gpu_indexes[0]);
      negated_remainder =
          (Torus *)cuda_malloc_async(big_lwe_size * num_blocks * sizeof(Torus),
                                     streams[0], gpu_indexes[0]);

      // init boolean temporary buffers
      sign_bits_are_different = (Torus *)cuda_malloc_async(
          big_lwe_size * sizeof(Torus), streams[0], gpu_indexes[0]);

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

      compare_signed_bits_lut = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, params, 1, 1, true);

      generate_device_accumulator_bivariate<Torus>(
          streams[0], gpu_indexes[0], compare_signed_bits_lut->get_lut(0, 0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, f_compare_extracted_signed_bits);
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

      // drop temporary buffers
      cuda_drop_async(positive_numerator, streams[0], gpu_indexes[0]);
      cuda_drop_async(positive_divisor, streams[0], gpu_indexes[0]);
      cuda_drop_async(sign_bits_are_different, streams[0], gpu_indexes[0]);
      cuda_drop_async(negated_quotient, streams[0], gpu_indexes[0]);
      cuda_drop_async(negated_remainder, streams[0], gpu_indexes[0]);
    }
  }
};

#endif // CUDA_INTEGER_UTILITIES_H
