#ifndef CUDA_INTEGER_H
#define CUDA_INTEGER_H

#include "pbs/programmable_bootstrap.cuh"
#include "programmable_bootstrap.h"
#include "programmable_bootstrap_multibit.h"
#include <cassert>
#include <cmath>
#include <functional>

enum OUTPUT_CARRY { NONE = 0, GENERATED = 1, PROPAGATED = 2 };
enum SHIFT_OR_ROTATE_TYPE {
  LEFT_SHIFT = 0,
  RIGHT_SHIFT = 1,
  LEFT_ROTATE = 2,
  RIGHT_ROTATE = 3
};
enum LUT_TYPE { OPERATOR = 0, MAXVALUE = 1, ISNONZERO = 2, BLOCKSLEN = 3 };
enum BITOP_TYPE {
  BITAND = 0,
  BITOR = 1,
  BITXOR = 2,
  BITNOT = 3,
  SCALAR_BITAND = 4,
  SCALAR_BITOR = 5,
  SCALAR_BITXOR = 6,
};

enum COMPARISON_TYPE {
  EQ = 0,
  NE = 1,
  GT = 2,
  GE = 3,
  LT = 4,
  LE = 5,
  MAX = 6,
  MIN = 7,
};
enum IS_RELATIONSHIP { IS_INFERIOR = 0, IS_EQUAL = 1, IS_SUPERIOR = 2 };

extern "C" {
void scratch_cuda_full_propagation_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_full_propagation_64_inplace(
    cuda_stream_t *stream, void *input_blocks, int8_t *mem_ptr, void *ksk,
    void *bsk, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t ks_base_log, uint32_t ks_level,
    uint32_t pbs_base_log, uint32_t pbs_level, uint32_t grouping_factor,
    uint32_t num_blocks);

void cleanup_cuda_full_propagation(cuda_stream_t *stream,
                                   int8_t **mem_ptr_void);

void scratch_cuda_integer_mult_radix_ciphertext_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t message_modulus,
    uint32_t carry_modulus, uint32_t glwe_dimension, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t pbs_base_log, uint32_t pbs_level,
    uint32_t ks_base_log, uint32_t ks_level, uint32_t grouping_factor,
    uint32_t num_blocks, PBS_TYPE pbs_type, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void cuda_integer_mult_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *radix_lwe_out, void *radix_lwe_left,
    void *radix_lwe_right, void *bsk, void *ksk, int8_t *mem_ptr,
    uint32_t message_modulus, uint32_t carry_modulus, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t pbs_base_log,
    uint32_t pbs_level, uint32_t ks_base_log, uint32_t ks_level,
    uint32_t grouping_factor, uint32_t num_blocks, PBS_TYPE pbs_type,
    uint32_t max_shared_memory);

void cleanup_cuda_integer_mult(cuda_stream_t *stream, int8_t **mem_ptr_void);

void cuda_negate_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint32_t lwe_dimension,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus);

void cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, void *scalar_input,
    uint32_t lwe_dimension, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus);

void scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory);

void cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint32_t shift, int8_t *mem_ptr,
    void *bsk, void *ksk, uint32_t num_blocks);

void scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory);

void cuda_integer_radix_arithmetic_scalar_shift_kb_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint32_t shift, int8_t *mem_ptr,
    void *bsk, void *ksk, uint32_t num_blocks);

void cleanup_cuda_integer_radix_logical_scalar_shift(cuda_stream_t *stream,
                                                     int8_t **mem_ptr_void);

void cleanup_cuda_integer_radix_arithmetic_scalar_shift(cuda_stream_t *stream,
                                                        int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_shift_and_rotate_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
    bool allocate_gpu_memory);

void cuda_integer_radix_shift_and_rotate_kb_64_inplace(
    cuda_stream_t *stream, void *lwe_array, void *lwe_shift, int8_t *mem_ptr,
    void *bsk, void *ksk, uint32_t num_blocks);

void cleanup_cuda_integer_radix_shift_and_rotate(cuda_stream_t *stream,
                                                 int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_comparison_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, COMPARISON_TYPE op_type,
    bool is_signed, bool allocate_gpu_memory);

void cuda_comparison_integer_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_1,
    void *lwe_array_2, int8_t *mem_ptr, void *bsk, void *ksk,
    uint32_t lwe_ciphertext_count);

void cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *scalar_blocks, int8_t *mem_ptr, void *bsk, void *ksk,
    uint32_t lwe_ciphertext_count, uint32_t num_scalar_blocks);

void cleanup_cuda_integer_comparison(cuda_stream_t *stream,
                                     int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_bitop_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, BITOP_TYPE op_type,
    bool allocate_gpu_memory);

void cuda_bitop_integer_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_1,
    void *lwe_array_2, int8_t *mem_ptr, void *bsk, void *ksk,
    uint32_t lwe_ciphertext_count);

void cuda_bitnot_integer_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    int8_t *mem_ptr, void *bsk, void *ksk, uint32_t lwe_ciphertext_count);

void cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_input,
    void *clear_blocks, uint32_t num_clear_blocks, int8_t *mem_ptr, void *bsk,
    void *ksk, uint32_t lwe_ciphertext_count, BITOP_TYPE op);

void cleanup_cuda_integer_bitop(cuda_stream_t *stream, int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_cmux_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_cmux_integer_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_condition,
    void *lwe_array_true, void *lwe_array_false, int8_t *mem_ptr, void *bsk,
    void *ksk, uint32_t lwe_ciphertext_count);

void cleanup_cuda_integer_radix_cmux(cuda_stream_t *stream,
                                     int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_scalar_rotate_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory);

void cuda_integer_radix_scalar_rotate_kb_64_inplace(cuda_stream_t *stream,
                                                    void *lwe_array, uint32_t n,
                                                    int8_t *mem_ptr, void *bsk,
                                                    void *ksk,
                                                    uint32_t num_blocks);

void cleanup_cuda_integer_radix_scalar_rotate(cuda_stream_t *stream,
                                              int8_t **mem_ptr_void);

void scratch_cuda_propagate_single_carry_kb_64_inplace(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_propagate_single_carry_kb_64_inplace(cuda_stream_t *stream,
                                               void *lwe_array, int8_t *mem_ptr,
                                               void *bsk, void *ksk,
                                               uint32_t num_blocks);

void cleanup_cuda_propagate_single_carry(cuda_stream_t *stream,
                                         int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_sum_ciphertexts_vec_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_in_radix,
    uint32_t max_num_radix_in_vec, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_integer_radix_sum_ciphertexts_vec_kb_64(
    cuda_stream_t *stream, void *radix_lwe_out, void *radix_lwe_vec,
    uint32_t num_radix_in_vec, int8_t *mem_ptr, void *bsk, void *ksk,
    uint32_t num_blocks_in_radix);

void cleanup_cuda_integer_radix_sum_ciphertexts_vec(cuda_stream_t *stream,
                                                    int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_overflowing_sub_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_integer_radix_overflowing_sub_kb_64(
    cuda_stream_t *stream, void *radix_lwe_out, void *radix_lwe_overflowed,
    void *radix_lwe_left, void *radix_lwe_right, int8_t *mem_ptr, void *bsk,
    void *ksk, uint32_t num_blocks_in_radix);

void cleanup_cuda_integer_radix_overflowing_sub(cuda_stream_t *stream,
                                                int8_t **mem_ptr_void);

void scratch_cuda_integer_scalar_mul_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_scalar_multiplication_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint64_t *decomposed_scalar,
    uint64_t *has_at_least_one_set, int8_t *mem_ptr, void *bsk, void *ksk,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t message_modulus,
    uint32_t num_blocks, uint32_t num_scalars);

void cleanup_cuda_integer_radix_scalar_mul(cuda_stream_t *stream,
                                           int8_t **mem_ptr_void);
}

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
 *    v_stream - cuda stream
 *    acc_bivariate - device pointer for bivariate accumulator
 *    ...
 *    f - wrapping function with two Torus inputs
 */
template <typename Torus>
void generate_device_accumulator_bivariate(
    cuda_stream_t *stream, Torus *acc_bivariate, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus, Torus)> f);

/*
 *  generate univariate accumulator (lut) for device pointer
 *    v_stream - cuda stream
 *    acc - device pointer for univariate accumulator
 *    ...
 *    f - evaluating function with one Torus input
 */
template <typename Torus>
void generate_device_accumulator(cuda_stream_t *stream, Torus *acc,
                                 uint32_t glwe_dimension,
                                 uint32_t polynomial_size,
                                 uint32_t message_modulus,
                                 uint32_t carry_modulus,
                                 std::function<Torus(Torus)> f);

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
    printf("pbs_type: %u, glwe_dimension: %u, polynomial_size: %u, "
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
  bool mem_reuse = false;

  int8_t *buffer;

  Torus *lut_indexes;
  Torus *lwe_indexes_in;
  Torus *lwe_indexes_out;

  // lwe_trivial_indexes is the intermediary index we need in case
  // lwe_indexes_in != lwe_indexes_out
  Torus *lwe_trivial_indexes;

  Torus *tmp_lwe_before_ks;
  Torus *tmp_lwe_after_ks;

  Torus *lut = nullptr;

  int_radix_lut(cuda_stream_t *stream, int_radix_params params,
                uint32_t num_luts, uint32_t num_radix_blocks,
                bool allocate_gpu_memory) {
    this->params = params;
    this->num_blocks = num_radix_blocks;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus big_size =
        (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
    Torus small_size =
        (params.small_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    ///////////////
    execute_scratch_pbs<Torus>(
        stream, &buffer, params.glwe_dimension, params.small_lwe_dimension,
        params.polynomial_size, params.pbs_level, params.grouping_factor,
        num_radix_blocks, cuda_get_max_shared_memory(stream->gpu_index),
        params.pbs_type, allocate_gpu_memory);

    if (allocate_gpu_memory) {
      // Allocate LUT
      // LUT is used as a trivial encryption and must be initialized outside
      // this constructor
      lut = (Torus *)cuda_malloc_async(num_luts * lut_buffer_size, stream);

      lut_indexes = (Torus *)cuda_malloc_async(lut_indexes_size, stream);

      // lut_indexes is initialized to 0 by default
      // if a different behavior is wanted, it should be rewritten later
      cuda_memset_async(lut_indexes, 0, lut_indexes_size, stream);

      // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
      // by default
      lwe_indexes_in = (Torus *)cuda_malloc(num_radix_blocks * sizeof(Torus),
                                            stream->gpu_index);
      lwe_indexes_out = (Torus *)cuda_malloc(num_radix_blocks * sizeof(Torus),
                                             stream->gpu_index);
      lwe_trivial_indexes = (Torus *)cuda_malloc(
          num_radix_blocks * sizeof(Torus), stream->gpu_index);
      auto h_lwe_indexes = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

      for (int i = 0; i < num_radix_blocks; i++)
        h_lwe_indexes[i] = i;

      cuda_memcpy_async_to_gpu(lwe_indexes_in, h_lwe_indexes,
                               num_radix_blocks * sizeof(Torus), stream);
      cuda_memcpy_async_to_gpu(lwe_indexes_out, h_lwe_indexes,
                               num_radix_blocks * sizeof(Torus), stream);
      cuda_memcpy_async_to_gpu(lwe_trivial_indexes, h_lwe_indexes,
                               num_radix_blocks * sizeof(Torus), stream);
      cuda_stream_add_callback(stream, host_free_on_stream_callback,
                               h_lwe_indexes);

      // Keyswitch
      tmp_lwe_before_ks = (Torus *)cuda_malloc_async(big_size, stream);
      tmp_lwe_after_ks = (Torus *)cuda_malloc_async(small_size, stream);
    }
  }

  // constructor to reuse memory
  int_radix_lut(cuda_stream_t *stream, int_radix_params params,
                uint32_t num_luts, uint32_t num_radix_blocks,
                int_radix_lut *base_lut_object) {
    this->params = params;
    this->num_blocks = num_radix_blocks;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    // base lut object should have bigger or equal memory than current one
    assert(num_radix_blocks <= base_lut_object->num_blocks);
    // pbs
    buffer = base_lut_object->buffer;
    // Keyswitch
    tmp_lwe_before_ks = base_lut_object->tmp_lwe_before_ks;
    tmp_lwe_after_ks = base_lut_object->tmp_lwe_after_ks;

    mem_reuse = true;

    // Allocate LUT
    // LUT is used as a trivial encryption and must be initialized outside
    // this constructor
    lut = (Torus *)cuda_malloc_async(num_luts * lut_buffer_size, stream);

    lut_indexes = (Torus *)cuda_malloc_async(lut_indexes_size, stream);

    // lut_indexes is initialized to 0 by default
    // if a different behavior is wanted, it should be rewritten later
    cuda_memset_async(lut_indexes, 0, lut_indexes_size, stream);

    // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
    // by default
    lwe_indexes_in = (Torus *)cuda_malloc(num_radix_blocks * sizeof(Torus),
                                          stream->gpu_index);
    lwe_indexes_out = (Torus *)cuda_malloc(num_radix_blocks * sizeof(Torus),
                                           stream->gpu_index);
    lwe_trivial_indexes = (Torus *)cuda_malloc(num_radix_blocks * sizeof(Torus),
                                               stream->gpu_index);
    auto h_lwe_indexes = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes[i] = i;

    cuda_memcpy_async_to_gpu(lwe_indexes_in, h_lwe_indexes,
                             num_radix_blocks * sizeof(Torus), stream);
    cuda_memcpy_async_to_gpu(lwe_indexes_out, h_lwe_indexes,
                             num_radix_blocks * sizeof(Torus), stream);
    cuda_memcpy_async_to_gpu(lwe_trivial_indexes, h_lwe_indexes,
                             num_radix_blocks * sizeof(Torus), stream);
    cuda_stream_add_callback(stream, host_free_on_stream_callback,
                             h_lwe_indexes);
  }

  Torus *get_lut(size_t ind) {
    assert(lut != nullptr);
    return &lut[ind * (params.glwe_dimension + 1) * params.polynomial_size];
  }

  Torus *get_lut_indexes(size_t ind) { return &lut_indexes[ind]; }
  void release(cuda_stream_t *stream) {
    cuda_drop_async(lut_indexes, stream);
    cuda_drop_async(lwe_indexes_in, stream);
    cuda_drop_async(lwe_indexes_out, stream);
    cuda_drop_async(lwe_trivial_indexes, stream);
    cuda_drop_async(lut, stream);
    if (!mem_reuse) {
      switch (params.pbs_type) {
      case MULTI_BIT:
        cleanup_cuda_multi_bit_programmable_bootstrap(stream, &buffer);
        break;
      case CLASSICAL:
        cleanup_cuda_programmable_bootstrap(stream, &buffer);
        break;
      default:
        PANIC("Cuda error (PBS): unknown PBS type. ")
      }
      cuda_drop_async(tmp_lwe_before_ks, stream);
      cuda_drop_async(tmp_lwe_after_ks, stream);
    }
  }
};

template <typename Torus> struct int_bit_extract_luts_buffer {
  int_radix_params params;
  int_radix_lut<Torus> *lut;

  // With offset
  int_bit_extract_luts_buffer(cuda_stream_t *stream, int_radix_params params,
                              uint32_t bits_per_block, uint32_t final_offset,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory) {
    this->params = params;

    lut = new int_radix_lut<Torus>(stream, params, bits_per_block,
                                   bits_per_block * num_radix_blocks,
                                   allocate_gpu_memory);

    if (allocate_gpu_memory) {
      for (int i = 0; i < bits_per_block; i++) {

        auto operator_f = [i, final_offset](Torus x) -> Torus {
          Torus y = (x >> i) & 1;
          return y << final_offset;
        };

        generate_device_accumulator<Torus>(
            stream, lut->get_lut(i), params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, operator_f);
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
      cuda_memcpy_async_to_gpu(
          lut->lut_indexes, h_lut_indexes,
          num_radix_blocks * bits_per_block * sizeof(Torus), stream);
      cuda_stream_add_callback(stream, host_free_on_stream_callback,
                               h_lut_indexes);

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
      cuda_memcpy_async_to_gpu(
          lut->lwe_indexes_in, h_lwe_indexes_in,
          num_radix_blocks * bits_per_block * sizeof(Torus), stream);
      cuda_stream_add_callback(stream, host_free_on_stream_callback,
                               h_lwe_indexes_in);

      /**
       * the output should aim different lwe ciphertexts, so lwe_indexes_out =
       * range(num_luts)
       */
      Torus *h_lwe_indexes_out =
          (Torus *)malloc(num_radix_blocks * bits_per_block * sizeof(Torus));

      for (int i = 0; i < num_radix_blocks * bits_per_block; i++)
        h_lwe_indexes_out[i] = i;

      cuda_memcpy_async_to_gpu(
          lut->lwe_indexes_out, h_lwe_indexes_out,
          num_radix_blocks * bits_per_block * sizeof(Torus), stream);
      cuda_stream_add_callback(stream, host_free_on_stream_callback,
                               h_lwe_indexes_out);
    }
  }

  // Without offset
  int_bit_extract_luts_buffer(cuda_stream_t *stream, int_radix_params params,
                              uint32_t bits_per_block,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory)
      : int_bit_extract_luts_buffer(stream, params, bits_per_block, 0,
                                    num_radix_blocks, allocate_gpu_memory) {}

  void release(cuda_stream_t *stream) { lut->release(stream); }
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

  int_bit_extract_luts_buffer<Torus> *bit_extract_luts;
  int_bit_extract_luts_buffer<Torus> *bit_extract_luts_with_offset_2;

  int_radix_lut<Torus> *mux_lut;
  Torus *tmp_mux_inputs;

  Torus offset;

  int_radix_lut<Torus> *cleaning_lut;

  int_shift_and_rotate_buffer(cuda_stream_t *stream,
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
        stream, params, bits_per_block, num_radix_blocks, allocate_gpu_memory);
    bit_extract_luts_with_offset_2 = new int_bit_extract_luts_buffer<Torus>(
        stream, params, bits_per_block, 2, num_radix_blocks,
        allocate_gpu_memory);

    mux_lut = new int_radix_lut<Torus>(stream, params, 1,
                                       bits_per_block * num_radix_blocks,
                                       allocate_gpu_memory);
    cleaning_lut = new int_radix_lut<Torus>(stream, params, 1, num_radix_blocks,
                                            allocate_gpu_memory);

    if (allocate_gpu_memory) {
      tmp_bits = (Torus *)cuda_malloc_async(bits_per_block * num_radix_blocks *
                                                (params.big_lwe_dimension + 1) *
                                                sizeof(Torus),
                                            stream);
      tmp_shift_bits = (Torus *)cuda_malloc_async(
          max_num_bits_that_tell_shift * num_radix_blocks *
              (params.big_lwe_dimension + 1) * sizeof(Torus),
          stream);

      tmp_rotated = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          stream);

      tmp_input_bits_a = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          stream);
      tmp_input_bits_b = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          stream);
      tmp_mux_inputs = (Torus *)cuda_malloc_async(
          bits_per_block * num_radix_blocks * (params.big_lwe_dimension + 1) *
              sizeof(Torus),
          stream);

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
          stream, mux_lut->get_lut(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          mux_lut_f);

      auto cleaning_lut_f = [](Torus x) -> Torus { return x; };
      generate_device_accumulator<Torus>(
          stream, cleaning_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          cleaning_lut_f);
    }
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(tmp_bits, stream);
    cuda_drop_async(tmp_shift_bits, stream);
    cuda_drop_async(tmp_rotated, stream);
    cuda_drop_async(tmp_input_bits_a, stream);
    cuda_drop_async(tmp_input_bits_b, stream);
    cuda_drop_async(tmp_mux_inputs, stream);

    bit_extract_luts->release(stream);
    bit_extract_luts_with_offset_2->release(stream);
    mux_lut->release(stream);
    cleaning_lut->release(stream);
  }
};

template <typename Torus> struct int_fullprop_buffer {
  PBS_TYPE pbs_type;
  int8_t *pbs_buffer;

  Torus *lut_buffer;
  Torus *lut_indexes;
  Torus *lwe_indexes;

  Torus *tmp_small_lwe_vector;
  Torus *tmp_big_lwe_vector;
};

template <typename Torus> struct int_sc_prop_memory {
  Torus *generates_or_propagates;
  Torus *step_output;

  // luts_array[2] = {lut_does_block_generate_carry,
  // lut_does_block_generate_or_propagate}
  int_radix_lut<Torus> *luts_array;
  int_radix_lut<Torus> *luts_carry_propagation_sum;
  int_radix_lut<Torus> *message_acc;

  int_radix_params params;

  int_sc_prop_memory(cuda_stream_t *stream, int_radix_params params,
                     uint32_t num_radix_blocks, bool allocate_gpu_memory) {
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    // allocate memory for intermediate calculations
    generates_or_propagates = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, stream);
    step_output = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, stream);

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
    luts_array = new int_radix_lut<Torus>(stream, params, 2, num_radix_blocks,
                                          allocate_gpu_memory);
    luts_carry_propagation_sum = new int_radix_lut<Torus>(
        stream, params, 1, num_radix_blocks, luts_array);
    message_acc = new int_radix_lut<Torus>(stream, params, 1, num_radix_blocks,
                                           luts_array);

    auto lut_does_block_generate_carry = luts_array->get_lut(0);
    auto lut_does_block_generate_or_propagate = luts_array->get_lut(1);

    // generate luts (aka accumulators)
    generate_device_accumulator<Torus>(
        stream, lut_does_block_generate_carry, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_lut_does_block_generate_carry);
    generate_device_accumulator<Torus>(
        stream, lut_does_block_generate_or_propagate, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_or_propagate);
    cuda_set_value_async<Torus>(&(stream->stream),
                                luts_array->get_lut_indexes(1), 1,
                                num_radix_blocks - 1);

    generate_device_accumulator_bivariate<Torus>(
        stream, luts_carry_propagation_sum->lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_luts_carry_propagation_sum);

    generate_device_accumulator<Torus>(stream, message_acc->lut, glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, f_message_acc);
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(generates_or_propagates, stream);
    cuda_drop_async(step_output, stream);

    luts_array->release(stream);
    luts_carry_propagation_sum->release(stream);
    message_acc->release(stream);

    delete luts_array;
    delete luts_carry_propagation_sum;
    delete message_acc;
  }
};

template <typename Torus> struct int_single_borrow_prop_memory {
  Torus *generates_or_propagates;
  Torus *step_output;

  // luts_array[2] = {lut_does_block_generate_carry,
  // lut_does_block_generate_or_propagate}
  int_radix_lut<Torus> *luts_array;
  int_radix_lut<Torus> *luts_borrow_propagation_sum;
  int_radix_lut<Torus> *message_acc;

  int_radix_params params;

  int_single_borrow_prop_memory(cuda_stream_t *stream, int_radix_params params,
                                uint32_t num_radix_blocks,
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
        num_radix_blocks * big_lwe_size_bytes, stream);
    step_output = (Torus *)cuda_malloc_async(
        num_radix_blocks * big_lwe_size_bytes, stream);

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
    luts_array = new int_radix_lut<Torus>(stream, params, 2, num_radix_blocks,
                                          allocate_gpu_memory);
    luts_borrow_propagation_sum = new int_radix_lut<Torus>(
        stream, params, 1, num_radix_blocks, luts_array);
    message_acc = new int_radix_lut<Torus>(stream, params, 1, num_radix_blocks,
                                           luts_array);

    auto lut_does_block_generate_carry = luts_array->get_lut(0);
    auto lut_does_block_generate_or_propagate = luts_array->get_lut(1);

    // generate luts (aka accumulators)
    generate_device_accumulator<Torus>(
        stream, lut_does_block_generate_carry, glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_lut_does_block_generate_carry);
    generate_device_accumulator<Torus>(
        stream, lut_does_block_generate_or_propagate, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_or_propagate);
    cuda_set_value_async<Torus>(&(stream->stream),
                                luts_array->get_lut_indexes(1), 1,
                                num_radix_blocks - 1);

    generate_device_accumulator_bivariate<Torus>(
        stream, luts_borrow_propagation_sum->lut, glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_luts_borrow_propagation_sum);

    generate_device_accumulator<Torus>(stream, message_acc->lut, glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, f_message_acc);
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(generates_or_propagates, stream);
    cuda_drop_async(step_output, stream);

    luts_array->release(stream);
    luts_borrow_propagation_sum->release(stream);
    message_acc->release(stream);

    delete luts_array;
    delete luts_borrow_propagation_sum;
    delete message_acc;
  }
};

template <typename Torus> struct int_sum_ciphertexts_vec_memory {
  Torus *new_blocks;
  Torus *old_blocks;
  Torus *small_lwe_vector;
  int_radix_params params;
  int_radix_lut<Torus> *luts_message_carry;
  int_sc_prop_memory<Torus> *scp_mem;

  int32_t *d_smart_copy_in;
  int32_t *d_smart_copy_out;

  bool mem_reuse = false;

  int_sum_ciphertexts_vec_memory(cuda_stream_t *stream, int_radix_params params,
                                 uint32_t num_blocks_in_radix,
                                 uint32_t max_num_radix_in_vec,
                                 bool allocate_gpu_memory) {
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    // create single carry propagation memory object
    scp_mem = new int_sc_prop_memory<Torus>(stream, params, num_blocks_in_radix,
                                            allocate_gpu_memory);
    int max_pbs_count = num_blocks_in_radix * max_num_radix_in_vec;

    // allocate gpu memory for intermediate buffers
    new_blocks = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.big_lwe_dimension + 1) * sizeof(Torus), stream);
    old_blocks = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.big_lwe_dimension + 1) * sizeof(Torus), stream);
    small_lwe_vector = (Torus *)cuda_malloc_async(
        max_pbs_count * (params.small_lwe_dimension + 1) * sizeof(Torus),
        stream);

    d_smart_copy_in =
        (int32_t *)cuda_malloc_async(max_pbs_count * sizeof(int32_t), stream);
    d_smart_copy_out =
        (int32_t *)cuda_malloc_async(max_pbs_count * sizeof(int32_t), stream);

    // create lut object for message and carry
    luts_message_carry = new int_radix_lut<Torus>(
        stream, params, 2, max_pbs_count, allocate_gpu_memory);

    auto message_acc = luts_message_carry->get_lut(0);
    auto carry_acc = luts_message_carry->get_lut(1);

    // define functions for each accumulator
    auto lut_f_message = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };
    auto lut_f_carry = [message_modulus](Torus x) -> Torus {
      return x / message_modulus;
    };

    // generate accumulators
    generate_device_accumulator<Torus>(stream, message_acc, glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, lut_f_message);
    generate_device_accumulator<Torus>(stream, carry_acc, glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, lut_f_carry);
  }

  int_sum_ciphertexts_vec_memory(cuda_stream_t *stream, int_radix_params params,
                                 uint32_t num_blocks_in_radix,
                                 uint32_t max_num_radix_in_vec,
                                 Torus *new_blocks, Torus *old_blocks,
                                 Torus *small_lwe_vector,
                                 int_radix_lut<Torus> *base_lut_object) {
    mem_reuse = true;
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    // create single carry propagation memory object
    scp_mem = new int_sc_prop_memory<Torus>(stream, params, num_blocks_in_radix,
                                            true);
    int max_pbs_count = num_blocks_in_radix * max_num_radix_in_vec;

    // assign  gpu memory for intermediate buffers
    this->new_blocks = new_blocks;
    this->old_blocks = old_blocks;
    this->small_lwe_vector = small_lwe_vector;

    d_smart_copy_in =
        (int32_t *)cuda_malloc_async(max_pbs_count * sizeof(int32_t), stream);
    d_smart_copy_out =
        (int32_t *)cuda_malloc_async(max_pbs_count * sizeof(int32_t), stream);

    // create lut object for message and carry
    luts_message_carry = new int_radix_lut<Torus>(
        stream, params, 2, max_pbs_count, base_lut_object);

    auto message_acc = luts_message_carry->get_lut(0);
    auto carry_acc = luts_message_carry->get_lut(1);

    // define functions for each accumulator
    auto lut_f_message = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };
    auto lut_f_carry = [message_modulus](Torus x) -> Torus {
      return x / message_modulus;
    };

    // generate accumulators
    generate_device_accumulator<Torus>(stream, message_acc, glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, lut_f_message);
    generate_device_accumulator<Torus>(stream, carry_acc, glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, lut_f_carry);
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(d_smart_copy_in, stream);
    cuda_drop_async(d_smart_copy_out, stream);

    if (!mem_reuse) {
      cuda_drop_async(new_blocks, stream);
      cuda_drop_async(old_blocks, stream);
      cuda_drop_async(small_lwe_vector, stream);
    }

    scp_mem->release(stream);
    luts_message_carry->release(stream);

    delete scp_mem;
    delete luts_message_carry;
  }
};

template <typename Torus> struct int_overflowing_sub_memory {
  int_radix_params params;
  bool mem_reuse = false;
  int_radix_lut<Torus> *luts_message_carry;
  int_single_borrow_prop_memory<Torus> *borrow_prop_mem;
  int_overflowing_sub_memory(cuda_stream_t *stream, int_radix_params params,
                             uint32_t num_blocks, bool allocate_gpu_memory) {
    this->params = params;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    borrow_prop_mem = new int_single_borrow_prop_memory<Torus>(
        stream, params, num_blocks, allocate_gpu_memory);

    int max_pbs_count = num_blocks * 2;

    // create lut object for message and carry
    luts_message_carry = new int_radix_lut<Torus>(
        stream, params, 2, max_pbs_count, allocate_gpu_memory);

    auto message_acc = luts_message_carry->get_lut(0);
    auto carry_acc = luts_message_carry->get_lut(1);

    // define functions for each accumulator
    auto lut_f_message = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };
    auto lut_f_carry = [message_modulus](Torus x) -> Torus {
      return x / message_modulus;
    };

    // generate accumulators
    generate_device_accumulator<Torus>(
        stream, message_acc, params.glwe_dimension, params.polynomial_size,
        message_modulus, carry_modulus, lut_f_message);
    generate_device_accumulator<Torus>(stream, carry_acc, params.glwe_dimension,
                                       params.polynomial_size, message_modulus,
                                       carry_modulus, lut_f_carry);
  }
  void release(cuda_stream_t *stream) {
    luts_message_carry->release(stream);
    borrow_prop_mem->release(stream);

    delete luts_message_carry;
    delete borrow_prop_mem;
  }
};

template <typename Torus> struct int_mul_memory {
  Torus *vector_result_sb;
  Torus *block_mul_res;
  Torus *small_lwe_vector;

  int_radix_lut<Torus> *luts_array; // lsb msb
  int_sum_ciphertexts_vec_memory<Torus> *sum_ciphertexts_mem;

  int_radix_params params;

  int_mul_memory(cuda_stream_t *stream, int_radix_params params,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory) {
    this->params = params;
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
        stream);
    block_mul_res = (Torus *)cuda_malloc_async(
        2 * total_block_count * (polynomial_size * glwe_dimension + 1) *
            sizeof(Torus),
        stream);
    small_lwe_vector = (Torus *)cuda_malloc_async(
        total_block_count * (lwe_dimension + 1) * sizeof(Torus), stream);

    // create int_radix_lut objects for lsb, msb, message, carry
    // luts_array -> lut = {lsb_acc, msb_acc}
    luts_array = new int_radix_lut<Torus>(stream, params, 2, total_block_count,
                                          allocate_gpu_memory);
    auto lsb_acc = luts_array->get_lut(0);
    auto msb_acc = luts_array->get_lut(1);

    // define functions for each accumulator
    auto lut_f_lsb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) % message_modulus;
    };
    auto lut_f_msb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) / message_modulus;
    };

    // generate accumulators
    generate_device_accumulator_bivariate<Torus>(
        stream, lsb_acc, glwe_dimension, polynomial_size, message_modulus,
        carry_modulus, lut_f_lsb);
    generate_device_accumulator_bivariate<Torus>(
        stream, msb_acc, glwe_dimension, polynomial_size, message_modulus,
        carry_modulus, lut_f_msb);

    // lut_indexes for luts_array should be reinitialized
    // first lsb_vector_block_count value should reference to lsb_acc
    // last msb_vector_block_count values should reference to msb_acc
    // for message and carry default lut_indexes is fine
    cuda_set_value_async<Torus>(
        &(stream->stream), luts_array->get_lut_indexes(lsb_vector_block_count),
        1, msb_vector_block_count);

    // create memory object for sum ciphertexts
    sum_ciphertexts_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        stream, params, num_radix_blocks, 2 * num_radix_blocks, block_mul_res,
        vector_result_sb, small_lwe_vector, luts_array);
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(vector_result_sb, stream);
    cuda_drop_async(block_mul_res, stream);
    cuda_drop_async(small_lwe_vector, stream);

    luts_array->release(stream);

    sum_ciphertexts_mem->release(stream);

    delete luts_array;
    delete sum_ciphertexts_mem;
  }
};

template <typename Torus> struct int_logical_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  Torus *tmp_rotated;

  bool reuse_memory = false;

  int_logical_scalar_shift_buffer(cuda_stream_t *stream,
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

      tmp_rotated = (Torus *)cuda_malloc_async(
          (max_amount_of_pbs + 2) * big_lwe_size_bytes, stream);

      cuda_memset_async(tmp_rotated, 0,
                        (max_amount_of_pbs + 2) * big_lwe_size_bytes, stream);

      uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

      // LUT
      // pregenerate lut vector and indexes
      // lut for left shift
      // here we generate 'num_bits_in_block' times lut
      // one for each 'shift_within_block' = 'shift' % 'num_bits_in_block'
      // even though lut_left contains 'num_bits_in_block' lut
      // lut_indexes will have indexes for single lut only and those indexes
      // will be 0 it means for pbs corresponding lut should be selected and
      // pass along lut_indexes filled with zeros

      // calculate bivariate lut for each 'shift_within_block'
      // so that in case an application calls scratches only once for a whole
      // circuit it can reuse memory for different shift values
      for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
        auto cur_lut_bivariate = new int_radix_lut<Torus>(
            stream, params, 1, num_radix_blocks, allocate_gpu_memory);

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
            stream, cur_lut_bivariate->lut, params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, shift_lut_f);

        lut_buffers_bivariate.push_back(cur_lut_bivariate);
      }
    }
  }

  int_logical_scalar_shift_buffer(cuda_stream_t *stream,
                                  SHIFT_OR_ROTATE_TYPE shift_type,
                                  int_radix_params params,
                                  uint32_t num_radix_blocks,
                                  bool allocate_gpu_memory,
                                  Torus *pre_allocated_buffer) {
    this->shift_type = shift_type;
    this->params = params;
    tmp_rotated = pre_allocated_buffer;
    reuse_memory = true;

    uint32_t max_amount_of_pbs = num_radix_blocks;
    uint32_t big_lwe_size = params.big_lwe_dimension + 1;
    uint32_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
    cuda_memset_async(tmp_rotated, 0,
                      (max_amount_of_pbs + 2) * big_lwe_size_bytes, stream);
    if (allocate_gpu_memory) {

      uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

      // LUT
      // pregenerate lut vector and indexes
      // lut for left shift
      // here we generate 'num_bits_in_block' times lut
      // one for each 'shift_within_block' = 'shift' % 'num_bits_in_block'
      // even though lut_left contains 'num_bits_in_block' lut
      // lut_indexes will have indexes for single lut only and those indexes
      // will be 0 it means for pbs corresponding lut should be selected and
      // pass along lut_indexes filled with zeros

      // calculate bivariate lut for each 'shift_within_block'
      // so that in case an application calls scratches only once for a whole
      // circuit it can reuse memory for different shift values
      for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
        auto cur_lut_bivariate = new int_radix_lut<Torus>(
            stream, params, 1, num_radix_blocks, allocate_gpu_memory);

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
            stream, cur_lut_bivariate->lut, params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, shift_lut_f);

        lut_buffers_bivariate.push_back(cur_lut_bivariate);
      }
    }
  }
  void release(cuda_stream_t *stream) {
    for (auto &buffer : lut_buffers_bivariate) {
      buffer->release(stream);
      delete buffer;
    }
    lut_buffers_bivariate.clear();

    if (!reuse_memory)
      cuda_drop_async(tmp_rotated, stream);
  }
};

template <typename Torus> struct int_arithmetic_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_univariate;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  Torus *tmp_rotated;

  cuda_stream_t *local_stream_1;
  cuda_stream_t *local_stream_2;

  int_arithmetic_scalar_shift_buffer(cuda_stream_t *stream,
                                     SHIFT_OR_ROTATE_TYPE shift_type,
                                     int_radix_params params,
                                     uint32_t num_radix_blocks,
                                     bool allocate_gpu_memory) {
    // In the arithmetic shift, a PBS has to be applied to the last rotated
    // block twice: once to shift it, once to compute the padding block to be
    // copied onto all blocks to the left of the last rotated block
    local_stream_1 = new cuda_stream_t(stream->gpu_index);
    local_stream_2 = new cuda_stream_t(stream->gpu_index);
    this->shift_type = shift_type;
    this->params = params;

    if (allocate_gpu_memory) {
      uint32_t big_lwe_size = params.big_lwe_dimension + 1;
      uint32_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

      tmp_rotated = (Torus *)cuda_malloc_async(
          (num_radix_blocks + 2) * big_lwe_size_bytes, stream);

      cuda_memset_async(tmp_rotated, 0,
                        (num_radix_blocks + 2) * big_lwe_size_bytes, stream);

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
            new int_radix_lut<Torus>(stream, params, 1, 1, allocate_gpu_memory);

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
            stream, shift_last_block_lut_univariate->lut, params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, last_block_lut_f);

        lut_buffers_univariate.push_back(shift_last_block_lut_univariate);
      }

      auto padding_block_lut_univariate =
          new int_radix_lut<Torus>(stream, params, 1, 1, allocate_gpu_memory);

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
          stream, padding_block_lut_univariate->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          padding_block_lut_f);

      lut_buffers_univariate.push_back(padding_block_lut_univariate);

      // lut to shift the first blocks
      // calculate lut for each 'shift_within_block'
      // so that in case an application calls scratches only once for a whole
      // circuit it can reuse memory for different shift values
      // NB: with two bits of message, this is actually only one LUT.
      for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
        auto shift_blocks_lut_bivariate = new int_radix_lut<Torus>(
            stream, params, 1, num_radix_blocks, allocate_gpu_memory);

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
            stream, shift_blocks_lut_bivariate->lut, params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, blocks_lut_f);

        lut_buffers_bivariate.push_back(shift_blocks_lut_bivariate);
      }
    }
  }

  void release(cuda_stream_t *stream) {
    local_stream_1->release();
    local_stream_2->release();
    for (auto &buffer : lut_buffers_bivariate) {
      buffer->release(stream);
      delete buffer;
    }
    for (auto &buffer : lut_buffers_univariate) {
      buffer->release(stream);
      delete buffer;
    }
    lut_buffers_bivariate.clear();
    lut_buffers_univariate.clear();

    cuda_drop_async(tmp_rotated, stream);
  }
};

template <typename Torus> struct int_zero_out_if_buffer {

  int_radix_params params;

  Torus *tmp;

  cuda_stream_t *local_stream;

  int_zero_out_if_buffer(cuda_stream_t *stream, int_radix_params params,
                         uint32_t num_radix_blocks, bool allocate_gpu_memory) {
    this->params = params;

    Torus big_size =
        (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
    if (allocate_gpu_memory) {

      tmp = (Torus *)cuda_malloc_async(big_size, stream);
      // We may use a different stream to allow concurrent operation
      local_stream = new cuda_stream_t(stream->gpu_index);
    }
  }
  void release(cuda_stream_t *stream) {
    cuda_drop_async(tmp, stream);
    local_stream->release();
  }
};

template <typename Torus> struct int_cmux_buffer {
  int_radix_lut<Torus> *predicate_lut;
  int_radix_lut<Torus> *inverted_predicate_lut;
  int_radix_lut<Torus> *message_extract_lut;

  Torus *tmp_true_ct;
  Torus *tmp_false_ct;

  int_zero_out_if_buffer<Torus> *zero_if_true_buffer;
  int_zero_out_if_buffer<Torus> *zero_if_false_buffer;

  int_radix_params params;

  int_cmux_buffer(cuda_stream_t *stream,
                  std::function<Torus(Torus)> predicate_lut_f,
                  int_radix_params params, uint32_t num_radix_blocks,
                  bool allocate_gpu_memory) {

    this->params = params;

    if (allocate_gpu_memory) {
      Torus big_size =
          (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);

      tmp_true_ct = (Torus *)cuda_malloc_async(big_size, stream);
      tmp_false_ct = (Torus *)cuda_malloc_async(big_size, stream);

      zero_if_true_buffer = new int_zero_out_if_buffer<Torus>(
          stream, params, num_radix_blocks, allocate_gpu_memory);
      zero_if_false_buffer = new int_zero_out_if_buffer<Torus>(
          stream, params, num_radix_blocks, allocate_gpu_memory);

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

      predicate_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      inverted_predicate_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      message_extract_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator_bivariate<Torus>(
          stream, predicate_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          lut_f);

      generate_device_accumulator_bivariate<Torus>(
          stream, inverted_predicate_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          inverted_lut_f);

      generate_device_accumulator<Torus>(
          stream, message_extract_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          message_extract_lut_f);
    }
  }

  void release(cuda_stream_t *stream) {
    predicate_lut->release(stream);
    delete predicate_lut;
    inverted_predicate_lut->release(stream);
    delete inverted_predicate_lut;
    message_extract_lut->release(stream);
    delete message_extract_lut;

    zero_if_true_buffer->release(stream);
    delete zero_if_true_buffer;
    zero_if_false_buffer->release(stream);
    delete zero_if_false_buffer;

    cuda_drop_async(tmp_true_ct, stream);
    cuda_drop_async(tmp_false_ct, stream);
  }
};

template <typename Torus> struct int_are_all_block_true_buffer {
  COMPARISON_TYPE op;
  int_radix_params params;

  Torus *tmp_out;

  // This map store LUTs that checks the equality between some input and values
  // of interest in are_all_block_true(), as with max_value (the maximum message
  // value).
  std::unordered_map<int, int_radix_lut<Torus> *> is_equal_to_lut_map;

  Torus *tmp_block_accumulated;

  int_are_all_block_true_buffer(cuda_stream_t *stream, COMPARISON_TYPE op,
                                int_radix_params params,
                                uint32_t num_radix_blocks,
                                bool allocate_gpu_memory) {
    this->params = params;
    this->op = op;

    if (allocate_gpu_memory) {
      Torus total_modulus = params.message_modulus * params.carry_modulus;
      uint32_t max_value = total_modulus - 1;

      int max_chunks = (num_radix_blocks + max_value - 1) / max_value;
      tmp_block_accumulated = (Torus *)cuda_malloc_async(
          (params.big_lwe_dimension + 1) * max_chunks * sizeof(Torus), stream);
      tmp_out = (Torus *)cuda_malloc_async((params.big_lwe_dimension + 1) *
                                               num_radix_blocks * sizeof(Torus),
                                           stream);
    }
  }

  void release(cuda_stream_t *stream) {
    for (auto &lut : is_equal_to_lut_map) {
      lut.second->release(stream);
    }
    is_equal_to_lut_map.clear();

    cuda_drop_async(tmp_block_accumulated, stream);
    cuda_drop_async(tmp_out, stream);
  }
};

template <typename Torus> struct int_comparison_eq_buffer {
  int_radix_params params;
  COMPARISON_TYPE op;

  int_radix_lut<Torus> *operator_lut;
  int_radix_lut<Torus> *is_non_zero_lut;

  int_are_all_block_true_buffer<Torus> *are_all_block_true_buffer;

  int_radix_lut<Torus> *scalar_comparison_luts;

  int_comparison_eq_buffer(cuda_stream_t *stream, COMPARISON_TYPE op,
                           int_radix_params params, uint32_t num_radix_blocks,
                           bool allocate_gpu_memory) {
    this->params = params;
    this->op = op;

    if (allocate_gpu_memory) {

      are_all_block_true_buffer = new int_are_all_block_true_buffer<Torus>(
          stream, op, params, num_radix_blocks, allocate_gpu_memory);

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
      operator_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator_bivariate<Torus>(
          stream, operator_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          operator_f);

      // f(x) -> x == 0
      Torus total_modulus = params.message_modulus * params.carry_modulus;
      auto is_non_zero_lut_f = [total_modulus](Torus x) -> Torus {
        return (x % total_modulus) != 0;
      };

      is_non_zero_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          stream, is_non_zero_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          is_non_zero_lut_f);

      // Scalar may have up to num_radix_blocks blocks
      scalar_comparison_luts = new int_radix_lut<Torus>(
          stream, params, total_modulus, num_radix_blocks, allocate_gpu_memory);

      for (int i = 0; i < total_modulus; i++) {
        auto lut_f = [i, operator_f](Torus x) -> Torus {
          return operator_f(i, x);
        };

        Torus *lut = scalar_comparison_luts->lut +
                     i * (params.glwe_dimension + 1) * params.polynomial_size;
        generate_device_accumulator<Torus>(
            stream, lut, params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, lut_f);
      }
    }
  }

  void release(cuda_stream_t *stream) {
    operator_lut->release(stream);
    delete operator_lut;
    is_non_zero_lut->release(stream);
    delete is_non_zero_lut;

    are_all_block_true_buffer->release(stream);
    delete are_all_block_true_buffer;

    scalar_comparison_luts->release(stream);
    delete scalar_comparison_luts;
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

  int_tree_sign_reduction_buffer(cuda_stream_t *stream,
                                 std::function<Torus(Torus)> operator_f,
                                 int_radix_params params,
                                 uint32_t num_radix_blocks,
                                 bool allocate_gpu_memory) {
    this->params = params;

    block_selector_f = [](Torus msb, Torus lsb) -> Torus {
      if (msb == IS_EQUAL) // EQUAL
        return lsb;
      else
        return msb;
    };

    if (allocate_gpu_memory) {
      tmp_x = (Torus *)cuda_malloc_async((params.big_lwe_dimension + 1) *
                                             num_radix_blocks * sizeof(Torus),
                                         stream);
      tmp_y = (Torus *)cuda_malloc_async((params.big_lwe_dimension + 1) *
                                             num_radix_blocks * sizeof(Torus),
                                         stream);

      // LUTs
      tree_inner_leaf_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      tree_last_leaf_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      tree_last_leaf_scalar_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);
      generate_device_accumulator_bivariate<Torus>(
          stream, tree_inner_leaf_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          block_selector_f);
    }
  }

  void release(cuda_stream_t *stream) {
    tree_inner_leaf_lut->release(stream);
    delete tree_inner_leaf_lut;
    tree_last_leaf_lut->release(stream);
    delete tree_last_leaf_lut;
    tree_last_leaf_scalar_lut->release(stream);
    delete tree_last_leaf_scalar_lut;

    cuda_drop_async(tmp_x, stream);
    cuda_drop_async(tmp_y, stream);
  }
};

template <typename Torus> struct int_comparison_diff_buffer {
  int_radix_params params;
  COMPARISON_TYPE op;

  Torus *tmp_packed_left;
  Torus *tmp_packed_right;

  std::function<Torus(Torus)> operator_f;

  int_tree_sign_reduction_buffer<Torus> *tree_buffer;

  int_comparison_diff_buffer(cuda_stream_t *stream, COMPARISON_TYPE op,
                             int_radix_params params, uint32_t num_radix_blocks,
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

      tmp_packed_left =
          (Torus *)cuda_malloc_async(big_size * (num_radix_blocks / 2), stream);

      tmp_packed_right =
          (Torus *)cuda_malloc_async(big_size * (num_radix_blocks / 2), stream);

      tree_buffer = new int_tree_sign_reduction_buffer<Torus>(
          stream, operator_f, params, num_radix_blocks, allocate_gpu_memory);
    }
  }

  void release(cuda_stream_t *stream) {
    tree_buffer->release(stream);
    delete tree_buffer;

    cuda_drop_async(tmp_packed_left, stream);
    cuda_drop_async(tmp_packed_right, stream);
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

  // Scalar EQ / NE
  Torus *tmp_packed_input;

  // Max Min
  int_cmux_buffer<Torus> *cmux_buffer;

  // Signed LUT
  int_radix_lut<Torus> *signed_lut;
  bool is_signed;

  // Used for scalar comparisons
  cuda_stream_t *lsb_stream;
  cuda_stream_t *msb_stream;

  int_comparison_buffer(cuda_stream_t *stream, COMPARISON_TYPE op,
                        int_radix_params params, uint32_t num_radix_blocks,
                        bool is_signed, bool allocate_gpu_memory) {
    this->params = params;
    this->op = op;
    this->is_signed = is_signed;

    identity_lut_f = [](Torus x) -> Torus { return x; };

    if (allocate_gpu_memory) {
      lsb_stream = cuda_create_stream(stream->gpu_index);
      msb_stream = cuda_create_stream(stream->gpu_index);

      tmp_lwe_array_out = (Torus *)cuda_malloc_async(
          (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus),
          stream);

      tmp_packed_input = (Torus *)cuda_malloc_async(
          (params.big_lwe_dimension + 1) * 2 * num_radix_blocks * sizeof(Torus),
          stream);

      // Block comparisons
      tmp_block_comparisons = (Torus *)cuda_malloc_async(
          (params.big_lwe_dimension + 1) * num_radix_blocks * sizeof(Torus),
          stream);

      // Cleaning LUT
      identity_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          stream, identity_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          identity_lut_f);

      uint32_t total_modulus = params.message_modulus * params.carry_modulus;
      auto is_zero_f = [total_modulus](Torus x) -> Torus {
        return (x % total_modulus) == 0;
      };

      is_zero_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          stream, is_zero_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          is_zero_f);

      switch (op) {
      case COMPARISON_TYPE::MAX:
      case COMPARISON_TYPE::MIN:
        cmux_buffer = new int_cmux_buffer<Torus>(
            stream,
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
            stream, op, params, num_radix_blocks, allocate_gpu_memory);
      case COMPARISON_TYPE::EQ:
      case COMPARISON_TYPE::NE:
        eq_buffer = new int_comparison_eq_buffer<Torus>(
            stream, op, params, num_radix_blocks, allocate_gpu_memory);
        break;
      default:
        PANIC("Unsupported comparison operation.")
      }

      if (is_signed) {
        signed_lut =
            new int_radix_lut<Torus>(stream, params, 1, 1, allocate_gpu_memory);

        auto message_modulus = (int)params.message_modulus;
        uint32_t sign_bit_pos = log2(message_modulus) - 1;
        std::function<Torus(Torus, Torus)> signed_lut_f;
        signed_lut_f = [sign_bit_pos](Torus x, Torus y) -> Torus {
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
            else if (x > y)
              return (Torus)(IS_SUPERIOR);
          } else {
            if (x < y)
              return (Torus)(IS_SUPERIOR);
            else if (x == y)
              return (Torus)(IS_EQUAL);
            else if (x > y)
              return (Torus)(IS_INFERIOR);
          }
          PANIC("Cuda error: sign_lut creation failed due to wrong function.")
        };

        generate_device_accumulator_bivariate<Torus>(
            stream, signed_lut->lut, params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, signed_lut_f);
      }
    }
  }

  void release(cuda_stream_t *stream) {
    switch (op) {
    case COMPARISON_TYPE::MAX:
    case COMPARISON_TYPE::MIN:
      cmux_buffer->release(stream);
      delete (cmux_buffer);
    case COMPARISON_TYPE::GT:
    case COMPARISON_TYPE::GE:
    case COMPARISON_TYPE::LT:
    case COMPARISON_TYPE::LE:
      diff_buffer->release(stream);
      delete (diff_buffer);
    case COMPARISON_TYPE::EQ:
    case COMPARISON_TYPE::NE:
      eq_buffer->release(stream);
      delete (eq_buffer);
      break;
    default:
      PANIC("Unsupported comparison operation.")
    }
    identity_lut->release(stream);
    delete identity_lut;
    is_zero_lut->release(stream);
    delete is_zero_lut;
    cuda_drop_async(tmp_lwe_array_out, stream);
    cuda_drop_async(tmp_block_comparisons, stream);
    cuda_drop_async(tmp_packed_input, stream);

    if (is_signed) {
      signed_lut->release(stream);
      delete (signed_lut);
    }
    cuda_destroy_stream(lsb_stream);
    cuda_destroy_stream(msb_stream);
  }
};

template <typename Torus> struct int_bitop_buffer {

  int_radix_params params;
  int_radix_lut<Torus> *lut;

  int_bitop_buffer(cuda_stream_t *stream, BITOP_TYPE op,
                   int_radix_params params, uint32_t num_radix_blocks,
                   bool allocate_gpu_memory) {

    this->params = params;

    switch (op) {
    case BITAND:
    case BITOR:
    case BITXOR:
      lut = new int_radix_lut<Torus>(stream, params, 1, num_radix_blocks,
                                     allocate_gpu_memory);
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
            stream, lut->lut, params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, lut_bivariate_f);
      }
      break;
    case BITNOT:
      lut = new int_radix_lut<Torus>(stream, params, 1, num_radix_blocks,
                                     allocate_gpu_memory);
      {
        auto lut_not_f = [params](Torus x) -> Torus {
          return (~x) % params.message_modulus;
        };
        generate_device_accumulator<Torus>(
            stream, lut->lut, params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, lut_not_f);
      }
      break;
    default:
      // Scalar OP
      uint32_t lut_size = (params.glwe_dimension + 1) * params.polynomial_size;

      lut = new int_radix_lut<Torus>(stream, params, params.message_modulus,
                                     num_radix_blocks, allocate_gpu_memory);

      for (int i = 0; i < params.message_modulus; i++) {
        auto lut_block = lut->lut + i * lut_size;
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
            stream, lut_block, params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus,
            lut_univariate_scalar_f);
      }
    }
  }

  void release(cuda_stream_t *stream) {
    lut->release(stream);
    delete lut;
  }
};

template <typename Torus> struct int_scalar_mul_buffer {
  int_radix_params params;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_buffer;
  int_sum_ciphertexts_vec_memory<Torus> *sum_ciphertexts_vec_mem;
  Torus *preshifted_buffer;
  Torus *all_shifted_buffer;

  int_scalar_mul_buffer(cuda_stream_t *stream, int_radix_params params,
                        uint32_t num_radix_blocks, bool allocate_gpu_memory) {
    this->params = params;

    if (allocate_gpu_memory) {
      uint32_t msg_bits = (uint32_t)std::log2(params.message_modulus);
      uint32_t lwe_size = params.big_lwe_dimension + 1;
      uint32_t lwe_size_bytes = lwe_size * sizeof(Torus);
      size_t num_ciphertext_bits = msg_bits * num_radix_blocks;

      //// Contains all shifted values of lhs for shift in range (0..msg_bits)
      //// The idea is that with these we can create all other shift that are in
      //// range (0..total_bits) for free (block rotation)
      preshifted_buffer = (Torus *)cuda_malloc_async(
          num_ciphertext_bits * lwe_size_bytes, stream);

      all_shifted_buffer = (Torus *)cuda_malloc_async(
          num_ciphertext_bits * num_radix_blocks * lwe_size_bytes, stream);

      cuda_memset_async(preshifted_buffer, 0,
                        num_ciphertext_bits * lwe_size_bytes, stream);

      cuda_memset_async(all_shifted_buffer, 0,
                        num_ciphertext_bits * num_radix_blocks * lwe_size_bytes,
                        stream);

      logical_scalar_shift_buffer = new int_logical_scalar_shift_buffer<Torus>(
          stream, LEFT_SHIFT, params, num_radix_blocks, allocate_gpu_memory,
          all_shifted_buffer);

      sum_ciphertexts_vec_mem = new int_sum_ciphertexts_vec_memory<Torus>(
          stream, params, num_radix_blocks, num_ciphertext_bits,
          allocate_gpu_memory);
    }
  }

  void release(cuda_stream_t *stream) {
    logical_scalar_shift_buffer->release(stream);
    sum_ciphertexts_vec_mem->release(stream);
    cuda_drop_async(preshifted_buffer, stream);
    cuda_drop_async(all_shifted_buffer, stream);
  }
};

#endif // CUDA_INTEGER_H
