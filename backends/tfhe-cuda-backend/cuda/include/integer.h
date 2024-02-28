#ifndef CUDA_INTEGER_H
#define CUDA_INTEGER_H

#include "bootstrap.h"
#include "bootstrap_multibit.h"
#include "pbs/bootstrap.cuh"
#include <cassert>
#include <cmath>
#include <functional>

enum OUTPUT_CARRY { NONE = 0, GENERATED = 1, PROPAGATED = 2 };
enum SHIFT_TYPE { LEFT_SHIFT = 0, RIGHT_SHIFT = 1 };
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

void cuda_small_scalar_multiplication_integer_radix_ciphertext_64(
    cuda_stream_t *stream, void *output_lwe_array, void *input_lwe_array,
    uint64_t scalar, uint32_t lwe_dimension, uint32_t lwe_ciphertext_count);

void cuda_small_scalar_multiplication_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint64_t scalar,
    uint32_t lwe_dimension, uint32_t lwe_ciphertext_count);

void scratch_cuda_integer_radix_scalar_shift_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_TYPE shift_type, bool allocate_gpu_memory);

void cuda_integer_radix_scalar_shift_kb_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint32_t shift, int8_t *mem_ptr,
    void *bsk, void *ksk, uint32_t num_blocks);

void cleanup_cuda_integer_radix_scalar_shift(cuda_stream_t *stream,
                                             int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_comparison_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, COMPARISON_TYPE op_type,
    bool allocate_gpu_memory);

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
    PBS_TYPE pbs_type, SHIFT_TYPE shift_type, bool allocate_gpu_memory);

void cuda_integer_radix_scalar_rotate_kb_64_inplace(cuda_stream_t *stream,
                                                    void *lwe_array, uint32_t n,
                                                    int8_t *mem_ptr, void *bsk,
                                                    void *ksk,
                                                    uint32_t num_blocks);

void cleanup_cuda_integer_radix_scalar_rotate(cuda_stream_t *stream,
                                              int8_t **mem_ptr_void);

void scratch_cuda_propagate_single_carry_low_latency_kb_64_inplace(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_propagate_single_carry_low_latency_kb_64_inplace(
    cuda_stream_t *stream, void *lwe_array, int8_t *mem_ptr, void *bsk,
    void *ksk, uint32_t num_blocks);

void cleanup_cuda_propagate_single_carry_low_latency(cuda_stream_t *stream,
                                                     int8_t **mem_ptr_void);
}

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

  int8_t *pbs_buffer;

  Torus *lut_indexes;
  Torus *lwe_indexes;

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
        stream, &pbs_buffer, params.glwe_dimension, params.small_lwe_dimension,
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
      lwe_indexes = (Torus *)cuda_malloc(num_radix_blocks * sizeof(Torus),
                                         stream->gpu_index);
      auto h_lwe_indexes = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

      for (int i = 0; i < num_radix_blocks; i++)
        h_lwe_indexes[i] = i;

      cuda_memcpy_async_to_gpu(lwe_indexes, h_lwe_indexes,
                               num_radix_blocks * sizeof(Torus), stream);
      free(h_lwe_indexes);

      // Keyswitch
      tmp_lwe_before_ks = (Torus *)cuda_malloc_async(big_size, stream);
      tmp_lwe_after_ks = (Torus *)cuda_malloc_async(small_size, stream);
    }
  }

  // constructor to reuse memory
  int_radix_lut(cuda_stream_t *stream, int_radix_params params,
                uint32_t num_luts, uint32_t num_radix_blocks,
                int_radix_lut<Torus> *base_lut_object) {
    this->params = params;
    this->num_blocks = num_radix_blocks;
    Torus lut_indexes_size = num_radix_blocks * sizeof(Torus);
    Torus lut_buffer_size =
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus);

    // base lut object should have bigger or equal memory than current one
    assert(num_radix_blocks <= base_lut_object->num_blocks);
    // pbs
    pbs_buffer = base_lut_object->pbs_buffer;
    // Keyswitch
    tmp_lwe_before_ks = base_lut_object->tmp_lwe_before_ks;
    tmp_lwe_after_ks = base_lut_object->tmp_lwe_after_ks;

    mem_reuse = true;

    // Allocate LUT
    // LUT is used as a trivial encryption and must be initialized outside
    // this contructor
    lut = (Torus *)cuda_malloc_async(num_luts * lut_buffer_size, stream);

    lut_indexes = (Torus *)cuda_malloc_async(lut_indexes_size, stream);

    // lut_indexes is initialized to 0 by default
    // if a different behavior is wanted, it should be rewritten later
    cuda_memset_async(lut_indexes, 0, lut_indexes_size, stream);

    // lwe_(input/output)_indexes are initialized to range(num_radix_blocks)
    // by default
    lwe_indexes = (Torus *)cuda_malloc(num_radix_blocks * sizeof(Torus),
                                       stream->gpu_index);
    auto h_lwe_indexes = (Torus *)malloc(num_radix_blocks * sizeof(Torus));

    for (int i = 0; i < num_radix_blocks; i++)
      h_lwe_indexes[i] = i;

    cuda_memcpy_async_to_gpu(lwe_indexes, h_lwe_indexes,
                             num_radix_blocks * sizeof(Torus), stream);
    cuda_synchronize_stream(stream);
    free(h_lwe_indexes);
  }

  Torus *get_lut(size_t ind) {
    assert(lut != nullptr);
    return &lut[ind * (params.glwe_dimension + 1) * params.polynomial_size];
  }

  Torus *get_lut_indexes(size_t ind) { return &lut_indexes[ind]; }
  void release(cuda_stream_t *stream) {
    cuda_drop_async(lut_indexes, stream);
    cuda_drop_async(lwe_indexes, stream);
    cuda_drop_async(lut, stream);
    if (!mem_reuse) {
      cuda_drop_async(pbs_buffer, stream);
      cuda_drop_async(tmp_lwe_before_ks, stream);
      cuda_drop_async(tmp_lwe_after_ks, stream);
    }
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

template <typename Torus> struct int_mul_memory {
  Torus *vector_result_sb;
  Torus *block_mul_res;
  Torus *small_lwe_vector;
  int_radix_lut<Torus> *luts_array; // lsb msb
  int_radix_lut<Torus> *luts_message;
  int_radix_lut<Torus> *luts_carry;
  int_sc_prop_memory<Torus> *scp_mem;
  int_radix_params params;

  int_mul_memory(cuda_stream_t *stream, int_radix_params params,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory) {
    this->params = params;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto lwe_dimension = params.small_lwe_dimension;

    // create single carry propagation memory object
    scp_mem = new int_sc_prop_memory<Torus>(stream, params, num_radix_blocks,
                                            allocate_gpu_memory);
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
    luts_message = new int_radix_lut<Torus>(stream, params, 1,
                                            total_block_count, luts_array);
    luts_carry = new int_radix_lut<Torus>(stream, params, 1, total_block_count,
                                          luts_array);

    auto lsb_acc = luts_array->get_lut(0);
    auto msb_acc = luts_array->get_lut(1);
    auto message_acc = luts_message->get_lut(0);
    auto carry_acc = luts_carry->get_lut(0);

    // define functions for each accumulator
    auto lut_f_lsb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) % message_modulus;
    };
    auto lut_f_msb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) / message_modulus;
    };
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
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(vector_result_sb, stream);
    cuda_drop_async(block_mul_res, stream);
    cuda_drop_async(small_lwe_vector, stream);

    luts_array->release(stream);
    luts_message->release(stream);
    luts_carry->release(stream);

    scp_mem->release(stream);

    delete luts_array;
    delete luts_message;
    delete luts_carry;

    delete scp_mem;
  }
};

template <typename Torus> struct int_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;
  std::vector<int_radix_lut<Torus> *> lut_buffers_univariate;

  SHIFT_TYPE shift_type;

  Torus *tmp_rotated;

  int_shift_buffer(cuda_stream_t *stream, SHIFT_TYPE shift_type,
                   int_radix_params params, uint32_t num_radix_blocks,
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
    }
  }

  void release(cuda_stream_t *stream) {
    for (auto &lut : is_equal_to_lut_map) {
      lut.second->release(stream);
    }
    is_equal_to_lut_map.clear();

    cuda_drop_async(tmp_block_accumulated, stream);
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
  int_radix_lut<Torus> *cleaning_lut;
  std::function<Torus(Torus)> cleaning_lut_f;

  int_radix_lut<Torus> *is_zero_lut;

  int_comparison_eq_buffer<Torus> *eq_buffer;
  int_comparison_diff_buffer<Torus> *diff_buffer;

  Torus *tmp_block_comparisons;
  Torus *tmp_lwe_array_out;

  // Scalar EQ / NE
  Torus *tmp_packed_input;

  // Max Min
  int_cmux_buffer<Torus> *cmux_buffer;

  // Used for scalar comparisons
  cuda_stream_t *lsb_stream;
  cuda_stream_t *msb_stream;

  int_comparison_buffer(cuda_stream_t *stream, COMPARISON_TYPE op,
                        int_radix_params params, uint32_t num_radix_blocks,
                        bool allocate_gpu_memory) {
    this->params = params;
    this->op = op;

    cleaning_lut_f = [](Torus x) -> Torus { return x; };

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
      cleaning_lut = new int_radix_lut<Torus>(
          stream, params, 1, num_radix_blocks, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          stream, cleaning_lut->lut, params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          cleaning_lut_f);

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
      }
    }
  }

  void release(cuda_stream_t *stream) {
    switch (op) {
    case COMPARISON_TYPE::MAX:
    case COMPARISON_TYPE::MIN:
      cmux_buffer->release(stream);
    case COMPARISON_TYPE::GT:
    case COMPARISON_TYPE::GE:
    case COMPARISON_TYPE::LT:
    case COMPARISON_TYPE::LE:
      diff_buffer->release(stream);
    case COMPARISON_TYPE::EQ:
    case COMPARISON_TYPE::NE:
      eq_buffer->release(stream);
      break;
    }
    cleaning_lut->release(stream);
    is_zero_lut->release(stream);
    delete is_zero_lut;
    cuda_drop_async(tmp_lwe_array_out, stream);
    cuda_drop_async(tmp_block_comparisons, stream);
    cuda_drop_async(tmp_packed_input, stream);

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

#endif // CUDA_INTEGER_H
