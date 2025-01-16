#ifndef CUDA_INTEGER_H
#define CUDA_INTEGER_H

#include "../pbs/pbs_enums.h"
#include <stdint.h>

enum OUTPUT_CARRY { NONE = 0, GENERATED = 1, PROPAGATED = 2 };
enum SHIFT_OR_ROTATE_TYPE {
  LEFT_SHIFT = 0,
  RIGHT_SHIFT = 1,
  LEFT_ROTATE = 2,
  RIGHT_ROTATE = 3
};
enum BITOP_TYPE {
  BITAND = 0,
  BITOR = 1,
  BITXOR = 2,
  SCALAR_BITAND = 3,
  SCALAR_BITOR = 4,
  SCALAR_BITXOR = 5,
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

enum CMP_ORDERING { IS_INFERIOR = 0, IS_EQUAL = 1, IS_SUPERIOR = 2 };

enum SIGNED_OPERATION { ADDITION = 1, SUBTRACTION = -1 };

enum outputFlag { FLAG_NONE = 0, FLAG_OVERFLOW = 1, FLAG_CARRY = 2 };

extern "C" {

typedef struct {
  void *ptr;
  uint64_t *degrees;
  uint64_t *noise_levels;
  uint32_t num_radix_blocks;
  uint32_t lwe_dimension;
} CudaRadixCiphertextFFI;

void scratch_cuda_apply_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);
void scratch_cuda_apply_many_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t num_many_lut, bool allocate_gpu_memory);
void cuda_apply_univariate_lut_kb_64(void *const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count, void *output_radix_lwe,
                                     void const *input_radix_lwe,
                                     int8_t *mem_ptr, void *const *ksks,
                                     void *const *bsks, uint32_t num_blocks);

void cleanup_cuda_apply_univariate_lut_kb_64(void *const *streams,
                                             uint32_t const *gpu_indexes,
                                             uint32_t gpu_count,
                                             int8_t **mem_ptr_void);

void scratch_cuda_apply_bivariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_apply_bivariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *output_radix_lwe, void const *input_radix_lwe_1,
    void const *input_radix_lwe_2, int8_t *mem_ptr, void *const *ksks,
    void *const *bsks, uint32_t num_blocks, uint32_t shift);

void cleanup_cuda_apply_bivariate_lut_kb_64(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count,
                                            int8_t **mem_ptr_void);

void cuda_apply_many_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *output_radix_lwe, void const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks, void *const *bsks, uint32_t num_blocks,
    uint32_t num_luts, uint32_t lut_stride);

void scratch_cuda_full_propagation_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_full_propagation_64_inplace(void *const *streams,
                                      uint32_t const *gpu_indexes,
                                      uint32_t gpu_count, void *input_blocks,
                                      int8_t *mem_ptr, void *const *ksks,
                                      void *const *bsks, uint32_t num_blocks);

void cleanup_cuda_full_propagation(void *const *streams,
                                   uint32_t const *gpu_indexes,
                                   uint32_t gpu_count, int8_t **mem_ptr_void);

void scratch_cuda_integer_mult_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, bool const is_boolean_left, bool const is_boolean_right,
    uint32_t message_modulus, uint32_t carry_modulus, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t pbs_base_log,
    uint32_t pbs_level, uint32_t ks_base_log, uint32_t ks_level,
    uint32_t grouping_factor, uint32_t num_blocks, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_integer_mult_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *radix_lwe_out, void const *radix_lwe_left, bool const is_bool_left,
    void const *radix_lwe_right, bool const is_bool_right, void *const *bsks,
    void *const *ksks, int8_t *mem_ptr, uint32_t polynomial_size,
    uint32_t num_blocks);

void cleanup_cuda_integer_mult(void *const *streams,
                               uint32_t const *gpu_indexes, uint32_t gpu_count,
                               int8_t **mem_ptr_void);

void cuda_negate_integer_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_in, uint32_t lwe_dimension,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus);

void cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, void const *scalar_input, uint32_t lwe_dimension,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus);

void scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory);

void cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, uint32_t shift, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks);

void scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory);

void cuda_integer_radix_arithmetic_scalar_shift_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, uint32_t shift, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks);

void cleanup_cuda_integer_radix_logical_scalar_shift(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void cleanup_cuda_integer_radix_arithmetic_scalar_shift(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_shift_and_rotate_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool is_signed, bool allocate_gpu_memory);

void cuda_integer_radix_shift_and_rotate_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, void const *lwe_shift, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks);

void cleanup_cuda_integer_radix_shift_and_rotate(void *const *streams,
                                                 uint32_t const *gpu_indexes,
                                                 uint32_t gpu_count,
                                                 int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_comparison_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    COMPARISON_TYPE op_type, bool is_signed, bool allocate_gpu_memory);

void cuda_comparison_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_1, void const *lwe_array_2,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t lwe_ciphertext_count);

void cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_in, void const *scalar_blocks,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t lwe_ciphertext_count, uint32_t num_scalar_blocks);

void cleanup_cuda_integer_comparison(void *const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count, int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_bitop_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    BITOP_TYPE op_type, bool allocate_gpu_memory);

void cuda_bitop_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_1, void const *lwe_array_2,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t lwe_ciphertext_count);

void cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_input, void const *clear_blocks,
    uint32_t num_clear_blocks, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t lwe_ciphertext_count, BITOP_TYPE op);

void cleanup_cuda_integer_bitop(void *const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_cmux_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_cmux_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_condition,
    CudaRadixCiphertextFFI const *lwe_array_true,
    CudaRadixCiphertextFFI const *lwe_array_false, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks);

void cleanup_cuda_integer_radix_cmux(void *const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count, int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_scalar_rotate_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory);

void cuda_integer_radix_scalar_rotate_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, uint32_t n, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks);

void cleanup_cuda_integer_radix_scalar_rotate(void *const *streams,
                                              uint32_t const *gpu_indexes,
                                              uint32_t gpu_count,
                                              int8_t **mem_ptr_void);

void scratch_cuda_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t requested_flag,
    uint32_t uses_carry, bool allocate_gpu_memory);

void scratch_cuda_add_and_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t requested_flag,
    uint32_t uses_carry, bool allocate_gpu_memory);

void cuda_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, void *carry_out, const void *carry_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_blocks,
    uint32_t requested_flag, uint32_t uses_carry);

void cuda_add_and_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lhs_array, const void *rhs_array, void *carry_out,
    const void *carry_in, int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t num_blocks, uint32_t requested_flag, uint32_t uses_carry);

void cleanup_cuda_propagate_single_carry(void *const *streams,
                                         uint32_t const *gpu_indexes,
                                         uint32_t gpu_count,
                                         int8_t **mem_ptr_void);

void cleanup_cuda_add_and_propagate_single_carry(void *const *streams,
                                                 uint32_t const *gpu_indexes,
                                                 uint32_t gpu_count,
                                                 int8_t **mem_ptr_void);

void scratch_cuda_integer_overflowing_sub_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t compute_overflow,
    bool allocate_gpu_memory);

void cuda_integer_overflowing_sub_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lhs_array, const void *rhs_array, void *overflow_block,
    const void *input_borrow, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks, uint32_t compute_overflow,
    uint32_t uses_input_borrow);

void cleanup_cuda_integer_overflowing_sub(void *const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count,
                                          int8_t **mem_ptr_void);

void scratch_cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks_in_radix, uint32_t max_num_radix_in_vec,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *radix_lwe_out, void *radix_lwe_vec, uint32_t num_radix_in_vec,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t num_blocks_in_radix);

void cleanup_cuda_integer_radix_partial_sum_ciphertexts_vec(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void scratch_cuda_integer_scalar_mul_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_scalar_multiplication_integer_radix_ciphertext_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, uint64_t const *decomposed_scalar,
    uint64_t const *has_at_least_one_set, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t message_modulus, uint32_t num_blocks, uint32_t num_scalars);

void cleanup_cuda_integer_radix_scalar_mul(void *const *streams,
                                           uint32_t const *gpu_indexes,
                                           uint32_t gpu_count,
                                           int8_t **mem_ptr_void);

void scratch_cuda_integer_div_rem_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    bool is_signed, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_integer_div_rem_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *quotient, void *remainder, void const *numerator, void const *divisor,
    bool is_signed, int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t num_blocks_in_radix);

void cleanup_cuda_integer_div_rem(void *const *streams,
                                  uint32_t const *gpu_indexes,
                                  uint32_t gpu_count, int8_t **mem_ptr_void);

void scratch_cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *output_radix_lwe, void *generates_or_propagates, int8_t *mem_ptr,
    void *const *ksks, void *const *bsks, uint32_t num_blocks, uint32_t shift);

void cleanup_cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void cuda_integer_reverse_blocks_64_inplace(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count, void *lwe_array,
                                            uint32_t num_blocks,
                                            uint32_t lwe_size);

void scratch_cuda_integer_abs_inplace_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, bool is_signed, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory);

void cuda_integer_abs_inplace_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *ct, int8_t *mem_ptr, bool is_signed,
    void *const *bsks, void *const *ksks);

void cleanup_cuda_integer_abs_inplace(void *const *streams,
                                      uint32_t const *gpu_indexes,
                                      uint32_t gpu_count,
                                      int8_t **mem_ptr_void);

void scratch_cuda_integer_are_all_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_integer_are_all_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_radix_blocks);

void cleanup_cuda_integer_are_all_comparisons_block_true(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void scratch_cuda_integer_is_at_least_one_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory);

void cuda_integer_is_at_least_one_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_radix_blocks);

void cleanup_cuda_integer_is_at_least_one_comparisons_block_true(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

} // extern C
#endif // CUDA_INTEGER_H
