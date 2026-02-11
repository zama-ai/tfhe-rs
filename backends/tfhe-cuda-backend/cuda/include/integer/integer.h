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

enum Direction { Trailing = 0, Leading = 1 };

enum BitValue { Zero = 0, One = 1 };

extern "C" {

typedef struct {
  void *const *streams;
  uint32_t const *gpu_indexes;
  uint32_t gpu_count;
} CudaStreamsFFI;

typedef struct {
  void *ptr;
  uint64_t *degrees;
  uint64_t *noise_levels;
  uint32_t num_radix_blocks;
  uint32_t max_num_radix_blocks;
  uint32_t lwe_dimension;
} CudaRadixCiphertextFFI;

typedef struct {
  uint64_t const *chosen_multiplier_has_at_least_one_set;
  uint64_t const *decomposed_chosen_multiplier;

  uint32_t const num_scalars;
  uint32_t const active_bits;
  uint64_t const shift_pre;
  uint32_t const shift_post;
  uint32_t const ilog2_chosen_multiplier;
  uint32_t const chosen_multiplier_num_bits;

  bool const is_chosen_multiplier_zero;
  bool const is_abs_chosen_multiplier_one;
  bool const is_chosen_multiplier_negative;
  bool const is_chosen_multiplier_pow2;
  bool const chosen_multiplier_has_more_bits_than_numerator;
  // if signed: test if chosen_multiplier >= 2^{num_bits - 1}
  bool const is_chosen_multiplier_geq_two_pow_numerator;

  uint32_t const ilog2_divisor;

  bool const is_divisor_zero;
  bool const is_abs_divisor_one;
  bool const is_divisor_negative;
  bool const is_divisor_pow2;
  bool const divisor_has_more_bits_than_numerator;
} CudaScalarDivisorFFI;

typedef struct {
  void *ptr;
  uint32_t num_radix_blocks;
  uint32_t lwe_dimension;
} CudaLweCiphertextListFFI;

typedef struct {
  void *ptr;
  uint32_t storage_log_modulus;
  uint32_t num_lwes_stored_per_glwe;
  // Input LWEs are grouped by groups of `num_lwes_stored_per_glwe`(the last
  // group may be smaller) Each group is then packed into one GLWE with
  // `num_lwes_stored_per_glwe` bodies (one for each LWE of the group). In the
  // end the total number of bodies is equal to the number of input LWE
  uint32_t total_lwe_bodies_count;
  uint32_t glwe_dimension;
  uint32_t polynomial_size;
} CudaPackedGlweCiphertextListFFI;

uint64_t scratch_cuda_apply_univariate_lut_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, void const *input_lut,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t pbs_level,
    uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint64_t lut_degree,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);
uint64_t scratch_cuda_apply_many_univariate_lut_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, void const *input_lut,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t pbs_level,
    uint32_t pbs_base_log, uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t num_many_lut, uint64_t lut_degree, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);
void cuda_apply_univariate_lut_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks, void *const *bsks);

void cleanup_cuda_apply_univariate_lut_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void);

void cleanup_cuda_apply_many_univariate_lut_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void);

void cuda_apply_many_univariate_lut_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks, void *const *bsks, uint32_t num_luts,
    uint32_t lut_stride);

uint64_t scratch_cuda_full_propagation_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_full_propagation_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *input_blocks,
    int8_t *mem_ptr, void *const *ksks, void *const *bsks, uint32_t num_blocks);

void cleanup_cuda_full_propagation_64_inplace(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_mult_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, bool const is_boolean_left,
    bool const is_boolean_right, uint32_t message_modulus,
    uint32_t carry_modulus, uint32_t glwe_dimension, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t pbs_base_log, uint32_t pbs_level,
    uint32_t ks_base_log, uint32_t ks_level, uint32_t grouping_factor,
    uint32_t num_blocks, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_mult_64_async(CudaStreamsFFI streams,
                                CudaRadixCiphertextFFI *radix_lwe_out,
                                CudaRadixCiphertextFFI const *radix_lwe_left,
                                bool const is_bool_left,
                                CudaRadixCiphertextFFI const *radix_lwe_right,
                                bool const is_bool_right, void *const *bsks,
                                void *const *ksks, int8_t *mem_ptr,
                                uint32_t polynomial_size, uint32_t num_blocks);

void cleanup_cuda_integer_mult_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void);

void cuda_negate_ciphertext_64(CudaStreamsFFI streams,
                               CudaRadixCiphertextFFI *lwe_array_out,
                               CudaRadixCiphertextFFI const *lwe_array_in,
                               uint32_t message_modulus, uint32_t carry_modulus,
                               uint32_t num_radix_blocks);

void cuda_scalar_addition_ciphertext_64_inplace(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    void const *scalar_input, void const *h_scalar_input, uint32_t num_scalars,
    uint32_t message_modulus, uint32_t carry_modulus);

uint64_t scratch_cuda_logical_scalar_shift_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_logical_scalar_shift_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array, uint32_t shift,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks);

uint64_t scratch_cuda_arithmetic_scalar_shift_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_arithmetic_scalar_shift_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array, uint32_t shift,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks);

void cleanup_cuda_logical_scalar_shift_64_inplace(CudaStreamsFFI streams,
                                                  int8_t **mem_ptr_void);

void cleanup_cuda_arithmetic_scalar_shift_64_inplace(CudaStreamsFFI streams,
                                                     int8_t **mem_ptr_void);

uint64_t scratch_cuda_shift_and_rotate_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_shift_and_rotate_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    CudaRadixCiphertextFFI const *lwe_shift, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_shift_and_rotate_64_inplace(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_comparison_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, COMPARISON_TYPE op_type,
    bool is_signed, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

uint64_t scratch_cuda_integer_scalar_comparison_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, COMPARISON_TYPE op_type,
    bool is_signed, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_comparison_64_async(CudaStreamsFFI streams,
                                      CudaRadixCiphertextFFI *lwe_array_out,
                                      CudaRadixCiphertextFFI const *lwe_array_1,
                                      CudaRadixCiphertextFFI const *lwe_array_2,
                                      int8_t *mem_ptr, void *const *bsks,
                                      void *const *ksks);

void cuda_integer_scalar_comparison_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, void const *scalar_blocks,
    void const *h_scalar_blocks, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_scalar_blocks);

void cleanup_cuda_integer_comparison_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void);

void cleanup_cuda_integer_scalar_comparison_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void);

uint64_t scratch_cuda_boolean_bitop_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, BITOP_TYPE op_type,
    bool is_unchecked, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_boolean_bitop_64_async(CudaStreamsFFI streams,
                                 CudaRadixCiphertextFFI *lwe_array_out,
                                 CudaRadixCiphertextFFI const *lwe_array_1,
                                 CudaRadixCiphertextFFI const *lwe_array_2,
                                 int8_t *mem_ptr, void *const *bsks,
                                 void *const *ksks);

void cleanup_cuda_boolean_bitop_64(CudaStreamsFFI streams,
                                   int8_t **mem_ptr_void);

uint64_t scratch_cuda_boolean_bitnot_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t lwe_ciphertext_count, bool is_unchecked, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_boolean_bitnot_64_async(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *lwe_array,
                                  int8_t *mem_ptr, void *const *bsks,
                                  void *const *ksks);

void cleanup_cuda_boolean_bitnot_64(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void);

void cuda_bitnot_ciphertext_64(CudaStreamsFFI streams,
                               CudaRadixCiphertextFFI *radix_ciphertext,
                               uint32_t ct_message_modulus,
                               uint32_t param_message_modulus,
                               uint32_t param_carry_modulus);

uint64_t scratch_cuda_integer_bitop_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, BITOP_TYPE op_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

uint64_t scratch_cuda_integer_scalar_bitop_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, BITOP_TYPE op_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_scalar_bitop_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_input, void const *clear_blocks,
    void const *h_clear_blocks, uint32_t num_clear_blocks, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks);

void cuda_integer_bitop_64_async(CudaStreamsFFI streams,
                                 CudaRadixCiphertextFFI *lwe_array_out,
                                 CudaRadixCiphertextFFI const *lwe_array_1,
                                 CudaRadixCiphertextFFI const *lwe_array_2,
                                 int8_t *mem_ptr, void *const *bsks,
                                 void *const *ksks);

void cleanup_cuda_integer_bitop_64(CudaStreamsFFI streams,
                                   int8_t **mem_ptr_void);

void cleanup_cuda_integer_scalar_bitop_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void);

uint64_t scratch_cuda_cmux_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_cmux_64_async(CudaStreamsFFI streams,
                        CudaRadixCiphertextFFI *lwe_array_out,
                        CudaRadixCiphertextFFI const *lwe_condition,
                        CudaRadixCiphertextFFI const *lwe_array_true,
                        CudaRadixCiphertextFFI const *lwe_array_false,
                        int8_t *mem_ptr, void *const *bsks, void *const *ksks);

void cleanup_cuda_cmux_64(CudaStreamsFFI streams, int8_t **mem_ptr_void);

uint64_t scratch_cuda_scalar_rotate_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_scalar_rotate_64_inplace_async(CudaStreamsFFI streams,
                                         CudaRadixCiphertextFFI *lwe_array,
                                         uint32_t n, int8_t *mem_ptr,
                                         void *const *bsks, void *const *ksks);

void cleanup_cuda_scalar_rotate_64_inplace(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void);

uint64_t scratch_cuda_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t requested_flag, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

uint64_t scratch_cuda_add_and_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t requested_flag, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    CudaRadixCiphertextFFI *carry_out, const CudaRadixCiphertextFFI *carry_in,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t requested_flag, uint32_t uses_carry);

void cuda_add_and_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lhs_array,
    const CudaRadixCiphertextFFI *rhs_array, CudaRadixCiphertextFFI *carry_out,
    const CudaRadixCiphertextFFI *carry_in, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t requested_flag, uint32_t uses_carry);

void cleanup_cuda_propagate_single_carry_64_inplace(CudaStreamsFFI streams,
                                                    int8_t **mem_ptr_void);

void cleanup_cuda_add_and_propagate_single_carry_64_inplace(
    CudaStreamsFFI streams, int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_overflowing_sub_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t compute_overflow, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_overflowing_sub_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lhs_array,
    const CudaRadixCiphertextFFI *rhs_array,
    CudaRadixCiphertextFFI *overflow_block,
    const CudaRadixCiphertextFFI *input_borrow, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t compute_overflow,
    uint32_t uses_input_borrow);

void cleanup_cuda_integer_overflowing_sub_64_inplace(CudaStreamsFFI streams,
                                                     int8_t **mem_ptr_void);

uint64_t scratch_cuda_partial_sum_ciphertexts_vec_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_in_radix,
    uint32_t max_num_radix_in_vec, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool reduce_degrees_for_single_carry_propagation, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_partial_sum_ciphertexts_vec_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *radix_lwe_out,
    CudaRadixCiphertextFFI *radix_lwe_vec, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_partial_sum_ciphertexts_vec_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_scalar_mul_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t num_scalar_bits,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_scalar_mul_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    uint64_t const *decomposed_scalar, uint64_t const *has_at_least_one_set,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t num_scalars);

void cleanup_cuda_integer_scalar_mul_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_div_rem_64_async(
    CudaStreamsFFI streams, bool is_signed, int8_t **mem_ptr,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_div_rem_64_async(CudaStreamsFFI streams,
                                   CudaRadixCiphertextFFI *quotient,
                                   CudaRadixCiphertextFFI *remainder,
                                   CudaRadixCiphertextFFI const *numerator,
                                   CudaRadixCiphertextFFI const *divisor,
                                   bool is_signed, int8_t *mem_ptr,
                                   void *const *bsks, void *const *ksks);

void cleanup_cuda_integer_div_rem_64(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void);

void cuda_integer_reverse_blocks_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array);

uint64_t scratch_cuda_integer_abs_inplace_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, bool is_signed,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_abs_inplace_64_async(CudaStreamsFFI streams,
                                       CudaRadixCiphertextFFI *ct,
                                       int8_t *mem_ptr, bool is_signed,
                                       void *const *bsks, void *const *ksks);

void cleanup_cuda_integer_abs_inplace_64(CudaStreamsFFI streams,
                                         int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_are_all_comparisons_block_true_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_are_all_comparisons_block_true_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_radix_blocks);

void cleanup_cuda_integer_are_all_comparisons_block_true_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_is_at_least_one_comparisons_block_true_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_is_at_least_one_comparisons_block_true_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_radix_blocks);

void cleanup_cuda_integer_is_at_least_one_comparisons_block_true_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void);

void extend_radix_with_trivial_zero_blocks_msb_64(
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    CudaStreamsFFI streams);

void trim_radix_blocks_lsb_64(CudaRadixCiphertextFFI *output,
                              CudaRadixCiphertextFFI const *input,
                              CudaStreamsFFI streams);

void trim_radix_blocks_msb_64(CudaRadixCiphertextFFI *output,
                              CudaRadixCiphertextFFI const *input,
                              CudaStreamsFFI streams);

uint64_t scratch_cuda_apply_noise_squashing_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_glwe_dimension, uint32_t input_polynomial_size,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t pbs_level,
    uint32_t pbs_base_log, uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t num_original_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_apply_noise_squashing_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks, void *const *bsks);

void cleanup_cuda_apply_noise_squashing(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void);

uint64_t scratch_cuda_sub_and_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t requested_flag, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_sub_and_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lhs_array,
    const CudaRadixCiphertextFFI *rhs_array, CudaRadixCiphertextFFI *carry_out,
    const CudaRadixCiphertextFFI *carry_in, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t requested_flag, uint32_t uses_carry);

void cleanup_cuda_sub_and_propagate_single_carry_64_inplace(
    CudaStreamsFFI streams, int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_unsigned_scalar_div_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_unsigned_scalar_div_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *numerator_ct,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaScalarDivisorFFI *scalar_divisor_ffi);

void cleanup_cuda_integer_unsigned_scalar_div_radix_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_signed_scalar_div_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_signed_scalar_div_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *numerator_ct,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaScalarDivisorFFI *scalar_divisor_ffi, uint32_t numerator_bits);

void cleanup_cuda_integer_signed_scalar_div_radix_64(CudaStreamsFFI streams,
                                                     int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_unsigned_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint32_t const active_bits_divisor, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_unsigned_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *quotient_ct,
    CudaRadixCiphertextFFI *remainder_ct, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint64_t const *divisor_has_at_least_one_set,
    uint64_t const *decomposed_divisor, uint32_t const num_scalars_divisor,
    void const *clear_blocks, void const *h_clear_blocks,
    uint32_t num_clear_blocks);

void cleanup_cuda_integer_unsigned_scalar_div_rem_radix_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_signed_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint32_t const active_bits_divisor, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_signed_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *quotient_ct,
    CudaRadixCiphertextFFI *remainder_ct, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint64_t const *divisor_has_at_least_one_set,
    uint64_t const *decomposed_divisor, uint32_t const num_scalars_divisor,
    uint32_t numerator_bits);

void cleanup_cuda_integer_signed_scalar_div_rem_radix_64(CudaStreamsFFI streams,
                                                         int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_count_of_consecutive_bits_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t counter_num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    Direction direction, BitValue bit_value, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_count_of_consecutive_bits_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_ct,
    CudaRadixCiphertextFFI const *input_ct, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_integer_count_of_consecutive_bits_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_grouped_oprf_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_to_process,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, uint32_t message_bits_per_block,
    uint32_t total_random_bits, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_grouped_oprf_64_async(CudaStreamsFFI streams,
                                        CudaRadixCiphertextFFI *radix_lwe_out,
                                        const void *seeded_lwe_input,
                                        uint32_t num_blocks_to_process,
                                        int8_t *mem, void *const *bsks);

void cleanup_cuda_integer_grouped_oprf_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_grouped_oprf_custom_range_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_intermediate,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, uint32_t message_bits_per_block,
    uint32_t num_input_random_bits, uint32_t num_scalar_bits,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_grouped_oprf_custom_range_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *radix_lwe_out,
    uint32_t num_blocks_intermediate, const void *seeded_lwe_input,
    const uint64_t *decomposed_scalar, const uint64_t *has_at_least_one_set,
    uint32_t num_scalars, uint32_t shift, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_integer_grouped_oprf_custom_range_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_ilog2_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t input_num_blocks, uint32_t counter_num_blocks,
    uint32_t num_bits_in_ciphertext, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_ilog2_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_ct,
    CudaRadixCiphertextFFI const *input_ct,
    CudaRadixCiphertextFFI const *trivial_ct_neg_n,
    CudaRadixCiphertextFFI const *trivial_ct_2,
    CudaRadixCiphertextFFI const *trivial_ct_m_minus_1_block, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks);

void cleanup_cuda_integer_ilog2_64(CudaStreamsFFI streams,
                                   int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_match_value_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_output_packed_blocks, uint32_t max_output_is_zero,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_match_value_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_result,
    CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI const *lwe_array_in_ct,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    int8_t *mem, void *const *bsks, void *const *ksks);

void cleanup_cuda_unchecked_match_value_64(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void);

uint64_t scratch_cuda_cast_to_unsigned_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_input_blocks, uint32_t target_num_blocks, bool input_is_signed,
    bool requires_full_propagate, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_cast_to_unsigned_64_async(CudaStreamsFFI streams,
                                    CudaRadixCiphertextFFI *output,
                                    CudaRadixCiphertextFFI *input,
                                    int8_t *mem_ptr, uint32_t target_num_blocks,
                                    bool input_is_signed, void *const *bsks,
                                    void *const *ksks);

void cleanup_cuda_cast_to_unsigned_64(CudaStreamsFFI streams,
                                      int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_match_value_or_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_match_packed_blocks, uint32_t num_final_blocks,
    uint32_t max_output_is_zero, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_match_value_or_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_ct,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    const uint64_t *h_or_value, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_unchecked_match_value_or_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_contains_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_contains_64_async(CudaStreamsFFI streams,
                                      CudaRadixCiphertextFFI *output,
                                      CudaRadixCiphertextFFI const *inputs,
                                      CudaRadixCiphertextFFI const *value,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      int8_t *mem, void *const *bsks,
                                      void *const *ksks);

void cleanup_cuda_unchecked_contains_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_contains_clear_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_contains_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *inputs, const uint64_t *h_clear_val,
    uint32_t num_inputs, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_unchecked_contains_clear_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_is_in_clears_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_clears, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_is_in_clears_64_async(CudaStreamsFFI streams,
                                          CudaRadixCiphertextFFI *output,
                                          CudaRadixCiphertextFFI const *input,
                                          const uint64_t *h_cleartexts,
                                          uint32_t num_clears,
                                          uint32_t num_blocks, int8_t *mem,
                                          void *const *bsks, void *const *ksks);

void cleanup_cuda_unchecked_is_in_clears_64(CudaStreamsFFI streams,
                                            int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_index_in_clears_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_clears, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_index_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *input,
    const uint64_t *h_cleartexts, uint32_t num_clears, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_unchecked_index_in_clears_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_first_index_in_clears_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_unique, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_first_index_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *input,
    const uint64_t *h_unique_values, const uint64_t *h_unique_indices,
    uint32_t num_unique, uint32_t num_blocks, uint32_t num_blocks_index,
    int8_t *mem, void *const *bsks, void *const *ksks);

void cuda_small_scalar_multiplication_integer_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array, uint64_t scalar,
    const uint32_t message_modulus, const uint32_t carry_modulus);

void cleanup_cuda_unchecked_first_index_in_clears_64(CudaStreamsFFI streams,
                                                     int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_first_index_of_clear_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_first_index_of_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    const uint64_t *h_clear_val, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_unchecked_first_index_of_clear_64(CudaStreamsFFI streams,
                                                    int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_first_index_of_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_first_index_of_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    CudaRadixCiphertextFFI const *value, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index, int8_t *mem,
    void *const *bsks, void *const *ksks);

void cleanup_cuda_unchecked_first_index_of_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_index_of_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_index_of_64_async(CudaStreamsFFI streams,
                                      CudaRadixCiphertextFFI *index_ct,
                                      CudaRadixCiphertextFFI *match_ct,
                                      CudaRadixCiphertextFFI const *inputs,
                                      CudaRadixCiphertextFFI const *value,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index, int8_t *mem,
                                      void *const *bsks, void *const *ksks);

void cleanup_cuda_unchecked_index_of_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_index_of_clear_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_index_of_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    const void *d_scalar_blocks, bool is_scalar_obviously_bigger,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_scalar_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_unchecked_index_of_clear_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_all_eq_slices_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_all_eq_slices_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *match_ct,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    uint32_t num_inputs, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_unchecked_all_eq_slices_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void);

uint64_t scratch_cuda_unchecked_contains_sub_slice_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_lhs, uint32_t num_rhs, uint32_t num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_unchecked_contains_sub_slice_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *match_ct,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    uint32_t num_rhs, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_unchecked_contains_sub_slice_64(CudaStreamsFFI streams,
                                                  int8_t **mem_ptr_void);

uint64_t scratch_cuda_cast_to_signed_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_input_blocks,
    uint32_t target_num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool input_is_signed,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_cast_to_signed_64_async(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *output,
                                  CudaRadixCiphertextFFI const *input,
                                  int8_t *mem, bool input_is_signed,
                                  void *const *bsks, void *const *ksks);

void cleanup_cuda_cast_to_signed_64(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void);
} // extern C

#endif // CUDA_INTEGER_H
