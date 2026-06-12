#ifndef CUDA_INTEGER_GOLDSCHMIDT_DIVISION_H
#define CUDA_INTEGER_GOLDSCHMIDT_DIVISION_H

#include "integer/bitwise_ops.cuh"
#include "integer/comparison.cuh"
#include "integer/ilog2.cuh"
#include "integer/integer.h"
#include "integer/multiplication.h"
#include "integer/radix_ciphertext.h"
#include "integer/shift_and_rotate.cuh"
#include "integer/vector_find.h"
#include "helper_profile.cuh"
#include <cstdio>

template <typename Torus> struct int_goldschmidt_division_buffer {

  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_radix_blocks;
  uint32_t lut_precision;
  uint32_t intermediate_num_blocks;

  int_count_of_consecutive_bits_buffer<Torus> *count_leading_zeros_buffer;
  int_comparison_buffer<Torus> *is_denominator_zero_buffer;
  int_shift_and_rotate_buffer<Torus> *normalize_batched_shift_buffer;
  Torus *d_zero_scalar;

  CudaRadixCiphertextFFI *current_numerator_Ni;
  CudaRadixCiphertextFFI *current_denominator_Di;
  CudaRadixCiphertextFFI *next_numerator_Ni;
  CudaRadixCiphertextFFI *next_denominator_Di;
  CudaRadixCiphertextFFI *x_long;

  uint32_t num_x0_blocks;
  uint64_t *host_approx_lut_inputs;
  uint64_t *host_approx_lut_outputs;
  int_unchecked_match_buffer<Torus> *approx_lut_eval_buffer;

  int_asymmetric_mul_memory<Torus> *mul_mem;
  CudaRadixCiphertextFFI *full_precision_product_buffer;
  CudaRadixCiphertextFFI *padded_lhs_operand;

  CudaRadixCiphertextFFI *trivial_1;
  CudaRadixCiphertextFFI *trivial_2;
  CudaRadixCiphertextFFI *trivial_msg_modulus_minus_1;
  CudaRadixCiphertextFFI *trivial_max;
  Torus *h_max_scalars;
  Torus *d_max_scalars;

  CudaRadixCiphertextFFI *numerator_bitnot;
  CudaRadixCiphertextFFI *r_partial_sum;
  CudaRadixCiphertextFFI *r_partial_sum_batched;
  CudaRadixCiphertextFFI *r_message_blocks;
  CudaRadixCiphertextFFI *r_carry_blocks;
  CudaRadixCiphertextFFI *r_carry_shifted;
  CudaRadixCiphertextFFI *r_msg_and_carry_batched;
  int_radix_lut<Torus> *finalize_extract_invert_batched_lut;
  CudaRadixCiphertextFFI *mul_low_terms_assembled;
  int_sum_ciphertexts_vec_memory<Torus> *finalize_mul_low_sum_mem;
  int_sc_prop_memory<Torus> *finalize_sc_prop_mem;
  int_borrow_prop_memory<Torus> *finalize_borrow_prop_mem;
  int_cmux_buffer<Torus> *finalize_cmux_mem;

  uint32_t *d_map;
  uint32_t *h_map;
  uint32_t *h_lut_idx;

  int_goldschmidt_division_buffer(CudaStreams streams, int_radix_params params,
                                  uint32_t num_radix_blocks,
                                  uint32_t lut_precision,
                                  bool allocate_gpu_memory,
                                  uint64_t &size_tracker) {
    uint64_t prev_size = size_tracker;
    auto print_mem_usage = [&](const char *step_name) {
      uint64_t diff = size_tracker - prev_size;
      if (diff > 0) {
        printf("[Mem Profiling] %s : %llu bytes\n", step_name,
               (unsigned long long)diff);
      }
      prev_size = size_tracker;
    };

    PUSH_RANGE("Goldschmidt Setup: Init Params");
    this->params = params;
    this->num_radix_blocks = num_radix_blocks;
    this->lut_precision = lut_precision;
    this->allocate_gpu_memory = allocate_gpu_memory;

    uint32_t bits_per_block = log2_int(params.message_modulus);
    uint32_t total_bits = num_radix_blocks * bits_per_block;
    uint32_t required_bits = total_bits + 2 * bits_per_block;
    uint32_t calculated_intermediate_blocks =
        (required_bits + bits_per_block - 1) / bits_per_block;

    this->intermediate_num_blocks =
        std::max(calculated_intermediate_blocks, 2 * num_radix_blocks);
    POP_RANGE();
    print_mem_usage("Init Params (No alloc)");

    PUSH_RANGE("Goldschmidt Setup: count_leading_zeros");
    count_leading_zeros_buffer =
        new int_count_of_consecutive_bits_buffer<Torus>(
            streams, params, num_radix_blocks, num_radix_blocks, (Direction)1,
            (BitValue)0, allocate_gpu_memory, size_tracker);
    POP_RANGE();
    print_mem_usage("count_leading_zeros_buffer");

    PUSH_RANGE("Goldschmidt Setup: is_denominator_zero");
    is_denominator_zero_buffer = new int_comparison_buffer<Torus>(
        streams, COMPARISON_TYPE::EQ, params, num_radix_blocks, false,
        allocate_gpu_memory, size_tracker);
    POP_RANGE();
    print_mem_usage("is_denominator_zero_buffer");

    PUSH_RANGE("Goldschmidt Setup: normalize_batched_shift");
    normalize_batched_shift_buffer = new int_shift_and_rotate_buffer<Torus>(
        streams, LEFT_SHIFT, false, params, 3 * num_radix_blocks,
        allocate_gpu_memory, size_tracker);
    POP_RANGE();
    print_mem_usage("normalize_batched_shift_buffer");

    PUSH_RANGE("Goldschmidt Setup: d_zero_scalar");
    d_zero_scalar = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    if (allocate_gpu_memory) {
      cuda_memset_async(d_zero_scalar, 0, num_radix_blocks * sizeof(Torus),
                        streams.stream(0), streams.gpu_index(0));
    }
    POP_RANGE();
    print_mem_usage("d_zero_scalar");

    PUSH_RANGE("Goldschmidt Setup: Ciphertexts 1");
    current_numerator_Ni = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), current_numerator_Ni,
        intermediate_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    current_denominator_Di = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), current_denominator_Di,
        intermediate_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint32_t max_intermediate_len = 3 * intermediate_num_blocks;

    full_precision_product_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), full_precision_product_buffer,
        max_intermediate_len, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    padded_lhs_operand = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), padded_lhs_operand,
        max_intermediate_len, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    POP_RANGE();
    print_mem_usage("Ciphertexts 1 (N_i, D_i, Product Buffer, Padded LHS)");

    uint32_t optimal_rhs_blocks = num_radix_blocks + (num_radix_blocks / 2);

    PUSH_RANGE("Goldschmidt Setup: mul_mem");
    mul_mem = new int_asymmetric_mul_memory<Torus>(
        streams, params, false, false, max_intermediate_len, optimal_rhs_blocks,
        allocate_gpu_memory, size_tracker);
    POP_RANGE();
    print_mem_usage("mul_mem (Multiplication Memory Engine)");

    PUSH_RANGE("Goldschmidt Setup: Approx LUT Arrays");
    this->num_x0_blocks = (lut_precision + 1) / bits_per_block;
    uint32_t num_matches = 1 << lut_precision;
    uint32_t packed_len = (this->num_x0_blocks + 1) / 2;

    this->host_approx_lut_inputs =
        new uint64_t[num_matches * this->num_x0_blocks];
    this->host_approx_lut_outputs = new uint64_t[num_matches * packed_len];

    uint64_t start_val = 1ULL << lut_precision;
    uint32_t bits_per_packed = 2 * bits_per_block;
    uint64_t mask_packed = (1ULL << bits_per_packed) - 1;

    for (uint32_t i = 0; i < num_matches; i++) {
      uint64_t val = start_val + i;
      uint64_t out_val = ((1ULL << (2 + 2 * lut_precision)) / (val + 1)) -
                         (1ULL << (lut_precision + 1));

      for (uint32_t b = 0; b < this->num_x0_blocks; b++) {
        this->host_approx_lut_inputs[i * this->num_x0_blocks + b] =
            (val >> (b * bits_per_block)) & (params.message_modulus - 1);
      }

      for (uint32_t b = 0; b < packed_len; b++) {
        this->host_approx_lut_outputs[i * packed_len + b] =
            (out_val >> (b * bits_per_packed)) & mask_packed;
      }
    }
    POP_RANGE();
    print_mem_usage("Approx LUT Arrays (Host Only)");

    PUSH_RANGE("Goldschmidt Setup: approx_lut_eval_buffer (ALIASED)");
    uint32_t approx_offset = 0;
    this->approx_lut_eval_buffer = new int_unchecked_match_buffer<Torus>(
        streams, params, num_matches, this->num_x0_blocks, packed_len, false,
        allocate_gpu_memory, size_tracker, mul_mem->block_mul_res,
        &approx_offset);
    POP_RANGE();
    print_mem_usage("approx_lut_eval_buffer (Aliased on mul_mem)");

    PUSH_RANGE("Goldschmidt Setup: Ciphertexts 2");
    x_long = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), x_long,
        intermediate_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    next_numerator_Ni = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), next_numerator_Ni,
        intermediate_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    next_denominator_Di = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), next_denominator_Di,
        intermediate_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    POP_RANGE();
    print_mem_usage("Ciphertexts 2 (x_long, next_N, next_D)");

    PUSH_RANGE("Goldschmidt Setup: Trivial 1");
    trivial_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_1, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    set_single_scalar_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_1, 1,
        params.message_modulus, params.carry_modulus);
    POP_RANGE();
    print_mem_usage("Trivial 1");

    PUSH_RANGE("Goldschmidt Setup: Trivial Max");
    trivial_max = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_max, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    h_max_scalars = new Torus[num_radix_blocks];
    for (uint32_t i = 0; i < num_radix_blocks; i++)
      h_max_scalars[i] = params.message_modulus - 1;
    d_max_scalars = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    if (allocate_gpu_memory) {
      cuda_memcpy_async_to_gpu(d_max_scalars, h_max_scalars,
                               num_radix_blocks * sizeof(Torus),
                               streams.stream(0), streams.gpu_index(0));
    }
    set_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_max, d_max_scalars,
        h_max_scalars, num_radix_blocks, params.message_modulus,
        params.carry_modulus);
    POP_RANGE();
    print_mem_usage("Trivial Max");

    PUSH_RANGE("Goldschmidt Setup: Finalize Mem 1");
    finalize_sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, params, num_radix_blocks, outputFlag::FLAG_NONE,
        allocate_gpu_memory, size_tracker);
    finalize_borrow_prop_mem = new int_borrow_prop_memory<Torus>(
        streams, params, num_radix_blocks, outputFlag::FLAG_OVERFLOW,
        allocate_gpu_memory, size_tracker);

    auto f_identity = [](Torus x) -> Torus { return x; };
    finalize_cmux_mem = new int_cmux_buffer<Torus>(
        streams, f_identity, params, 2 * num_radix_blocks, allocate_gpu_memory,
        size_tracker);
    POP_RANGE();
    print_mem_usage("Finalize Mem 1 (SC Prop, Borrow Prop, CMUX)");

    PUSH_RANGE("Goldschmidt Setup: Trivial 2 and Modulus");
    trivial_2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_2, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    set_single_scalar_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_2, 2,
        params.message_modulus, params.carry_modulus);

    trivial_msg_modulus_minus_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_msg_modulus_minus_1, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    set_single_scalar_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_msg_modulus_minus_1,
        params.message_modulus - 1, params.message_modulus,
        params.carry_modulus);
    POP_RANGE();
    print_mem_usage("Trivial 2 and Modulus");

    PUSH_RANGE("Goldschmidt Setup: Finalize CTs");
    numerator_bitnot = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), numerator_bitnot,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    r_partial_sum = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), r_partial_sum,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    r_message_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), r_message_blocks,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    r_carry_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), r_carry_blocks,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    r_carry_shifted = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), r_carry_shifted,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint32_t total_terms_mul_low = 2 * num_radix_blocks + 2;
    mul_low_terms_assembled = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mul_low_terms_assembled,
        total_terms_mul_low * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    r_partial_sum_batched = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), r_partial_sum_batched,
        2 * num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    r_msg_and_carry_batched = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), r_msg_and_carry_batched,
        2 * num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    POP_RANGE();
    print_mem_usage("Finalize CTs");

    PUSH_RANGE("Goldschmidt Setup: Finalize Mem 2");
    finalize_mul_low_sum_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, params, num_radix_blocks, total_terms_mul_low, true,
        allocate_gpu_memory, size_tracker);

    finalize_extract_invert_batched_lut =
        new int_radix_lut<Torus>(streams, params, 2, 2 * num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);
    POP_RANGE();
    print_mem_usage("Finalize Mem 2 (Sum Vec Mem + Batched LUT)");

    PUSH_RANGE("Goldschmidt Setup: LUT Gen Batched");
    auto msg_modulus = params.message_modulus;
    auto f_msg_invert = [msg_modulus](Torus x) -> Torus {
      Torus msg = x % msg_modulus;
      return (~msg) % msg_modulus;
    };
    auto f_carry_invert = [msg_modulus](Torus x) -> Torus {
      Torus carry = x / msg_modulus;
      return (~carry) % msg_modulus;
    };

    auto active_streams =
        streams.active_gpu_subset(2 * num_radix_blocks, params.pbs_type);

    // First num_radix_blocks blocks use LUT 0 (message invert), the next
    // num_radix_blocks blocks use LUT 1 (carry invert).
    auto lut_index_generator = [num_radix_blocks](Torus *h_lut_indexes,
                                                  uint32_t num_indexes) {
      for (uint32_t i = 0; i < num_indexes; i++) {
        h_lut_indexes[i] = (i < num_radix_blocks) ? 0 : 1;
      }
    };
    finalize_extract_invert_batched_lut->generate_and_broadcast_lut(
        active_streams, {0, 1}, {f_msg_invert, f_carry_invert},
        lut_index_generator);
    POP_RANGE();
    print_mem_usage("LUT Gen Batched");

    PUSH_RANGE("Goldschmidt Setup: Map Allocations");
    uint32_t max_total_blocks = 2 * max_intermediate_len * optimal_rhs_blocks;
    this->h_map = new uint32_t[max_total_blocks];
    this->h_lut_idx = new uint32_t[max_total_blocks];
    this->d_map = (uint32_t *)cuda_malloc_with_size_tracking_async(
        max_total_blocks * sizeof(uint32_t), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    POP_RANGE();
  }

  void release(CudaStreams streams) {
    PUSH_RANGE("Release: clz");
    count_leading_zeros_buffer->release(streams);
    delete count_leading_zeros_buffer;
    POP_RANGE();

    PUSH_RANGE("Release: is_denom_zero");
    is_denominator_zero_buffer->release(streams);
    delete is_denominator_zero_buffer;
    POP_RANGE();

    PUSH_RANGE("Release: norm_shift");
    normalize_batched_shift_buffer->release(streams);
    delete normalize_batched_shift_buffer;
    POP_RANGE();

    PUSH_RANGE("Release: mul_mem");
    mul_mem->release(streams);
    delete mul_mem;
    POP_RANGE();

    PUSH_RANGE("Release: d_zero_scalar");
    if (allocate_gpu_memory)
      cuda_drop_async(d_zero_scalar, streams.stream(0), streams.gpu_index(0));
    POP_RANGE();

    PUSH_RANGE("Release: CTs 1");
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   current_numerator_Ni, allocate_gpu_memory);
    delete current_numerator_Ni;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   current_denominator_Di, allocate_gpu_memory);
    delete current_denominator_Di;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   full_precision_product_buffer,
                                   allocate_gpu_memory);
    delete full_precision_product_buffer;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   padded_lhs_operand, allocate_gpu_memory);
    delete padded_lhs_operand;
    POP_RANGE();

    PUSH_RANGE("Release: approx_lut_eval");
    this->approx_lut_eval_buffer->release(streams);
    delete this->approx_lut_eval_buffer;
    POP_RANGE();

    PUSH_RANGE("Release: CTs 2");
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   x_long, allocate_gpu_memory);
    delete x_long;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   next_numerator_Ni, allocate_gpu_memory);
    delete next_numerator_Ni;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   next_denominator_Di, allocate_gpu_memory);
    delete next_denominator_Di;
    POP_RANGE();

    PUSH_RANGE("Release: Trivials");
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   trivial_1, allocate_gpu_memory);
    delete trivial_1;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   trivial_max, allocate_gpu_memory);
    delete trivial_max;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   trivial_2, allocate_gpu_memory);
    delete trivial_2;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   trivial_msg_modulus_minus_1,
                                   allocate_gpu_memory);
    delete trivial_msg_modulus_minus_1;
    POP_RANGE();

    PUSH_RANGE("Release: Finalize CTs");
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   numerator_bitnot, allocate_gpu_memory);
    delete numerator_bitnot;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   r_partial_sum, allocate_gpu_memory);
    delete r_partial_sum;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   r_message_blocks, allocate_gpu_memory);
    delete r_message_blocks;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   r_carry_blocks, allocate_gpu_memory);
    delete r_carry_blocks;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   r_carry_shifted, allocate_gpu_memory);
    delete r_carry_shifted;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   mul_low_terms_assembled,
                                   allocate_gpu_memory);
    delete mul_low_terms_assembled;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   r_partial_sum_batched, allocate_gpu_memory);
    delete r_partial_sum_batched;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   r_msg_and_carry_batched,
                                   allocate_gpu_memory);
    delete r_msg_and_carry_batched;
    POP_RANGE();

    PUSH_RANGE("Release: Finalize Mems");
    finalize_mul_low_sum_mem->release(streams);
    delete finalize_mul_low_sum_mem;

    finalize_extract_invert_batched_lut->release(streams);
    delete finalize_extract_invert_batched_lut;
    POP_RANGE();

    PUSH_RANGE("Release: Max Scalars");
    if (allocate_gpu_memory)
      cuda_drop_async(d_max_scalars, streams.stream(0), streams.gpu_index(0));
    delete[] h_max_scalars;
    POP_RANGE();

    PUSH_RANGE("Release: Prop and CMUX");
    finalize_sc_prop_mem->release(streams);
    delete finalize_sc_prop_mem;
    finalize_borrow_prop_mem->release(streams);
    delete finalize_borrow_prop_mem;
    finalize_cmux_mem->release(streams);
    delete finalize_cmux_mem;
    POP_RANGE();

    PUSH_RANGE("Release: Approx inputs");
    delete[] this->host_approx_lut_inputs;
    delete[] this->host_approx_lut_outputs;
    POP_RANGE();

    PUSH_RANGE("Release: Map");
    delete[] this->h_map;
    delete[] this->h_lut_idx;
    cuda_drop_async(this->d_map, streams.stream(0), streams.gpu_index(0));
    POP_RANGE();

    PUSH_RANGE("Release: Sync");
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    POP_RANGE();
  }
};

#endif
