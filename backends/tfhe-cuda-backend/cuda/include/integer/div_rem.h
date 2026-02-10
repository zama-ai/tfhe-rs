#pragma once
#include "abs.h"
#include "bitwise_ops.h"
#include "comparison.h"
#include "integer_utilities.h"
#include "scalar_shifts.h"

// used only when 4 gpus are available
template <typename Torus> struct unsigned_int_div_rem_2_2_memory {
  int_radix_params params;
  bool gpu_memory_allocated;

  // memory objects for other operations
  int_borrow_prop_memory<Torus> *overflow_sub_mem_1;
  int_borrow_prop_memory<Torus> *overflow_sub_mem_2;
  int_borrow_prop_memory<Torus> *overflow_sub_mem_3;
  int_comparison_buffer<Torus> *comparison_buffer_1;
  int_comparison_buffer<Torus> *comparison_buffer_2;
  int_comparison_buffer<Torus> *comparison_buffer_3;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem;
  int_bitop_buffer<Torus> *bitor_mem_1;
  int_bitop_buffer<Torus> *bitor_mem_2;
  int_bitop_buffer<Torus> *bitor_mem_3;
  int_logical_scalar_shift_buffer<Torus> *shift_mem;

  // lookup tables
  int_radix_lut<Torus> *message_extract_lut_1;
  int_radix_lut<Torus> *message_extract_lut_2;
  int_radix_lut<Torus> *zero_out_if_not_1_lut_1;
  int_radix_lut<Torus> *zero_out_if_not_1_lut_2;
  int_radix_lut<Torus> *zero_out_if_not_2_lut_1;
  int_radix_lut<Torus> *zero_out_if_not_2_lut_2;
  int_radix_lut<Torus> *quotient_lut_1;
  int_radix_lut<Torus> *quotient_lut_2;
  int_radix_lut<Torus> *quotient_lut_3;

  // sub streams
  CudaStreams sub_streams_1;

  // temporary device buffers
  CudaRadixCiphertextFFI *d1;                  // num_blocks + 1
  CudaRadixCiphertextFFI *d2;                  // num_blocks + 1
  CudaRadixCiphertextFFI *d3;                  // num_blocks + 1
  CudaRadixCiphertextFFI *tmp_gpu_0;           // num_blocks + 1
  CudaRadixCiphertextFFI *tmp_gpu_1;           // num_blocks + 1
  CudaRadixCiphertextFFI *tmp_gpu_2;           // num_blocks + 1
  CudaRadixCiphertextFFI *tmp_gpu_3;           // num_blocks + 1
  CudaRadixCiphertextFFI *divisor_gpu_1;       // num_blocks
  CudaRadixCiphertextFFI *divisor_gpu_2;       // num_blocks
  CudaRadixCiphertextFFI *remainder_gpu_1;     // num_blocks
  CudaRadixCiphertextFFI *remainder_gpu_2;     // num_blocks
  CudaRadixCiphertextFFI *remainder_gpu_3;     // num_blocks
  CudaRadixCiphertextFFI *low1;                // num_blocks
  CudaRadixCiphertextFFI *low2;                // num_blocks
  CudaRadixCiphertextFFI *low3;                // num_blocks
  CudaRadixCiphertextFFI *rem0;                // num_blocks
  CudaRadixCiphertextFFI *rem1;                // num_blocks
  CudaRadixCiphertextFFI *rem2;                // num_blocks
  CudaRadixCiphertextFFI *rem3;                // num_blocks
  CudaRadixCiphertextFFI *sub_result_1;        // num_blocks
  CudaRadixCiphertextFFI *sub_result_2;        // num_blocks
  CudaRadixCiphertextFFI *sub_result_3;        // num_blocks
  CudaRadixCiphertextFFI *sub_1_overflowed;    // num_blocks
  CudaRadixCiphertextFFI *sub_2_overflowed;    // num_blocks
  CudaRadixCiphertextFFI *sub_3_overflowed;    // num_blocks
  CudaRadixCiphertextFFI *comparison_blocks_1; // num_blocks
  CudaRadixCiphertextFFI *comparison_blocks_2; // num_blocks
  CudaRadixCiphertextFFI *comparison_blocks_3; // num_blocks
  CudaRadixCiphertextFFI *cmp_1;               // boolean block
  CudaRadixCiphertextFFI *cmp_2;               // boolean block
  CudaRadixCiphertextFFI *cmp_3;               // boolean block
  CudaRadixCiphertextFFI *c0;                  // single block
  CudaRadixCiphertextFFI *q1;                  // single block
  CudaRadixCiphertextFFI *q2;                  // single block
  CudaRadixCiphertextFFI *q3;                  // single block

  Torus *h_buffer; // used for memory copies

  Torus **first_indexes_for_overflow_sub_gpu_0;
  Torus **second_indexes_for_overflow_sub_gpu_0;
  Torus **scalars_for_overflow_sub_gpu_0;

  Torus **first_indexes_for_overflow_sub_gpu_1;
  Torus **second_indexes_for_overflow_sub_gpu_1;
  Torus **scalars_for_overflow_sub_gpu_1;

  Torus **first_indexes_for_overflow_sub_gpu_2;
  Torus **second_indexes_for_overflow_sub_gpu_2;
  Torus **scalars_for_overflow_sub_gpu_2;

  cudaEvent_t create_indexes_done;

  uint32_t max_indexes_to_erase;
  uint64_t tmp_size_tracker = 0;

  // allocate and initialize if needed, temporary arrays used to calculate
  // cuda integer div_rem_2_2 operation
  void init_temporary_buffers(CudaStreams streams, uint32_t num_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {

    // more than one block temporary arrays
    tmp_gpu_0 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_gpu_0, num_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    d3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), d3, num_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    low3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), low3, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    rem3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), rem3, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    sub_result_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), sub_result_1, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    sub_1_overflowed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), sub_1_overflowed, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    comparison_blocks_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), comparison_blocks_1,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    cmp_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), cmp_1, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    q3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), q3, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tmp_gpu_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), tmp_gpu_1, num_blocks + 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    d2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), d2, num_blocks + 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    low2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), low2, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    rem2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), rem2, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    divisor_gpu_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), divisor_gpu_1, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    remainder_gpu_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), remainder_gpu_1, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    sub_result_2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), sub_result_2, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    sub_2_overflowed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), sub_2_overflowed, 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    comparison_blocks_2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), comparison_blocks_2,
        num_blocks, params.big_lwe_dimension, tmp_size_tracker,
        allocate_gpu_memory);
    cmp_2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), cmp_2, 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    q2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(1), streams.gpu_index(1), q2, 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);

    tmp_gpu_2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), tmp_gpu_2, num_blocks + 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    d1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), d1, num_blocks + 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    low1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), low1, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    rem1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), rem1, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    divisor_gpu_2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), divisor_gpu_2, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    remainder_gpu_2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), remainder_gpu_2, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    sub_result_3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), sub_result_3, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    sub_3_overflowed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), sub_3_overflowed, 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    comparison_blocks_3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), comparison_blocks_3,
        num_blocks, params.big_lwe_dimension, tmp_size_tracker,
        allocate_gpu_memory);
    cmp_3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), cmp_3, 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    q1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(2), streams.gpu_index(2), q1, 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);

    tmp_gpu_3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(3), streams.gpu_index(3), tmp_gpu_3, num_blocks + 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    rem0 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(3), streams.gpu_index(3), rem0, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    remainder_gpu_3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(3), streams.gpu_index(3), remainder_gpu_3, num_blocks,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
    c0 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(3), streams.gpu_index(3), c0, 1,
        params.big_lwe_dimension, tmp_size_tracker, allocate_gpu_memory);
  }

  // initialize lookup tables for div_rem_2_2 operation
  void init_lookup_tables(CudaStreams streams, uint32_t num_blocks,
                          bool allocate_gpu_memory, uint64_t &size_tracker) {

    zero_out_if_not_1_lut_1 =
        new int_radix_lut<Torus>(streams.get_ith(0), params, 1, num_blocks,
                                 allocate_gpu_memory, size_tracker);

    zero_out_if_not_2_lut_1 =
        new int_radix_lut<Torus>(streams.get_ith(1), params, 1, num_blocks,
                                 allocate_gpu_memory, tmp_size_tracker);

    zero_out_if_not_2_lut_2 =
        new int_radix_lut<Torus>(streams.get_ith(2), params, 1, num_blocks,
                                 allocate_gpu_memory, tmp_size_tracker);

    zero_out_if_not_1_lut_2 =
        new int_radix_lut<Torus>(streams.get_ith(3), params, 1, num_blocks,
                                 allocate_gpu_memory, tmp_size_tracker);

    auto zero_out_if_not_1_lut_f = [](Torus x) -> Torus {
      Torus block = x / 2;
      bool condition = (x & 1) == 1;
      return block * (Torus)condition;
    };
    auto zero_out_if_not_2_lut_f = [](Torus x) -> Torus {
      Torus block = x / 3;
      bool condition = (x % 3) == 2;
      return block * (Torus)condition;
    };

    int_radix_lut<Torus> *luts[2] = {zero_out_if_not_1_lut_1,
                                     zero_out_if_not_1_lut_2};
    size_t lut_gpu_indexes[2] = {0, 3};
    for (int j = 0; j < 2; j++) {
      luts[j]->generate_and_broadcast_lut(streams.get_ith(lut_gpu_indexes[j]),
                                          {0}, {zero_out_if_not_1_lut_f},
                                          LUT_0_FOR_ALL_BLOCKS);
    }

    luts[0] = zero_out_if_not_2_lut_1;
    luts[1] = zero_out_if_not_2_lut_2;
    lut_gpu_indexes[0] = 1;
    lut_gpu_indexes[1] = 2;
    for (int j = 0; j < 2; j++) {
      luts[j]->generate_and_broadcast_lut(streams.get_ith(lut_gpu_indexes[j]),
                                          {0}, {zero_out_if_not_2_lut_f},
                                          LUT_0_FOR_ALL_BLOCKS);
    }

    quotient_lut_1 =
        new int_radix_lut<Torus>(streams.get_ith(2), params, 1, 1,
                                 allocate_gpu_memory, tmp_size_tracker);
    quotient_lut_2 =
        new int_radix_lut<Torus>(streams.get_ith(1), params, 1, 1,
                                 allocate_gpu_memory, tmp_size_tracker);
    quotient_lut_3 = new int_radix_lut<Torus>(
        streams.get_ith(0), params, 1, 1, allocate_gpu_memory, size_tracker);

    auto quotient_lut_1_f = [](Torus cond) -> Torus {
      return (Torus)(cond == 2);
    };
    auto quotient_lut_2_f = [](Torus cond) -> Torus {
      return (Torus)((cond == 2) * 2);
    };
    auto quotient_lut_3_f = [](Torus cond) -> Torus { return cond * 3; };

    quotient_lut_1->generate_and_broadcast_lut(
        streams.get_ith(2), {0}, {quotient_lut_1_f}, LUT_0_FOR_ALL_BLOCKS);
    quotient_lut_2->generate_and_broadcast_lut(
        streams.get_ith(1), {0}, {quotient_lut_2_f}, LUT_0_FOR_ALL_BLOCKS);
    quotient_lut_3->generate_and_broadcast_lut(
        streams.get_ith(0), {0}, {quotient_lut_3_f}, LUT_0_FOR_ALL_BLOCKS);

    message_extract_lut_1 = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    message_extract_lut_2 = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

    auto message_modulus = params.message_modulus;
    auto lut_f_message_extract = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };

    luts[0] = message_extract_lut_1;
    luts[1] = message_extract_lut_2;

    auto active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    for (int j = 0; j < 2; j++) {
      luts[j]->generate_and_broadcast_lut(
          active_streams, {0}, {lut_f_message_extract}, LUT_0_FOR_ALL_BLOCKS);
    }
  }

  unsigned_int_div_rem_2_2_memory(CudaStreams streams, int_radix_params params,
                                  uint32_t num_blocks, bool allocate_gpu_memory,
                                  uint64_t &size_tracker) {
    if (streams.count() < 4) {
      PANIC("GPU count should be greater than 4m when using div_rem_2_2");
    }

    if (params.message_modulus != 4 || params.carry_modulus != 4) {
      PANIC("Only message_modulus == 4 && carry_modulus == 4 parameters are "
            "supported");
    }

    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
        streams.get_ith(0), params, num_blocks + 1, outputFlag::FLAG_NONE,
        allocate_gpu_memory, size_tracker);

    shift_mem = new int_logical_scalar_shift_buffer<Torus>(
        streams.get_ith(1), SHIFT_OR_ROTATE_TYPE::LEFT_SHIFT, params,
        2 * num_blocks, allocate_gpu_memory, tmp_size_tracker);

    uint32_t compute_overflow = 1;
    overflow_sub_mem_1 = new int_borrow_prop_memory<Torus>(
        streams.get_ith(0), params, num_blocks, compute_overflow,
        allocate_gpu_memory, size_tracker);
    overflow_sub_mem_2 = new int_borrow_prop_memory<Torus>(
        streams.get_ith(1), params, num_blocks, compute_overflow,
        allocate_gpu_memory, tmp_size_tracker);
    overflow_sub_mem_3 = new int_borrow_prop_memory<Torus>(
        streams.get_ith(2), params, num_blocks, compute_overflow,
        allocate_gpu_memory, tmp_size_tracker);
    uint32_t group_size = overflow_sub_mem_1->group_size;
    bool use_seq = overflow_sub_mem_1->prop_simu_group_carries_mem
                       ->use_sequential_algorithm_to_resolve_group_carries;

    cuda_set_device(0);
    cudaEventCreateWithFlags(&create_indexes_done, cudaEventDisableTiming);
    create_indexes_for_overflow_sub(streams.get_ith(0), num_blocks, group_size,
                                    use_seq, allocate_gpu_memory, size_tracker);
    cudaEventRecord(create_indexes_done, streams.stream(0));
    cuda_set_device(1);
    cudaStreamWaitEvent(streams.stream(1), create_indexes_done, 0);
    cuda_set_device(2);
    cudaStreamWaitEvent(streams.stream(2), create_indexes_done, 0);

    scatter_indexes_for_overflowing_sub(
        streams.stream(1), streams.gpu_index(1),
        &first_indexes_for_overflow_sub_gpu_1,
        &second_indexes_for_overflow_sub_gpu_1, &scalars_for_overflow_sub_gpu_1,
        num_blocks, allocate_gpu_memory, tmp_size_tracker);
    scatter_indexes_for_overflowing_sub(
        streams.stream(2), streams.gpu_index(2),
        &first_indexes_for_overflow_sub_gpu_2,
        &second_indexes_for_overflow_sub_gpu_2, &scalars_for_overflow_sub_gpu_2,
        num_blocks, allocate_gpu_memory, tmp_size_tracker);

    comparison_buffer_1 = new int_comparison_buffer<Torus>(
        streams.get_ith(0), COMPARISON_TYPE::EQ, params, num_blocks, false,
        allocate_gpu_memory, size_tracker);
    comparison_buffer_2 = new int_comparison_buffer<Torus>(
        streams.get_ith(1), COMPARISON_TYPE::EQ, params, num_blocks, false,
        allocate_gpu_memory, tmp_size_tracker);
    comparison_buffer_3 = new int_comparison_buffer<Torus>(
        streams.get_ith(2), COMPARISON_TYPE::EQ, params, num_blocks, false,
        allocate_gpu_memory, tmp_size_tracker);
    bitor_mem_1 = new int_bitop_buffer<Torus>(
        streams.get_ith(0), BITOP_TYPE::BITOR, params, num_blocks,
        allocate_gpu_memory, size_tracker);
    bitor_mem_2 = new int_bitop_buffer<Torus>(
        streams.get_ith(1), BITOP_TYPE::BITOR, params, num_blocks,
        allocate_gpu_memory, tmp_size_tracker);
    bitor_mem_3 = new int_bitop_buffer<Torus>(
        streams.get_ith(2), BITOP_TYPE::BITOR, params, num_blocks,
        allocate_gpu_memory, tmp_size_tracker);

    init_lookup_tables(streams, num_blocks, allocate_gpu_memory, size_tracker);
    init_temporary_buffers(streams, num_blocks, allocate_gpu_memory,
                           size_tracker);

    sub_streams_1.create_on_same_gpus(streams);
  }

  void scatter_indexes_for_overflowing_sub(
      cudaStream_t const stream, size_t gpu_index, Torus ***first_indexes_ptr,
      Torus ***second_indexes_ptr, Torus ***scalars_ptr, uint32_t num_blocks,
      bool allocate_gpu_memory, uint64_t &size_tracker) {

    auto first_indexes = (Torus **)malloc(num_blocks * sizeof(Torus *));
    auto second_indexes = (Torus **)malloc(num_blocks * sizeof(Torus *));
    auto scalars = (Torus **)malloc(num_blocks * sizeof(Torus *));

    for (int nb = 1; nb <= num_blocks; nb++) {
      first_indexes[nb - 1] = (Torus *)cuda_malloc_with_size_tracking_async(
          nb * sizeof(Torus), stream, gpu_index, size_tracker,
          allocate_gpu_memory);
      second_indexes[nb - 1] = (Torus *)cuda_malloc_with_size_tracking_async(
          nb * sizeof(Torus), stream, gpu_index, size_tracker,
          allocate_gpu_memory);
      scalars[nb - 1] = (Torus *)cuda_malloc_with_size_tracking_async(
          nb * sizeof(Torus), stream, gpu_index, size_tracker,
          allocate_gpu_memory);

      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          first_indexes[nb - 1], first_indexes_for_overflow_sub_gpu_0[nb - 1],
          nb * sizeof(Torus), stream, gpu_index, allocate_gpu_memory);
      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          second_indexes[nb - 1], second_indexes_for_overflow_sub_gpu_0[nb - 1],
          nb * sizeof(Torus), stream, gpu_index, allocate_gpu_memory);
      cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
          scalars[nb - 1], scalars_for_overflow_sub_gpu_0[nb - 1],
          nb * sizeof(Torus), stream, gpu_index, allocate_gpu_memory);
      *first_indexes_ptr = first_indexes;
      *second_indexes_ptr = second_indexes;
      *scalars_ptr = scalars;
    }
  }

  void create_indexes_for_overflow_sub(CudaStreams streams, uint32_t num_blocks,
                                       uint32_t group_size, bool use_seq,
                                       bool allocate_gpu_memory,
                                       uint64_t &size_tracker) {
    max_indexes_to_erase = num_blocks;

    first_indexes_for_overflow_sub_gpu_0 =
        (Torus **)malloc(num_blocks * sizeof(Torus *));
    second_indexes_for_overflow_sub_gpu_0 =
        (Torus **)malloc(num_blocks * sizeof(Torus *));
    scalars_for_overflow_sub_gpu_0 =
        (Torus **)malloc(num_blocks * sizeof(Torus *));

    HostBuffer<Torus> h_lut_indexes;
    h_lut_indexes.allocate(num_blocks);
    Torus *h_scalar = (Torus *)malloc(num_blocks * sizeof(Torus));

    // Extra indexes for the luts in first step
    for (int nb = 1; nb <= num_blocks; nb++) {
      first_indexes_for_overflow_sub_gpu_0[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
              size_tracker, allocate_gpu_memory);

      auto index_generator = [nb, group_size](HostBuffer<Torus> &h_lut_indexes,
                                              uint32_t) {
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
      };

      generate_lut_indexes<Torus>(streams, index_generator,
                                  first_indexes_for_overflow_sub_gpu_0[nb - 1],
                                  nb, 2 * group_size + 1, h_lut_indexes,
                                  allocate_gpu_memory);
    }
    // Extra indexes for the luts in second step
    uint32_t num_extra_luts = use_seq ? (group_size - 1) : 1;
    uint32_t num_luts_second_step = 2 * group_size + num_extra_luts;
    for (int nb = 1; nb <= num_blocks; nb++) {
      second_indexes_for_overflow_sub_gpu_0[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
              size_tracker, allocate_gpu_memory);
      scalars_for_overflow_sub_gpu_0[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
              size_tracker, allocate_gpu_memory);

      auto index_generator = [nb, group_size, use_seq](
                                 HostBuffer<Torus> &h_lut_indexes, uint32_t) {
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
        }
      };

      generate_lut_indexes<Torus>(streams, index_generator,
                                  second_indexes_for_overflow_sub_gpu_0[nb - 1],
                                  nb, num_luts_second_step, h_lut_indexes,
                                  allocate_gpu_memory);

      for (int index = 0; index < nb; index++) {
        uint32_t grouping_index = index / group_size;
        bool is_in_first_grouping = (grouping_index == 0);
        uint32_t index_in_grouping = index % group_size;
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
          scalars_for_overflow_sub_gpu_0[nb - 1], h_scalar, nb * sizeof(Torus),
          streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
    }
    {
      auto gpu_phase = GpuReleasePhase(streams);
      auto cpu_phase = std::move(gpu_phase).synchronize();
      h_lut_indexes.release(cpu_phase);
    }
    free(h_scalar);
  };

  void release(CudaStreams streams) {

    if (streams.count() < 4) {
      PANIC("GPU count should be greater than 4 when using div_rem_2_2");
    }
    if (params.message_modulus != 4 || params.carry_modulus != 4) {
      PANIC("Only message_modulus == 4 && carry_modulus == 4 parameters are "
            "supported");
    }

    // release and delete integer ops memory objects
    sub_and_propagate_mem->release(streams.get_ith(0));
    shift_mem->release(streams.get_ith(1));
    overflow_sub_mem_1->release(streams.get_ith(0));
    overflow_sub_mem_2->release(streams.get_ith(1));
    overflow_sub_mem_3->release(streams.get_ith(2));
    comparison_buffer_1->release(streams.get_ith(0));
    comparison_buffer_2->release(streams.get_ith(1));
    comparison_buffer_3->release(streams.get_ith(2));
    bitor_mem_1->release(streams.get_ith(0));
    bitor_mem_2->release(streams.get_ith(1));
    bitor_mem_3->release(streams.get_ith(2));

    delete sub_and_propagate_mem;
    sub_and_propagate_mem = nullptr;
    delete shift_mem;
    shift_mem = nullptr;
    delete overflow_sub_mem_1;
    overflow_sub_mem_1 = nullptr;
    delete overflow_sub_mem_2;
    overflow_sub_mem_2 = nullptr;
    delete overflow_sub_mem_3;
    overflow_sub_mem_3 = nullptr;
    delete comparison_buffer_1;
    comparison_buffer_1 = nullptr;
    delete comparison_buffer_2;
    comparison_buffer_2 = nullptr;
    delete comparison_buffer_3;
    comparison_buffer_3 = nullptr;
    delete bitor_mem_1;
    bitor_mem_1 = nullptr;
    delete bitor_mem_2;
    bitor_mem_2 = nullptr;
    delete bitor_mem_3;
    bitor_mem_3 = nullptr;

    // release and delete lut objects
    message_extract_lut_1->release(streams);
    message_extract_lut_2->release(streams);
    zero_out_if_not_1_lut_1->release(streams.get_ith(0));
    zero_out_if_not_1_lut_2->release(streams.get_ith(3));
    zero_out_if_not_2_lut_1->release(streams.get_ith(1));
    zero_out_if_not_2_lut_2->release(streams.get_ith(2));
    quotient_lut_1->release(streams.get_ith(2));
    quotient_lut_2->release(streams.get_ith(1));
    quotient_lut_3->release(streams.get_ith(0));

    delete message_extract_lut_1;
    message_extract_lut_1 = nullptr;
    delete message_extract_lut_2;
    message_extract_lut_2 = nullptr;
    delete zero_out_if_not_1_lut_1;
    zero_out_if_not_1_lut_1 = nullptr;
    delete zero_out_if_not_1_lut_2;
    zero_out_if_not_1_lut_2 = nullptr;
    delete zero_out_if_not_2_lut_1;
    zero_out_if_not_2_lut_1 = nullptr;
    delete zero_out_if_not_2_lut_2;
    zero_out_if_not_2_lut_2 = nullptr;
    delete quotient_lut_1;
    quotient_lut_1 = nullptr;
    delete quotient_lut_2;
    quotient_lut_2 = nullptr;
    delete quotient_lut_3;
    quotient_lut_3 = nullptr;

    // release and delete temporary buffers
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2), d1,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1), d2,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), d3,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   low1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   low2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   low3, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(3), streams.gpu_index(3),
                                   rem0, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   rem1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   rem2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   rem3, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   sub_result_3, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   sub_result_2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   sub_result_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   sub_3_overflowed, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   sub_2_overflowed, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   sub_1_overflowed, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(3), streams.gpu_index(3),
                                   tmp_gpu_3, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   tmp_gpu_2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   tmp_gpu_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_gpu_0, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   divisor_gpu_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   divisor_gpu_2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   remainder_gpu_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   remainder_gpu_2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(3), streams.gpu_index(3),
                                   remainder_gpu_3, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   comparison_blocks_3, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   comparison_blocks_2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   comparison_blocks_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2),
                                   cmp_3, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1),
                                   cmp_2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   cmp_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(3), streams.gpu_index(3), c0,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(2), streams.gpu_index(2), q1,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(1), streams.gpu_index(1), q2,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), q3,
                                   gpu_memory_allocated);

    delete d1;
    d1 = nullptr;
    delete d2;
    d2 = nullptr;
    delete d3;
    d3 = nullptr;
    delete low1;
    low1 = nullptr;
    delete low2;
    low2 = nullptr;
    delete low3;
    low3 = nullptr;
    delete rem0;
    rem0 = nullptr;
    delete rem1;
    rem1 = nullptr;
    delete rem2;
    rem2 = nullptr;
    delete rem3;
    rem3 = nullptr;
    delete sub_result_1;
    sub_result_1 = nullptr;
    delete sub_result_2;
    sub_result_2 = nullptr;
    delete sub_result_3;
    sub_result_3 = nullptr;
    delete sub_1_overflowed;
    sub_1_overflowed = nullptr;
    delete sub_2_overflowed;
    sub_2_overflowed = nullptr;
    delete sub_3_overflowed;
    sub_3_overflowed = nullptr;
    delete tmp_gpu_0;
    tmp_gpu_0 = nullptr;
    delete tmp_gpu_1;
    tmp_gpu_1 = nullptr;
    delete tmp_gpu_2;
    tmp_gpu_2 = nullptr;
    delete tmp_gpu_3;
    tmp_gpu_3 = nullptr;
    delete divisor_gpu_1;
    divisor_gpu_1 = nullptr;
    delete divisor_gpu_2;
    divisor_gpu_2 = nullptr;
    delete remainder_gpu_1;
    remainder_gpu_1 = nullptr;
    delete remainder_gpu_2;
    remainder_gpu_2 = nullptr;
    delete remainder_gpu_3;
    remainder_gpu_3 = nullptr;
    delete comparison_blocks_1;
    comparison_blocks_1 = nullptr;
    delete comparison_blocks_2;
    comparison_blocks_2 = nullptr;
    delete comparison_blocks_3;
    comparison_blocks_3 = nullptr;
    delete cmp_1;
    cmp_1 = nullptr;
    delete cmp_2;
    cmp_2 = nullptr;
    delete cmp_3;
    cmp_3 = nullptr;
    delete c0;
    c0 = nullptr;
    delete q1;
    q1 = nullptr;
    delete q2;
    q2 = nullptr;
    delete q3;
    q3 = nullptr;

    for (int i = 0; i < max_indexes_to_erase; i++) {
      cuda_drop_with_size_tracking_async(
          first_indexes_for_overflow_sub_gpu_0[i], streams.stream(0),
          streams.gpu_index(0), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          second_indexes_for_overflow_sub_gpu_0[i], streams.stream(0),
          streams.gpu_index(0), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          scalars_for_overflow_sub_gpu_0[i], streams.stream(0),
          streams.gpu_index(0), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          first_indexes_for_overflow_sub_gpu_1[i], streams.stream(1),
          streams.gpu_index(1), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          second_indexes_for_overflow_sub_gpu_1[i], streams.stream(1),
          streams.gpu_index(1), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          scalars_for_overflow_sub_gpu_1[i], streams.stream(1),
          streams.gpu_index(1), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          first_indexes_for_overflow_sub_gpu_2[i], streams.stream(2),
          streams.gpu_index(2), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          second_indexes_for_overflow_sub_gpu_2[i], streams.stream(2),
          streams.gpu_index(2), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          scalars_for_overflow_sub_gpu_2[i], streams.stream(2),
          streams.gpu_index(2), gpu_memory_allocated);
    }

    for (uint j = 0; j < 3; j++) {
      cuda_synchronize_stream(streams.stream(j), streams.gpu_index(j));
    }

    free(first_indexes_for_overflow_sub_gpu_0);
    free(second_indexes_for_overflow_sub_gpu_0);
    free(scalars_for_overflow_sub_gpu_0);
    free(first_indexes_for_overflow_sub_gpu_1);
    free(second_indexes_for_overflow_sub_gpu_1);
    free(scalars_for_overflow_sub_gpu_1);
    free(first_indexes_for_overflow_sub_gpu_2);
    free(second_indexes_for_overflow_sub_gpu_2);
    free(scalars_for_overflow_sub_gpu_2);

    cudaEventDestroy(create_indexes_done);

    // release sub streams
    sub_streams_1.release();
  }
};

template <typename Torus> struct unsigned_int_div_rem_memory {
  int_radix_params params;

  // memory objects for other operations
  int_logical_scalar_shift_buffer<Torus> *shift_mem_1;
  int_logical_scalar_shift_buffer<Torus> *shift_mem_2;
  int_borrow_prop_memory<Torus> *overflow_sub_mem;
  int_comparison_buffer<Torus> *comparison_buffer;
  unsigned_int_div_rem_2_2_memory<Torus> *div_rem_2_2_mem;

  // lookup tables
  int_radix_lut<Torus> **masking_luts_1;
  int_radix_lut<Torus> **masking_luts_2;
  int_radix_lut<Torus> *message_extract_lut_1;
  int_radix_lut<Torus> *message_extract_lut_2;
  int_radix_lut<Torus> **zero_out_if_overflow_did_not_happen;
  int_radix_lut<Torus> **zero_out_if_overflow_happened;
  int_radix_lut<Torus> **merge_overflow_flags_luts;

  // sub streams
  CudaStreams sub_streams_1;
  CudaStreams sub_streams_2;
  CudaStreams sub_streams_3;
  CudaStreams sub_streams_4;

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
  void init_temporary_buffers(CudaStreams streams, uint32_t num_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {

    // non boolean temporary arrays, with `num_blocks` blocks
    remainder1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), remainder1, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    remainder2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), remainder2, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    numerator_block_stack = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), numerator_block_stack,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    interesting_remainder2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), interesting_remainder2,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    interesting_divisor = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), interesting_divisor,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    divisor_ms_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), divisor_ms_blocks, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    new_remainder = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), new_remainder, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    cleaned_merged_interesting_remainder = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        cleaned_merged_interesting_remainder, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_1, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    // temporary arrays used as stacks
    tmp_radix = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_radix, num_blocks + 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    interesting_remainder1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), interesting_remainder1,
        num_blocks + 1, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    numerator_block_1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), numerator_block_1, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    // temporary arrays for boolean blocks
    subtraction_overflowed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), subtraction_overflowed, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    did_not_overflow = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), did_not_overflow, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    overflow_sum = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), overflow_sum, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    overflow_sum_radix = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), overflow_sum_radix, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    at_least_one_upper_block_is_non_zero = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        at_least_one_upper_block_is_non_zero, 1, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);
  }

  // initialize lookup tables for div_rem operation
  void init_lookup_tables(CudaStreams streams, uint32_t num_blocks,
                          bool allocate_gpu_memory, uint64_t &size_tracker) {
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
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);
      masking_luts_2[i] = new int_radix_lut<Torus>(
          streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

      auto active_streams_1 = streams.active_gpu_subset(1, params.pbs_type);
      masking_luts_1[i]->generate_and_broadcast_lut(
          active_streams_1, {0}, {lut_f_masking}, LUT_0_FOR_ALL_BLOCKS);

      auto active_streams_2 =
          streams.active_gpu_subset(num_blocks, params.pbs_type);
      masking_luts_2[i]->generate_and_broadcast_lut(
          active_streams_2, {0}, {lut_f_masking}, LUT_0_FOR_ALL_BLOCKS);
    }

    // create and generate message_extract_lut_1 and message_extract_lut_2
    // both of them are equal but because they are used in two different
    // executions in parallel we need two different pbs_buffers.
    message_extract_lut_1 = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    message_extract_lut_2 = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

    auto message_modulus = params.message_modulus;
    auto lut_f_message_extract = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };

    int_radix_lut<Torus> *luts[2] = {message_extract_lut_1,
                                     message_extract_lut_2};

    auto active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);
    for (int j = 0; j < 2; j++) {
      luts[j]->generate_and_broadcast_lut(
          active_streams, {0}, {lut_f_message_extract}, LUT_0_FOR_ALL_BLOCKS);
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
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    zero_out_if_overflow_did_not_happen[1] = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

    auto cur_lut_f = [&](Torus block, Torus overflow_sum) -> Torus {
      if (overflow_did_not_happen(overflow_sum)) {
        return 0;
      } else {
        return block;
      }
    };

    zero_out_if_overflow_did_not_happen[0]
        ->generate_and_broadcast_bivariate_lut(active_streams, {0}, {cur_lut_f},
                                               LUT_0_FOR_ALL_BLOCKS, {},
                                               params.message_modulus - 2);
    zero_out_if_overflow_did_not_happen[1]
        ->generate_and_broadcast_bivariate_lut(active_streams, {0}, {cur_lut_f},
                                               LUT_0_FOR_ALL_BLOCKS, {},
                                               params.message_modulus - 1);

    // create and generate zero_out_if_overflow_happened
    zero_out_if_overflow_happened = new int_radix_lut<Torus> *[2];
    zero_out_if_overflow_happened[0] = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    zero_out_if_overflow_happened[1] = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

    auto overflow_happened_f = [&](Torus block, Torus overflow_sum) -> Torus {
      if (overflow_happened(overflow_sum)) {
        return 0;
      } else {
        return block;
      }
    };

    zero_out_if_overflow_happened[0]->generate_and_broadcast_bivariate_lut(
        active_streams, {0}, {overflow_happened_f}, LUT_0_FOR_ALL_BLOCKS, {},
        params.message_modulus - 2);
    zero_out_if_overflow_happened[1]->generate_and_broadcast_bivariate_lut(
        active_streams, {0}, {overflow_happened_f}, LUT_0_FOR_ALL_BLOCKS, {},
        params.message_modulus - 1);

    // merge_overflow_flags_luts
    merge_overflow_flags_luts = new int_radix_lut<Torus> *[num_bits_in_message];
    auto active_gpu_count_for_bits =
        streams.active_gpu_subset(1, params.pbs_type);
    for (int i = 0; i < num_bits_in_message; i++) {
      auto lut_f_bit = [i](Torus x, Torus y) -> Torus {
        return (x == 0 && y == 0) << i;
      };

      merge_overflow_flags_luts[i] = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);

      merge_overflow_flags_luts[i]->generate_and_broadcast_bivariate_lut(
          active_gpu_count_for_bits, {0}, {lut_f_bit}, LUT_0_FOR_ALL_BLOCKS);
    }
  }

  unsigned_int_div_rem_memory(CudaStreams streams, int_radix_params params,
                              uint32_t num_blocks, bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    auto active_streams =
        streams.active_gpu_subset(2 * num_blocks, params.pbs_type);
    this->params = params;

    if (params.message_modulus == 4 && params.carry_modulus == 4 &&
        streams.count() >= 4) {
      div_rem_2_2_mem = new unsigned_int_div_rem_2_2_memory<Torus>(
          streams, params, num_blocks, allocate_gpu_memory, size_tracker);
      return;
    }

    shift_mem_1 = new int_logical_scalar_shift_buffer<Torus>(
        streams, SHIFT_OR_ROTATE_TYPE::LEFT_SHIFT, params, 2 * num_blocks,
        allocate_gpu_memory, size_tracker);

    shift_mem_2 = new int_logical_scalar_shift_buffer<Torus>(
        streams, SHIFT_OR_ROTATE_TYPE::LEFT_SHIFT, params, 2 * num_blocks,
        allocate_gpu_memory, size_tracker);

    uint32_t compute_overflow = 1;
    overflow_sub_mem = new int_borrow_prop_memory<Torus>(
        streams, params, num_blocks, compute_overflow, allocate_gpu_memory,
        size_tracker);
    uint32_t group_size = overflow_sub_mem->group_size;
    bool use_seq = overflow_sub_mem->prop_simu_group_carries_mem
                       ->use_sequential_algorithm_to_resolve_group_carries;
    create_indexes_for_overflow_sub(streams, num_blocks, group_size, use_seq,
                                    allocate_gpu_memory, size_tracker);

    comparison_buffer = new int_comparison_buffer<Torus>(
        streams, COMPARISON_TYPE::NE, params, num_blocks, false,
        allocate_gpu_memory, size_tracker);

    init_lookup_tables(streams, num_blocks, allocate_gpu_memory, size_tracker);
    init_temporary_buffers(streams, num_blocks, allocate_gpu_memory,
                           size_tracker);

    sub_streams_1.create_on_same_gpus(active_streams);
    sub_streams_2.create_on_same_gpus(active_streams);
    sub_streams_3.create_on_same_gpus(active_streams);
    sub_streams_4.create_on_same_gpus(active_streams);
  }

  void create_indexes_for_overflow_sub(CudaStreams streams, uint32_t num_blocks,
                                       uint32_t group_size, bool use_seq,
                                       bool allocate_gpu_memory,
                                       uint64_t &size_tracker) {
    max_indexes_to_erase = num_blocks;

    first_indexes_for_overflow_sub =
        (Torus **)malloc(num_blocks * sizeof(Torus *));
    second_indexes_for_overflow_sub =
        (Torus **)malloc(num_blocks * sizeof(Torus *));
    scalars_for_overflow_sub = (Torus **)malloc(num_blocks * sizeof(Torus *));

    HostBuffer<Torus> h_lut_indexes;
    h_lut_indexes.allocate(num_blocks);
    Torus *h_scalar = (Torus *)malloc(num_blocks * sizeof(Torus));

    // Extra indexes for the luts in first step
    for (int nb = 1; nb <= num_blocks; nb++) {
      first_indexes_for_overflow_sub[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
              size_tracker, allocate_gpu_memory);

      auto index_generator = [nb, group_size](HostBuffer<Torus> &h_lut_indexes,
                                              uint32_t) {
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
      };

      generate_lut_indexes<Torus>(
          streams, index_generator, first_indexes_for_overflow_sub[nb - 1], nb,
          2 * group_size + 1, h_lut_indexes, allocate_gpu_memory);
    }
    // Extra indexes for the luts in second step
    uint32_t num_extra_luts = use_seq ? (group_size - 1) : 1;
    uint32_t num_luts_second_step = 2 * group_size + num_extra_luts;
    for (int nb = 1; nb <= num_blocks; nb++) {
      second_indexes_for_overflow_sub[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
              size_tracker, allocate_gpu_memory);
      scalars_for_overflow_sub[nb - 1] =
          (Torus *)cuda_malloc_with_size_tracking_async(
              nb * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
              size_tracker, allocate_gpu_memory);

      auto index_generator = [nb, group_size, use_seq](
                                 HostBuffer<Torus> &h_lut_indexes, uint32_t) {
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
        }
      };

      generate_lut_indexes<Torus>(
          streams, index_generator, second_indexes_for_overflow_sub[nb - 1], nb,
          num_luts_second_step, h_lut_indexes, allocate_gpu_memory);

      for (int index = 0; index < nb; index++) {
        uint32_t grouping_index = index / group_size;
        bool is_in_first_grouping = (grouping_index == 0);
        uint32_t index_in_grouping = index % group_size;
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
          scalars_for_overflow_sub[nb - 1], h_scalar, nb * sizeof(Torus),
          streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
    }
    {
      auto gpu_phase = GpuReleasePhase(streams);
      auto cpu_phase = std::move(gpu_phase).synchronize();
      h_lut_indexes.release(cpu_phase);
    }
    free(h_scalar);
  };

  void release(CudaStreams streams) {

    if (params.message_modulus == 4 && params.carry_modulus == 4 &&
        streams.count() >= 4) {
      div_rem_2_2_mem->release(streams);
      delete div_rem_2_2_mem;
      return;
    }

    uint32_t num_bits_in_message = 31 - __builtin_clz(params.message_modulus);

    // release and delete other operation memory objects
    shift_mem_1->release(streams);
    shift_mem_2->release(streams);
    overflow_sub_mem->release(streams);
    comparison_buffer->release(streams);
    delete shift_mem_1;
    delete shift_mem_2;
    delete overflow_sub_mem;
    delete comparison_buffer;

    // drop temporary buffers
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   remainder1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   remainder2, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   numerator_block_stack, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   numerator_block_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_radix, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   interesting_remainder1,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   interesting_remainder2,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   interesting_divisor, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   divisor_ms_blocks, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   new_remainder, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   subtraction_overflowed,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   did_not_overflow, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   overflow_sum, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   overflow_sum_radix, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_1, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   at_least_one_upper_block_is_non_zero,
                                   gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   cleaned_merged_interesting_remainder,
                                   gpu_memory_allocated);
    // release and delete lookup tables

    // masking_luts_1 and masking_luts_2
    for (int i = 0; i < params.message_modulus - 1; i++) {
      masking_luts_1[i]->release(streams);
      masking_luts_2[i]->release(streams);

      delete masking_luts_1[i];
      delete masking_luts_2[i];
    }
    delete[] masking_luts_1;
    delete[] masking_luts_2;

    // message_extract_lut_1 and message_extract_lut_2
    message_extract_lut_1->release(streams);
    message_extract_lut_2->release(streams);

    delete message_extract_lut_1;
    delete message_extract_lut_2;

    // zero_out_if_overflow_did_not_happen
    zero_out_if_overflow_did_not_happen[0]->release(streams);
    zero_out_if_overflow_did_not_happen[1]->release(streams);

    delete zero_out_if_overflow_did_not_happen[0];
    delete zero_out_if_overflow_did_not_happen[1];

    delete[] zero_out_if_overflow_did_not_happen;

    // zero_out_if_overflow_happened
    zero_out_if_overflow_happened[0]->release(streams);
    zero_out_if_overflow_happened[1]->release(streams);

    delete zero_out_if_overflow_happened[0];
    delete zero_out_if_overflow_happened[1];

    delete[] zero_out_if_overflow_happened;

    // merge_overflow_flags_luts
    for (int i = 0; i < num_bits_in_message; i++) {
      merge_overflow_flags_luts[i]->release(streams);

      delete merge_overflow_flags_luts[i];
    }
    delete[] merge_overflow_flags_luts;

    // release sub streams
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    sub_streams_1.release();
    sub_streams_2.release();
    sub_streams_3.release();
    sub_streams_4.release();

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
      cuda_drop_with_size_tracking_async(
          first_indexes_for_overflow_sub[i], streams.stream(0),
          streams.gpu_index(0), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          second_indexes_for_overflow_sub[i], streams.stream(0),
          streams.gpu_index(0), gpu_memory_allocated);
      cuda_drop_with_size_tracking_async(
          scalars_for_overflow_sub[i], streams.stream(0), streams.gpu_index(0),
          gpu_memory_allocated);
    }
    free(first_indexes_for_overflow_sub);
    free(second_indexes_for_overflow_sub);
    free(scalars_for_overflow_sub);
  }
};
template <typename Torus> struct int_div_rem_memory {
  int_radix_params params;
  CudaStreams active_streams;
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
  CudaStreams sub_streams_1;
  CudaStreams sub_streams_2;

  // temporary device buffers
  CudaRadixCiphertextFFI *positive_numerator;
  CudaRadixCiphertextFFI *positive_divisor;
  CudaRadixCiphertextFFI *sign_bits_are_different;
  CudaRadixCiphertextFFI *negated_quotient;
  CudaRadixCiphertextFFI *negated_remainder;
  bool gpu_memory_allocated;

  int_div_rem_memory(CudaStreams streams, int_radix_params params,
                     bool is_signed, uint32_t num_blocks,
                     bool allocate_gpu_memory, uint64_t &size_tracker) {

    gpu_memory_allocated = allocate_gpu_memory;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);
    this->params = params;
    this->is_signed = is_signed;

    unsigned_mem = new unsigned_int_div_rem_memory<Torus>(
        streams, params, num_blocks, allocate_gpu_memory, size_tracker);

    if (is_signed) {
      Torus sign_bit_pos = 31 - __builtin_clz(params.message_modulus) - 1;

      // init memory objects for other integer operations
      abs_mem_1 = new int_abs_buffer<Torus>(streams, params, num_blocks,
                                            allocate_gpu_memory, size_tracker);
      abs_mem_2 = new int_abs_buffer<Torus>(streams, params, num_blocks,
                                            allocate_gpu_memory, size_tracker);
      uint32_t requested_flag = outputFlag::FLAG_NONE;
      scp_mem_1 = new int_sc_prop_memory<Torus>(
          streams, params, num_blocks, requested_flag, allocate_gpu_memory,
          size_tracker);
      scp_mem_2 = new int_sc_prop_memory<Torus>(
          streams, params, num_blocks, requested_flag, allocate_gpu_memory,
          size_tracker);

      std::function<uint64_t(uint64_t)> quotient_predicate_lut_f =
          [](uint64_t x) -> uint64_t { return x == 1; };
      std::function<uint64_t(uint64_t)> remainder_predicate_lut_f =
          [sign_bit_pos](uint64_t x) -> uint64_t {
        return (x >> sign_bit_pos) == 1;
      };

      cmux_quotient_mem = new int_cmux_buffer<Torus>(
          streams, quotient_predicate_lut_f, params, num_blocks,
          allocate_gpu_memory, size_tracker);
      cmux_remainder_mem = new int_cmux_buffer<Torus>(
          streams, remainder_predicate_lut_f, params, num_blocks,
          allocate_gpu_memory, size_tracker);
      // init temporary memory buffers
      positive_numerator = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), positive_numerator,
          num_blocks, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);
      positive_divisor = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), positive_divisor, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      negated_quotient = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), negated_quotient, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      negated_remainder = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), negated_remainder,
          num_blocks, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);

      // init boolean temporary buffers
      sign_bits_are_different = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), sign_bits_are_different, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      // init sub streams
      sub_streams_1.create_on_same_gpus(streams);
      sub_streams_2.create_on_same_gpus(streams);

      // init lookup tables
      //  to extract and compare signed bits
      auto f_compare_extracted_signed_bits = [sign_bit_pos](Torus x,
                                                            Torus y) -> Torus {
        Torus x_sign_bit = (x >> sign_bit_pos) & 1;
        Torus y_sign_bit = (y >> sign_bit_pos) & 1;
        return (Torus)(x_sign_bit != y_sign_bit);
      };

      compare_signed_bits_lut = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);

      auto active_gpu_count_cmp =
          streams.active_gpu_subset(1, params.pbs_type); // only 1 block needed

      compare_signed_bits_lut->generate_and_broadcast_bivariate_lut(
          active_gpu_count_cmp, {0}, {f_compare_extracted_signed_bits},
          LUT_0_FOR_ALL_BLOCKS);
    }
  }

  void release(CudaStreams streams) {
    unsigned_mem->release(streams);
    delete unsigned_mem;

    if (is_signed) {
      // release objects for other integer operations
      abs_mem_1->release(streams);
      abs_mem_2->release(streams);
      scp_mem_1->release(streams);
      scp_mem_2->release(streams);
      cmux_quotient_mem->release(streams);
      cmux_remainder_mem->release(streams);

      delete abs_mem_1;
      delete abs_mem_2;
      delete scp_mem_1;
      delete scp_mem_2;
      delete cmux_quotient_mem;
      delete cmux_remainder_mem;

      // drop temporary buffers
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     positive_numerator, gpu_memory_allocated);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     positive_divisor, gpu_memory_allocated);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     sign_bits_are_different,
                                     gpu_memory_allocated);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     negated_quotient, gpu_memory_allocated);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     negated_remainder, gpu_memory_allocated);
      // release lookup tables
      compare_signed_bits_lut->release(streams);
      delete compare_signed_bits_lut;

      // release sub streams
      cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
      sub_streams_1.release();
      sub_streams_2.release();

      // delete temporary buffers
      delete positive_numerator;
      delete positive_divisor;
      delete sign_bits_are_different;
      delete negated_quotient;
      delete negated_remainder;
    }
  }
};
