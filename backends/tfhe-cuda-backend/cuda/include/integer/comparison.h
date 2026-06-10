#pragma once
#include "checked_arithmetic.h"
#include "cmux.h"
#include "integer_utilities.h"

template <typename Torus> struct int_are_all_block_true_buffer {
  COMPARISON_TYPE op;
  int_radix_params params;

  CudaRadixCiphertextFFI *tmp_out;
  CudaRadixCiphertextFFI *tmp_block_accumulated;

  // This map store LUTs that checks the equality between some input and values
  // of interest in are_all_block_true(), as with max_value (the maximum message
  // value).
  int_radix_lut<Torus> *is_max_value;
  Torus *preallocated_h_lut;
  bool gpu_memory_allocated;

  int_are_all_block_true_buffer(CudaStreams streams, COMPARISON_TYPE op,
                                int_radix_params params,
                                uint32_t num_radix_blocks,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->op = op;

    Torus total_modulus = params.message_modulus * params.carry_modulus;
    uint32_t max_value = (total_modulus - 1) / (params.message_modulus - 1);

    int max_chunks = CEIL_DIV(num_radix_blocks, max_value);
    tmp_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_out, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_block_accumulated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_block_accumulated,
        max_chunks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    preallocated_h_lut = (Torus *)malloc(safe_mul_sizeof<Torus>(
        params.glwe_dimension + 1, params.polynomial_size));

    is_max_value = new int_radix_lut<Torus>(streams, params, 2, max_chunks,
                                            allocate_gpu_memory, size_tracker);

    auto active_streams =
        streams.active_gpu_subset(max_chunks, params.pbs_type);

    auto is_max_value_f = [max_value](Torus x) -> Torus {
      return x == max_value;
    };

    is_max_value->generate_and_broadcast_lut(
        active_streams, {0}, {is_max_value_f}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_out, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_block_accumulated, gpu_memory_allocated);
    is_max_value->release(streams);
    delete is_max_value;
    delete tmp_out;
    delete tmp_block_accumulated;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(preallocated_h_lut);
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

  int_comparison_eq_buffer(CudaStreams streams, COMPARISON_TYPE op,
                           int_radix_params params, uint32_t num_radix_blocks,
                           bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->op = op;
    Torus total_modulus = params.message_modulus * params.carry_modulus;

    are_all_block_true_buffer = new int_are_all_block_true_buffer<Torus>(
        streams, op, params, num_radix_blocks, allocate_gpu_memory,
        size_tracker);

    // f(x) -> x == 0
    auto is_non_zero_lut_f = [total_modulus](Torus x) -> Torus {
      return (x % total_modulus) != 0;
    };

    is_non_zero_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    is_non_zero_lut->generate_and_broadcast_lut(
        active_streams, {0}, {is_non_zero_lut_f}, LUT_0_FOR_ALL_BLOCKS);

    // Scalar may have up to num_radix_blocks blocks
    scalar_comparison_luts = new int_radix_lut<Torus>(
        streams, params, total_modulus, num_radix_blocks, allocate_gpu_memory,
        size_tracker);

    // Operator LUT
    auto operator_f = [op](Torus lhs, Torus rhs) -> Torus {
      if (op == COMPARISON_TYPE::EQ) {
        return (lhs == rhs);
      } else if (op == COMPARISON_TYPE::NE) {
        return (lhs != rhs);
      } else {
        // For signed scalar comparisons we check equality with zero
        return (lhs == rhs);
      }
    };

    std::vector<std::function<Torus(Torus)>> lut_funcs;
    std::vector<uint32_t> lut_indices;
    for (int i = 0; i < total_modulus; i++) {
      auto lut_f = [i, operator_f](Torus x) -> Torus {
        return operator_f(i, x);
      };
      lut_funcs.push_back(lut_f);
      lut_indices.push_back(i);
    }

    scalar_comparison_luts->generate_and_broadcast_lut(
        active_streams, lut_indices, lut_funcs, LUT_0_FOR_ALL_BLOCKS);

    if (op == COMPARISON_TYPE::EQ || op == COMPARISON_TYPE::NE) {
      operator_lut =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);

      operator_lut->generate_and_broadcast_bivariate_lut(
          active_streams, {0}, {operator_f}, LUT_0_FOR_ALL_BLOCKS);
    } else {
      operator_lut = nullptr;
    }
  }

  void release(CudaStreams streams) {
    if (op == COMPARISON_TYPE::EQ || op == COMPARISON_TYPE::NE) {
      PANIC_IF_FALSE(operator_lut != nullptr,
                     "Cuda error: no operator lut was created");
      operator_lut->release(streams);
      delete operator_lut;
      operator_lut = nullptr;
    }
    is_non_zero_lut->release(streams);
    delete is_non_zero_lut;
    is_non_zero_lut = nullptr;
    are_all_block_true_buffer->release(streams);
    delete are_all_block_true_buffer;
    are_all_block_true_buffer = nullptr;
    scalar_comparison_luts->release(streams);
    delete scalar_comparison_luts;
    scalar_comparison_luts = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_tree_sign_reduction_buffer {
  int_radix_params params;

  std::function<Torus(Torus, Torus)> block_selector_f;

  int_radix_lut<Torus> *tree_inner_leaf_lut;
  int_radix_lut<Torus> *tree_last_leaf_lut;

  int_radix_lut<Torus> *tree_last_leaf_scalar_lut;

  Torus *preallocated_h_lut;
  CudaRadixCiphertextFFI *tmp_x;
  CudaRadixCiphertextFFI *tmp_y;
  bool gpu_memory_allocated;

  int_tree_sign_reduction_buffer(CudaStreams streams,
                                 std::function<Torus(Torus)> operator_f,
                                 int_radix_params params,
                                 uint32_t num_radix_blocks,
                                 bool allocate_gpu_memory,
                                 uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;

    block_selector_f = [](Torus msb, Torus lsb) -> Torus {
      if (msb == IS_EQUAL) // EQUAL
        return lsb;
      else
        return msb;
    };

    tmp_x = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_x, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_y = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_y, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    // LUTs

    tree_last_leaf_lut = new int_radix_lut<Torus>(
        streams, params, 1, 1, allocate_gpu_memory, size_tracker);

    preallocated_h_lut = (Torus *)malloc(safe_mul_sizeof<Torus>(
        params.glwe_dimension + 1, params.polynomial_size));

    tree_last_leaf_scalar_lut = new int_radix_lut<Torus>(
        streams, params, 1, 1, allocate_gpu_memory, size_tracker);

    tree_inner_leaf_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    tree_inner_leaf_lut->generate_and_broadcast_bivariate_lut(
        active_streams, {0}, {block_selector_f}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_x, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_y, gpu_memory_allocated);
    tree_inner_leaf_lut->release(streams);
    delete tree_inner_leaf_lut;
    tree_last_leaf_lut->release(streams);
    delete tree_last_leaf_lut;
    tree_last_leaf_scalar_lut->release(streams);
    delete tree_last_leaf_scalar_lut;

    delete tmp_x;
    delete tmp_y;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(preallocated_h_lut);
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
  Torus *preallocated_h_lut1;
  Torus *preallocated_h_lut2;
  int_comparison_diff_buffer(CudaStreams streams, COMPARISON_TYPE op,
                             int_radix_params params, uint32_t num_radix_blocks,
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
        PANIC("Cuda error (comparisons): unknown comparison type")
      }
    };

    tmp_packed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_packed, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tree_buffer = new int_tree_sign_reduction_buffer<Torus>(
        streams, operator_f, params, num_radix_blocks, allocate_gpu_memory,
        size_tracker);
    tmp_signs_a = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_signs_a, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tmp_signs_b = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_signs_b, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    // LUTs
    reduce_signs_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);
    preallocated_h_lut1 = (Torus *)malloc(safe_mul_sizeof<Torus>(
        params.glwe_dimension + 1, params.polynomial_size));
    preallocated_h_lut2 = (Torus *)malloc(safe_mul_sizeof<Torus>(
        params.glwe_dimension + 1, params.polynomial_size));
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_packed, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_signs_a, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_signs_b, gpu_memory_allocated);
    tree_buffer->release(streams);
    delete tree_buffer;
    reduce_signs_lut->release(streams);
    delete reduce_signs_lut;

    delete tmp_packed;
    delete tmp_signs_a;
    delete tmp_signs_b;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(preallocated_h_lut1);
    free(preallocated_h_lut2);
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

  /// @brief Borrow-propagation fast path for unsigned GT/GE/LT/LE on 2_2
  /// params. When enabled, the comparison reuses the overflow (borrow-out) path
  /// of the overflowing-sub borrow propagation instead of the sign-tree
  /// reduction.
  bool use_borrow_fast_path;
  /// @brief Borrow-propagation memory, allocated only on the fast path.
  int_borrow_prop_memory<Torus> *diff_borrow_mem;
  /// @brief Final single-block LUT applying the per-op inversion:
  ///   f(block) = ((block >> 2) & 1) ^ invert
  int_radix_lut<Torus> *lut_borrow_flag_cmp;

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
  CudaStreams lsb_streams;
  CudaStreams msb_streams;
  bool gpu_memory_allocated;
  Torus *preallocated_h_lut;
  // The comparison buffer allows a fast path for unsigned GT/GE/LT/LE when the
  // parameters are 2_2, by using an optimized version of the overflowing sub in
  // the same way that is done in the cpu.
  int_comparison_buffer(CudaStreams streams, COMPARISON_TYPE op,
                        int_radix_params params, uint32_t num_radix_blocks,
                        bool is_signed, bool allocate_gpu_memory,
                        uint64_t &size_tracker,
                        bool allow_borrow_fast_path = false) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->op = op;
    this->is_signed = is_signed;
    diff_borrow_mem = nullptr;
    lut_borrow_flag_cmp = nullptr;
    // When we are in the fast path we can avoid calculating the luts for the
    // tree reduction.
    use_borrow_fast_path =
        allow_borrow_fast_path &&
        (op == COMPARISON_TYPE::GT || op == COMPARISON_TYPE::GE ||
         op == COMPARISON_TYPE::LT || op == COMPARISON_TYPE::LE) &&
        !is_signed && params.message_modulus == 4 && params.carry_modulus == 4;
    // Null the sign-tree members so release() can safely skip them.
    diff_buffer = nullptr;
    eq_buffer = nullptr;
    identity_lut = nullptr;
    is_zero_lut = nullptr;
    tmp_lwe_array_out = nullptr;
    tmp_packed_input = nullptr;

    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);

    identity_lut_f = [](Torus x) -> Torus { return x; };

    lsb_streams.create_on_same_gpus(active_streams);
    msb_streams.create_on_same_gpus(active_streams);

    // Block comparisons buffer. Allocated for both paths: the sign-tree path
    // stores the per-block comparison results here, the borrow-propagation fast
    // path stores the subtraction blocks here.
    tmp_block_comparisons = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_block_comparisons,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    // We use the tree reduction old algorithm.
    if (!use_borrow_fast_path) {
      // +1 to have space for signed comparison
      tmp_lwe_array_out = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), tmp_lwe_array_out,
          num_radix_blocks + 1, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);

      tmp_packed_input = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), tmp_packed_input,
          2 * num_radix_blocks, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);

      // Cleaning LUT
      identity_lut =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);

      identity_lut->generate_and_broadcast_lut(
          active_streams, {0}, {identity_lut_f}, LUT_0_FOR_ALL_BLOCKS);

      uint32_t total_modulus = params.message_modulus * params.carry_modulus;
      auto is_zero_f = [total_modulus](Torus x) -> Torus {
        return (x % total_modulus) == 0;
      };

      is_zero_lut =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);

      is_zero_lut->generate_and_broadcast_lut(active_streams, {0}, {is_zero_f},
                                              LUT_0_FOR_ALL_BLOCKS);

      switch (op) {
      case COMPARISON_TYPE::MAX:
      case COMPARISON_TYPE::MIN:
        cmux_buffer = new int_cmux_buffer<Torus>(
            streams,
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
            streams, op, params, num_radix_blocks, allocate_gpu_memory,
            size_tracker);
      case COMPARISON_TYPE::EQ:
      case COMPARISON_TYPE::NE:
        eq_buffer = new int_comparison_eq_buffer<Torus>(
            streams, op, params, num_radix_blocks, allocate_gpu_memory,
            size_tracker);
        break;
      default:
        PANIC("Unsupported comparison operation.")
      }
    }

    if (is_signed) {

      tmp_trivial_sign_block = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), tmp_trivial_sign_block, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      signed_lut = new int_radix_lut<Torus>(streams, params, 1, 1,
                                            allocate_gpu_memory, size_tracker);
      signed_msb_lut = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);

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

      auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
      signed_lut->generate_and_broadcast_bivariate_lut(
          active_streams, {0}, {signed_lut_f}, LUT_0_FOR_ALL_BLOCKS);
    }

    // Allocate the borrow-propagation machinery reused by the fast path. We
    // reuse the overflowing-sub borrow propagation and finish with a
    // single-block LUT that extracts the borrow flag and applies the per-op
    // boolean inversion (lut_borrow_flag_cmp below).
    if (use_borrow_fast_path) {
      // FLAG_NONE: host_difference_check_via_borrow does the overflow-block
      // combination itself, so int_borrow_prop_memory's own borrow-flag LUT is
      // never used and we avoid allocating it.
      diff_borrow_mem = new int_borrow_prop_memory<Torus>(
          streams, params, num_radix_blocks, (uint32_t)outputFlag::FLAG_NONE,
          allocate_gpu_memory, size_tracker);

      // GE/LE need to invert the `<` result, GT/LT do not.
      bool invert = (op == COMPARISON_TYPE::GE || op == COMPARISON_TYPE::LE);
      auto f_borrow_flag_cmp = [invert](Torus block) -> Torus {
        return ((block >> 2) & 1) ^ (Torus)invert;
      };

      lut_borrow_flag_cmp = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);
      auto active_streams_one = streams.active_gpu_subset(1, params.pbs_type);
      lut_borrow_flag_cmp->generate_and_broadcast_lut(
          active_streams_one, {0}, {f_borrow_flag_cmp}, LUT_0_FOR_ALL_BLOCKS);

      // We need to create the luts for the borrow fast path that are optimized
      // for comparisons. This saves us half the number of pbs of the second
      // step if we were using the generic overflow path. The cpu perform
      // exactly this operation too.
      if (allocate_gpu_memory) {
        auto *mem_simu_group_carries =
            diff_borrow_mem->prop_simu_group_carries_mem;
        uint32_t group_size = diff_borrow_mem->group_size;
        uint32_t n_groups = diff_borrow_mem->num_groups;
        bool seq = mem_simu_group_carries
                       ->use_sequential_algorithm_to_resolve_group_carries;

        // Mirror second_step_lut_index_generator / h_scalar_array_cum_sum for a
        // single cumulative-sum position (see
        // int_prop_simu_group_carries_memory).
        auto lut_index_for = [group_size, seq](uint32_t pos) -> Torus {
          uint32_t group_index = pos / group_size;
          uint32_t pos_in_group = pos % group_size;
          if (group_index == 0)
            return (Torus)pos_in_group;
          else if (pos_in_group == group_size - 1)
            return seq ? (Torus)((group_index - 1) % (group_size - 1) +
                                 2 * group_size)
                       : (Torus)(2 * group_size);
          else
            return (Torus)(pos_in_group + group_size);
        };
        auto corrector_for = [group_size, seq](uint32_t pos) -> Torus {
          uint32_t group_index = pos / group_size;
          uint32_t pos_in_group = pos % group_size;
          if (group_index == 0 || pos_in_group != group_size - 1)
            return (Torus)0;
          return seq ? ((Torus)1 << ((group_index - 1) % (group_size - 1)))
                     : (Torus)1;
        };

        std::vector<Torus> h_indexes(n_groups);
        std::vector<Torus> h_scalar_corrector(n_groups);
        for (uint32_t g = 0; g + 1 < n_groups; g++) {
          uint32_t pos = (g + 1) * group_size - 1;
          h_indexes[g] = lut_index_for(pos);
          h_scalar_corrector[g] = corrector_for(pos);
        }
        uint32_t simulator_pos = num_radix_blocks - 2;
        h_indexes[n_groups - 1] = lut_index_for(simulator_pos);
        h_scalar_corrector[n_groups - 1] = corrector_for(simulator_pos);

        auto *lut = mem_simu_group_carries->luts_array_second_step;
        cuda_memcpy_with_size_tracking_async_to_gpu(
            lut->get_lut_indexes(0, 0), h_indexes.data(),
            safe_mul_sizeof<Torus>(n_groups), streams.stream(0),
            streams.gpu_index(0), allocate_gpu_memory);
        lut->broadcast_lut(active_streams, false);

        cuda_memcpy_with_size_tracking_async_to_gpu(
            mem_simu_group_carries->scalar_array_cum_sum,
            h_scalar_corrector.data(), safe_mul_sizeof<Torus>(n_groups),
            streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
        for (uint32_t i = 0; i < n_groups; i++)
          mem_simu_group_carries->h_scalar_array_cum_sum[i] =
              h_scalar_corrector[i];
      }
    }

    preallocated_h_lut = (Torus *)malloc(safe_mul_sizeof<Torus>(
        params.glwe_dimension + 1, params.polynomial_size));
  }

  void release(CudaStreams streams) {
    if (!use_borrow_fast_path) {
      switch (op) {
      case COMPARISON_TYPE::MAX:
      case COMPARISON_TYPE::MIN:
        cmux_buffer->release(streams);
        delete (cmux_buffer);
      case COMPARISON_TYPE::GT:
      case COMPARISON_TYPE::GE:
      case COMPARISON_TYPE::LT:
      case COMPARISON_TYPE::LE:
        diff_buffer->release(streams);
        delete (diff_buffer);
      case COMPARISON_TYPE::EQ:
      case COMPARISON_TYPE::NE:
        eq_buffer->release(streams);
        delete (eq_buffer);
        break;
      default:
        PANIC("Unsupported comparison operation.")
      }
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_lwe_array_out, gpu_memory_allocated);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_packed_input, gpu_memory_allocated);
      identity_lut->release(streams);
      delete identity_lut;
      is_zero_lut->release(streams);
      delete is_zero_lut;
      delete tmp_lwe_array_out;
      delete tmp_packed_input;
    }
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_block_comparisons, gpu_memory_allocated);
    delete tmp_block_comparisons;

    if (is_signed) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_trivial_sign_block,
                                     gpu_memory_allocated);
      signed_lut->release(streams);
      delete signed_lut;
      signed_msb_lut->release(streams);
      delete signed_msb_lut;
      delete tmp_trivial_sign_block;
    }
    if (use_borrow_fast_path) {
      diff_borrow_mem->release(streams);
      delete diff_borrow_mem;
      diff_borrow_mem = nullptr;
      lut_borrow_flag_cmp->release(streams);
      delete lut_borrow_flag_cmp;
      lut_borrow_flag_cmp = nullptr;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    lsb_streams.release();
    msb_streams.release();
    free(preallocated_h_lut);
  }
};
