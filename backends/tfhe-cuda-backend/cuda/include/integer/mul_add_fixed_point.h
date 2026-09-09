#pragma once
#include "integer_utilities.h"
#include <cstring>

// ---------------------------------------------------------------------------
// Fixed-point fused multiply-add with an asymmetric right operand
// ---------------------------------------------------------------------------
//
// Computes, over a radix of base beta = message_modulus:
//
//     result[L] = trunc_beta^s( lhs[L] * rhs[R] + added[L] * beta^s )
//
// where s = R + |rescaling| is the number of low blocks dropped from the
// product, so that the output has exactly as many blocks as `lhs`. This is the
// primitive the Goldschmidt divider needs: the left operand carries the running
// numerator/denominator (L blocks) and the right one the short iteration factor
// (R << L blocks).
//
// Two shapes are supported, selected at scratch time:
//
//   MUL_ADD_MODE_FIXED_POINT
//     accumulator W  = L + R + |rescaling|
//     dropped blocks s = R + |rescaling|
//     skip k         = the largest column count whose worst-case weight stays
//                      below 2^precision, i.e. below one output ulp. Those
//                      columns are never bootstrapped.
//
//   MUL_ADD_MODE_MUL_LOW
//     accumulator W  = L = R = n, skip = 0, s = 0
//     i.e. the low half of a square product, plus caller-supplied extra terms.
//     Used for the remainder r = n - q*d, where the extra terms are bitnot(n)
//     and a trivial 1.
//
// The (lhs block, rhs block) pairs that survive both the skip threshold and the
// accumulator width are enumerated once on the host at scratch time - the set
// only depends on the shape, never on the data - and turned into gather/scatter
// index maps. Only those pairs are bootstrapped, which is what keeps this at
// the CPU implementation's block-multiplication count.
//
// The surviving pairs form a trapezoid rather than the square matrix a naive
// port would bootstrap: columns below `skip` weigh less than one output ulp,
// and columns at or above `accumulator` fall off the top. For L = 34, R = 5, k
// = 3 (the seed step), with a = lhs block index and column = a + r:
//
//     column   0  1  2 | 3  4  5 ...            36 37 38 | (>= W: dropped)
//              -  -  - | x  x  x                 x  x  x
//     r = 0    .  .  . | *  *  *  ...            *  *  .
//     r = 1       .  . | *  *  *  ...            *  *  *
//     r = 2          . | *  *  *  ...            *  *  *
//     r = 3            | *  *  *  ...            *  *  *
//     r = 4            | *  *  *  ...            *  *  *
//              \_____ skipped: total weight < 1 output ulp
//
// Each surviving '*' becomes one bivariate bootstrap, producing a message half
// at `column` and a carry half at `column + 1`. Those land in a dense term
// vector of (2R + 1) rows by `window = accumulator - skip` blocks, which the
// column sum consumes directly - row r holds the message halves of rhs block r,
// row R + r its carry halves, and the last row the `added` operand, shifted so
// its LSB sits at the output's LSB:
//
//     terms row  0    [ . . lsb products of r=0 . . ]
//                ...
//     terms row  R-1  [ . . lsb products of r=R-1 . ]
//     terms row  R    [ . . msb products of r=0 . . ]
//                ...
//     terms row 2R-1  [ . . msb products of r=R-1 . ]
//     terms row 2R    [ 0 ... 0 | added ........... ]
//                       |<- s-k ->|
//
// The retained output is the top L blocks of that window, i.e. blocks
// [s - k, s - k + L) of the summed accumulator.
#define MUL_ADD_MODE_FIXED_POINT 0u
#define MUL_ADD_MODE_MUL_LOW 1u

/// @brief Saturating 128-bit multiply, returning the maximum representable
/// value on overflow.
///
/// The column-weight bounds below are compared against 2^precision, and
/// precision reaches 66 in this algorithm, so the arithmetic cannot be done in
/// uint64_t.
/// @param a Left factor.
/// @param b Right factor.
/// @return a * b, saturated.
inline __uint128_t mul_add_sat_mul(__uint128_t a, __uint128_t b) {
  const __uint128_t max = ~(__uint128_t)0;
  if (a == 0 || b == 0)
    return 0;
  if (a > max / b)
    return max;
  return a * b;
}

/// @brief Saturating 128-bit exponentiation.
/// @param base Value raised to the power.
/// @param exp Exponent.
/// @return base^exp, saturated.
inline __uint128_t mul_add_sat_pow(__uint128_t base, uint32_t exp) {
  __uint128_t result = 1;
  for (uint32_t i = 0; i < exp; i++)
    result = mul_add_sat_mul(result, base);
  return result;
}

/// @brief Worst-case weight of the low `columns` columns of a schoolbook
/// product, in units of the product's LSB, while the columns are still growing
/// (columns <= rhs_length).
///
/// Evaluates c * beta^(c+1) - (c+1) * beta^c + 1.
/// @param columns Number of low columns considered.
/// @param block_size The radix base beta, i.e. message_modulus.
/// @return The bound, saturated.
inline __uint128_t mul_add_triangular_max(uint32_t columns,
                                          uint32_t block_size) {
  __uint128_t term1 =
      mul_add_sat_mul(columns, mul_add_sat_pow(block_size, columns + 1));
  __uint128_t term2 =
      mul_add_sat_mul(columns + 1, mul_add_sat_pow(block_size, columns));
  if (term1 < term2)
    return 1;
  return term1 - term2 + 1;
}

/// @brief Same bound as mul_add_triangular_max, extended past the point where
/// the columns stop growing and saturate at rhs_length entries each.
/// @param columns Number of low columns considered.
/// @param block_size The radix base beta, i.e. message_modulus.
/// @param rhs_length Block count of the right operand, where columns saturate.
/// @return The bound, saturated.
inline __uint128_t mul_add_general_max(uint32_t columns, uint32_t block_size,
                                       uint32_t rhs_length) {
  if (columns <= rhs_length)
    return mul_add_triangular_max(columns, block_size);
  __uint128_t triangular = mul_add_triangular_max(rhs_length, block_size);
  __uint128_t rectangular = mul_add_sat_mul(
      mul_add_sat_mul(
          mul_add_sat_mul(rhs_length, mul_add_sat_pow(block_size, rhs_length)),
          mul_add_sat_pow(block_size, columns - rhs_length) - 1),
      block_size - 1);
  const __uint128_t max = ~(__uint128_t)0;
  if (triangular > max - rectangular)
    return max;
  return triangular + rectangular;
}

/// @brief Largest number of low columns that can be dropped while the weight
/// discarded with them stays strictly below 2^precision, i.e. below one output
/// ulp. Those columns are never bootstrapped.
/// @param block_size The radix base beta, i.e. message_modulus.
/// @param rhs_length Block count of the right operand.
/// @param precision Bits of the output ulp.
/// @return The column count, 0 when nothing can be dropped.
inline uint32_t mul_add_find_max_columns(uint32_t block_size,
                                         uint32_t rhs_length,
                                         uint32_t precision) {
  if (rhs_length == 0)
    return 0;
  __uint128_t target = (__uint128_t)1 << precision;
  for (uint32_t columns = 0; columns <= 4096; columns++) {
    if (mul_add_general_max(columns, block_size, rhs_length) >= target)
      return columns == 0 ? 0 : columns - 1;
  }
  PANIC("Cuda error (mul_add_fixed_point): could not determine the number of "
        "columns to skip")
  return 0;
}

/// @brief Enumerates the (lhs block, rhs block) pairs of one half of the block
/// products that survive both the skip threshold and the accumulator width,
/// appending them to the gather/scatter index maps.
///
/// A block product has two halves, and they differ only in where the result
/// lands: the lsb half sits in column `a + r`, the msb half one column higher.
/// Each half is stored in its own band of term rows so that one lut_indexes run
/// can switch LUTs between them. Both halves skip the same low columns, since
/// the skip threshold is about the column a pair *starts* at.
///
/// @param skip Columns below this weigh less than one output ulp and are never
/// bootstrapped.
/// @param accumulator Columns at or above this fall off the top of the output.
/// @param window Width of a term row, i.e. accumulator - skip.
/// @param column_offset 0 for the lsb half, 1 for the msb half.
/// @param term_row_base 0 for the lsb half, rhs_blocks for the msb half.
/// @param degree Degree every block of this half leaves its bootstrap with.
/// @param idx In/out cursor into the index maps, advanced past the pairs added.
inline void
mul_add_enumerate_pairs(uint32_t lhs_blocks, uint32_t rhs_blocks, uint32_t skip,
                        uint32_t accumulator, uint32_t window,
                        uint32_t column_offset, uint32_t term_row_base,
                        uint64_t degree, uint32_t *h_pair_lhs_idx,
                        uint32_t *h_pair_rhs_idx, uint32_t *h_pair_dst_idx,
                        uint64_t *h_product_degrees, uint32_t &idx) {
  for (uint32_t r = 0; r < rhs_blocks; r++) {
    for (uint32_t a = 0; a < lhs_blocks; a++) {
      uint32_t column = a + r + column_offset;
      if (a + r < skip || column >= accumulator)
        continue;
      h_pair_lhs_idx[idx] = a;
      h_pair_rhs_idx[idx] = r;
      h_pair_dst_idx[idx] = (term_row_base + r) * window + (column - skip);
      h_product_degrees[h_pair_dst_idx[idx]] = degree;
      idx++;
    }
  }
}

/// @brief Scratch for the fixed-point fused multiply-add, holding the shape
/// this buffer was scratched for, the gather/scatter index maps of the
/// surviving block-product pairs, and the buffers the pairs and the column sum
/// run in. See the file banner above for the two supported shapes.
template <typename Torus> struct int_mul_add_fixed_point_memory {
  int_radix_params params;
  bool gpu_memory_allocated;

  /// @brief MUL_ADD_MODE_FIXED_POINT or MUL_ADD_MODE_MUL_LOW.
  uint32_t mode;
  /// @brief L, the left operand's block count and also the output width.
  uint32_t lhs_blocks;
  /// @brief R, the right operand's block count.
  uint32_t rhs_blocks;
  /// @brief |rescaling|, the extra low blocks dropped beyond R.
  uint32_t rescaling;
  /// @brief Bits of the output ulp; drives how many columns `skip` covers.
  uint32_t precision;
  /// @brief k, the low columns whose weight stays below one output ulp and
  /// which are therefore never computed.
  uint32_t skip;
  /// @brief W, the full accumulator width.
  uint32_t accumulator;
  /// @brief W - k, the only part of the accumulator actually built.
  uint32_t window;
  /// @brief s = R + |rescaling|, the low blocks dropped from the product.
  uint32_t out_shift;
  /// @brief Upper bound on the caller-supplied addends one call may pass.
  uint32_t max_extra_terms;
  /// @brief Rows of the term matrix: 2R, plus the added slot and extra terms.
  uint32_t num_terms;
  /// @brief Pairs belonging to the lsb half, i.e. where the msb half starts.
  uint32_t num_lsb_pairs;
  /// @brief lsb + msb pairs, i.e. the bootstrap count of one call.
  uint32_t num_pairs;

  /// @brief Left operand of every surviving pair, gathered contiguously.
  CudaRadixCiphertextFFI *pair_lhs;
  /// @brief Right operand of every surviving pair on entry, and the
  /// bootstrapped block products on exit: the bivariate LUT is applied in
  /// place, as in host_integer_mult_radix.
  CudaRadixCiphertextFFI *pair_products;
  /// @brief The term matrix, num_terms * window blocks, consumed directly by
  /// the column sum without a copy.
  CudaRadixCiphertextFFI *terms;
  /// @brief Keyswitch output buffer for the column sum.
  CudaRadixCiphertextFFI *small_lwe_vector;
  /// @brief Summed accumulator, which the retained output is sliced out of.
  CudaRadixCiphertextFFI *sum_result;

  /// @brief Device copy of the per-pair left operand block indexes.
  uint32_t *d_pair_lhs_idx;
  /// @brief Device copy of the per-pair right operand block indexes.
  uint32_t *d_pair_rhs_idx;
  /// @brief Device copy of each pair's destination slot in the term matrix.
  uint32_t *d_pair_dst_idx;
  /// @brief Host copy of the per-pair left operand block indexes, used to
  /// carry the operands' degrees across the gather.
  uint32_t *h_pair_lhs_idx;
  /// @brief Host copy of the per-pair right operand block indexes, same use.
  uint32_t *h_pair_rhs_idx;
  /// @brief Degrees of the term matrix laid out exactly as the terms: copied
  /// in wholesale on every call, after which the added and extra slots are
  /// overwritten from the actual inputs.
  uint64_t *h_product_degrees;
  /// @brief Noise levels of the term matrix, same layout and same use.
  uint64_t *h_product_noise_levels;

  /// @brief {lsb, msb} block multiplication LUTs.
  int_radix_lut<Torus> *luts_array;
  /// @brief {message, carry} LUTs for the column sum.
  int_radix_lut<Torus> *sum_luts;
  /// @brief Scratch for summing the term matrix column-wise.
  int_sum_ciphertexts_vec_memory<Torus> *sum_mem;
  /// @brief Scratch for the final carry propagation.
  int_sc_prop_memory<Torus> *sc_prop_mem;

  int_mul_add_fixed_point_memory(CudaStreams streams, int_radix_params params,
                                 uint32_t mode, uint32_t lhs_blocks,
                                 uint32_t rhs_blocks, uint32_t rescaling,
                                 uint32_t precision, uint32_t max_extra_terms,
                                 bool allocate_gpu_memory,
                                 uint64_t &size_tracker) {
    this->params = params;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->mode = mode;
    this->lhs_blocks = lhs_blocks;
    this->rhs_blocks = rhs_blocks;
    this->rescaling = rescaling;
    this->precision = precision;
    this->max_extra_terms = max_extra_terms;

    PANIC_IF_FALSE(lhs_blocks > 0 && rhs_blocks > 0,
                   "Cuda error (mul_add_fixed_point): both operands must have "
                   "at least one block");

    auto message_modulus = params.message_modulus;

    if (mode == MUL_ADD_MODE_MUL_LOW) {
      PANIC_IF_FALSE(lhs_blocks == rhs_blocks,
                     "Cuda error (mul_add_fixed_point): the mul-low shape "
                     "expects two operands of the same width");
      this->skip = 0;
      this->accumulator = lhs_blocks;
      this->out_shift = 0;
      this->num_terms = 2 * rhs_blocks + max_extra_terms;
    } else {
      this->skip =
          mul_add_find_max_columns(message_modulus, rhs_blocks, precision);
      this->accumulator = lhs_blocks + rhs_blocks + rescaling;
      this->out_shift = rhs_blocks + rescaling;
      this->num_terms = 2 * rhs_blocks + 1 + max_extra_terms;
      PANIC_IF_FALSE(this->skip <= this->out_shift,
                     "Cuda error (mul_add_fixed_point): the truncation "
                     "threshold reaches into the retained output blocks");
    }
    this->window = this->accumulator - this->skip;

    // Enumerate the surviving (lhs block, rhs block) pairs: lsb halves first so
    // a single lut_indexes run switches to the msb LUT, mirroring
    // host_integer_mult_radix.
    uint32_t max_pairs = 2 * lhs_blocks * rhs_blocks;
    h_pair_lhs_idx = new uint32_t[max_pairs];
    h_pair_rhs_idx = new uint32_t[max_pairs];
    uint32_t *h_pair_dst_idx = new uint32_t[max_pairs];
    h_product_degrees = new uint64_t[(size_t)num_terms * window];
    h_product_noise_levels = new uint64_t[(size_t)num_terms * window];
    std::memset(h_product_degrees, 0,
                safe_mul_sizeof<uint64_t>((size_t)num_terms * window));

    uint32_t idx = 0;
    // lsb halves first, so a single lut_indexes run switches to the msb LUT.
    mul_add_enumerate_pairs(lhs_blocks, rhs_blocks, skip, accumulator, window,
                            /*column_offset=*/0, /*term_row_base=*/0,
                            message_modulus - 1, h_pair_lhs_idx, h_pair_rhs_idx,
                            h_pair_dst_idx, h_product_degrees, idx);
    num_lsb_pairs = idx;
    mul_add_enumerate_pairs(lhs_blocks, rhs_blocks, skip, accumulator, window,
                            /*column_offset=*/1, /*term_row_base=*/rhs_blocks,
                            message_modulus - 2, h_pair_lhs_idx, h_pair_rhs_idx,
                            h_pair_dst_idx, h_product_degrees, idx);
    num_pairs = idx;
    // Every block that carries a product comes straight out of a bootstrap.
    for (size_t i = 0; i < (size_t)num_terms * window; i++)
      h_product_noise_levels[i] = h_product_degrees[i] ? 1 : 0;
    PANIC_IF_FALSE(num_pairs > 0,
                   "Cuda error (mul_add_fixed_point): the shape leaves no "
                   "block product to compute");

    d_pair_lhs_idx = (uint32_t *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<uint32_t>(num_pairs), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    d_pair_rhs_idx = (uint32_t *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<uint32_t>(num_pairs), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    d_pair_dst_idx = (uint32_t *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<uint32_t>(num_pairs), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    if (allocate_gpu_memory) {
      cuda_memcpy_async_to_gpu(d_pair_lhs_idx, h_pair_lhs_idx,
                               safe_mul_sizeof<uint32_t>(num_pairs),
                               streams.stream(0), streams.gpu_index(0));
      cuda_memcpy_async_to_gpu(d_pair_rhs_idx, h_pair_rhs_idx,
                               safe_mul_sizeof<uint32_t>(num_pairs),
                               streams.stream(0), streams.gpu_index(0));
      cuda_memcpy_async_to_gpu(d_pair_dst_idx, h_pair_dst_idx,
                               safe_mul_sizeof<uint32_t>(num_pairs),
                               streams.stream(0), streams.gpu_index(0));
      cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    }
    delete[] h_pair_dst_idx;

    pair_lhs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), pair_lhs, num_pairs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    pair_products = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), pair_products, num_pairs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    terms = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), terms, num_terms * window,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), small_lwe_vector,
        num_terms * window, params.small_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    sum_result = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), sum_result, window,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    // {lsb, msb} block multiplication, one index run per half.
    luts_array = new int_radix_lut<Torus>(streams, params, 2, num_pairs,
                                          allocate_gpu_memory, size_tracker);
    auto lut_f_lsb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) % message_modulus;
    };
    auto lut_f_msb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) / message_modulus;
    };
    auto num_lsb = num_lsb_pairs;
    auto lut_index_generator = [num_lsb](Torus *h_lut_indexes,
                                         uint32_t num_indexes) {
      for (uint32_t i = 0; i < num_indexes; i++)
        h_lut_indexes[i] = (i < num_lsb) ? 0 : 1;
    };
    auto active_streams = streams.active_gpu_subset(num_pairs, params.pbs_type);
    luts_array->generate_and_broadcast_bivariate_lut(
        active_streams, {0, 1}, {lut_f_lsb, lut_f_msb}, lut_index_generator);

    // The column sum needs its own {message, carry} LUT: sharing `luts_array`
    // the way int_mul_memory does would overwrite the block-multiplication
    // accumulators, which is only safe when the buffer is scratched per call.
    uint32_t chunk_size = params.max_degree();
    uint32_t max_pbs_count =
        std::max(2 * ((num_terms * window) / chunk_size), 2 * window);
    sum_luts = new int_radix_lut<Torus>(streams, params, 2, max_pbs_count,
                                        allocate_gpu_memory, size_tracker);
    sum_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, params, window, num_terms, terms, small_lwe_vector, sum_luts,
        true, allocate_gpu_memory, size_tracker);
    sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, params, window, outputFlag::FLAG_NONE, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   pair_lhs, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   pair_products, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   terms, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   small_lwe_vector, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   sum_result, gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_pair_lhs_idx, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_pair_rhs_idx, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_pair_dst_idx, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    luts_array->release(streams);
    sum_mem->release(streams);
    sum_luts->release(streams);
    sc_prop_mem->release(streams);

    delete pair_lhs;
    delete pair_products;
    delete terms;
    delete small_lwe_vector;
    delete sum_result;
    delete luts_array;
    delete sum_mem;
    delete sum_luts;
    delete sc_prop_mem;
    delete[] h_pair_lhs_idx;
    delete[] h_pair_rhs_idx;
    delete[] h_product_degrees;
    delete[] h_product_noise_levels;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
