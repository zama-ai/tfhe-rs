#ifndef CUDA_INTEGER_GOLDSCHMIDT_DIVISION_CUH
#define CUDA_INTEGER_GOLDSCHMIDT_DIVISION_CUH

#include "integer/bitwise_ops.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/goldschmidt_division.h"
#include "integer/ilog2.cuh"
#include "integer/integer.cuh"
#include "integer/multiplication.cuh"
#include "integer/scalar_comparison.cuh"
#include "integer/shift_and_rotate.cuh"
#include "integer/subtraction.cuh"
#include "integer/vector_find.cuh"
#include "radix_ciphertext.cuh"

// Copies `input` into `output` scaled by beta^shift, i.e. shifted left by
// `shift` blocks for a positive shift and right for a negative one. Blocks that
// fall outside `output` are dropped and the rest is zero filled; no bootstraps.
template <typename Torus>
__host__ void
goldschmidt_blockshift(CudaStreams streams, CudaRadixCiphertextFFI *output,
                       const CudaRadixCiphertextFFI *input, int32_t shift) {
  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  uint32_t out_blocks = output->num_radix_blocks;
  uint32_t in_blocks = input->num_radix_blocks;

  set_zero_radix_ciphertext_slice_async<Torus>(stream, gpu_index, output, 0,
                                               out_blocks);
  if (shift >= 0) {
    uint32_t left = (uint32_t)shift;
    if (left >= out_blocks)
      return;
    uint32_t count = std::min(in_blocks, out_blocks - left);
    copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, output, left,
                                             left + count, input, 0, count);
  } else {
    uint32_t right = (uint32_t)(-shift);
    if (right >= in_blocks)
      return;
    uint32_t count = std::min(in_blocks - right, out_blocks);
    copy_radix_ciphertext_slice_async<Torus>(streams.stream(0), gpu_index,
                                             output, 0, count, input, right,
                                             right + count);
  }
}

// Brings the denominator into [1/2, 1) as a Q0.fp fixed point and rescales the
// numerator by the same power of two, leaving it as Q64.(fp-64).
//
//     lz = leading_zeros(D)
//     d  = (D << lz) * beta^2                 exact, D << lz has its MSB set
//     n  = floor(N * 2^lz / 2^(2*(2n-fp)))    the numerator, same scaling
//
// The numerator is widened to twice the operand width before shifting so the
// shift cannot lose its top bits, then narrowed back down to the fixed point.
template <typename Torus, typename KSTorus>
__host__ void goldschmidt_normalize(
    CudaStreams streams, const CudaRadixCiphertextFFI *numerator,
    const CudaRadixCiphertextFFI *denominator,
    int_goldschmidt_division_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {
  PUSH_RANGE("goldschmidt normalize")
  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  uint32_t num_blocks = mem->num_blocks;
  uint32_t fp_blocks = mem->fp_blocks;

  host_integer_count_of_consecutive_bits<Torus, KSTorus>(
      streams, mem->leading_zeros, denominator, mem->leading_zeros_mem, bsks,
      ksks);
  host_scalar_equality_check<Torus, KSTorus>(
      streams, mem->d_is_zero, denominator, mem->d_zero_scalar,
      mem->is_zero_mem, bsks, ksks, num_blocks, num_blocks);

  // The barrel shifter wants the amount at the same width as the value, so the
  // counter is zero extended for each of the two shifts.
  CudaRadixCiphertextFFI narrow_amount;
  as_radix_ciphertext_slice<Torus>(&narrow_amount, mem->shift_amount, 0,
                                   num_blocks);
  goldschmidt_blockshift<Torus>(streams, &narrow_amount, mem->leading_zeros, 0);
  copy_radix_ciphertext_async<Torus>(stream, gpu_index, mem->shifted_d,
                                     denominator);
  host_shift_and_rotate_inplace<Torus, KSTorus>(
      streams, mem->shifted_d, &narrow_amount, mem->shift_d_mem, bsks, ksks);
  goldschmidt_blockshift<Torus>(streams, mem->current_d, mem->shifted_d,
                                (int32_t)(fp_blocks - num_blocks));

  goldschmidt_blockshift<Torus>(streams, mem->wide_n, numerator, 0);
  goldschmidt_blockshift<Torus>(streams, mem->shift_amount, mem->leading_zeros,
                                0);
  host_shift_and_rotate_inplace<Torus, KSTorus>(
      streams, mem->wide_n, mem->shift_amount, mem->shift_n_mem, bsks, ksks);
  goldschmidt_blockshift<Torus>(
      streams, mem->current_n, mem->wide_n,
      (int32_t)fp_blocks - 2 * (int32_t)num_blocks);
  POP_RANGE()
}

// Looks up x0 on d's top (lut_precision + 1) bits and folds the seed into both
// operands: n <- n * (1 + x0), d <- d * (1 + x0). The table is built so that
// the product stays below 1, which every later round then preserves.
template <typename Torus>
__host__ void goldschmidt_seed(CudaStreams streams,
                               int_goldschmidt_division_buffer<Torus> *mem,
                               void *const *bsks, uint64_t *const *ksks) {
  PUSH_RANGE("goldschmidt seed")

  // d's top x0_blocks blocks are the table's index.
  CudaRadixCiphertextFFI d_msb;
  as_radix_ciphertext_slice<Torus>(&d_msb, mem->current_d,
                                   mem->fp_blocks - mem->x0_blocks,
                                   mem->fp_blocks);
  host_unchecked_match_value<Torus>(streams, mem->seed_factor, mem->seed_found,
                                    &d_msb, mem->h_lut_inputs,
                                    mem->h_lut_outputs, mem->seed_lut_mem, bsks,
                                    (Torus *const *)ksks);

  // x0 is a fraction with x0_blocks blocks below the point, so the product is
  // truncated by exactly that much and the accumulator term carries the `+ 1`.
  host_mul_add_fixed_point_with_rescaling<Torus>(
      streams, mem->next_n, mem->current_n, mem->seed_factor, mem->current_n,
      mem->mul_add_mem[0], bsks, ksks);
  host_mul_add_fixed_point_with_rescaling<Torus>(
      streams, mem->next_d, mem->current_d, mem->seed_factor, mem->current_d,
      mem->mul_add_mem[0], bsks, ksks);
  std::swap(mem->current_n, mem->next_n);
  std::swap(mem->current_d, mem->next_d);
  POP_RANGE()
}

// One round: x = 1 - d read straight off d's blocks, then
// n <- n * (1 + x) and d <- d * (1 + x). The last round skips d, which is not
// read again.
template <typename Torus>
__host__ void goldschmidt_iterations(CudaStreams streams,
                                     int_goldschmidt_division_buffer<Torus> *mem,
                                     uint32_t iterations, void *const *bsks,
                                     uint64_t *const *ksks) {
  PUSH_RANGE("goldschmidt iterations")
  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  auto params = mem->params;

  for (uint32_t i = 0; i < iterations; i++) {
    uint32_t x_blocks = mem->x_blocks[i];
    uint32_t x_zero_blocks = mem->x_zero_blocks[i];

    // d sits just below 1, so its top x_zero_blocks blocks are all beta-1 and
    // 1 - d is the bitwise complement of what is left. Only x_blocks of it are
    // significant at this round's precision, so complement just those.
    //
    //     d       = 0. 3 3 3 3 | b b b b b | ... low blocks ...
    //                 \_ zero _/ \_ x _/
    //     1 - d   = 0. 0 0 0 0 | !b !b ... | ...
    CudaRadixCiphertextFFI x_view;
    as_radix_ciphertext_slice<Torus>(&x_view, mem->factor_x, 0, x_blocks);
    uint32_t x_start = mem->fp_blocks - x_zero_blocks - x_blocks;
    copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, &x_view, 0,
                                             x_blocks, mem->current_d, x_start,
                                             x_start + x_blocks);
    host_bitnot<Torus>(streams, &x_view, params.message_modulus,
                       params.message_modulus, params.carry_modulus);

    host_mul_add_fixed_point_with_rescaling<Torus>(
        streams, mem->next_n, mem->current_n, &x_view, mem->current_n,
        mem->mul_add_mem[1 + i], bsks, ksks);
    if (i + 1 < iterations) {
      host_mul_add_fixed_point_with_rescaling<Torus>(
          streams, mem->next_d, mem->current_d, &x_view, mem->current_d,
          mem->mul_add_mem[1 + i], bsks, ksks);
      std::swap(mem->current_d, mem->next_d);
    }
    std::swap(mem->current_n, mem->next_n);
  }
  POP_RANGE()
}

// Reads the quotient out of the fixed point, recovers the remainder and applies
// the one-step correction.
//
// Every truncation in the algorithm rounds down and d stays below 1 throughout,
// so the quotient is either exact or one too small - never too large. Which of
// the two is settled by the remainder: if r = n - q*d still reaches d, bump q.
//
// r is built without a subtraction. The mul-low leaves q*d + !n + 1 = q*d - n
// as an unpropagated sum whose blocks split into a message half M and a carry
// half C, and -(M + C) = !M + !C + 2, so two lookups and an addition give the
// remainder directly.
template <typename Torus, typename KSTorus>
__host__ void goldschmidt_finalize(
    CudaStreams streams, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, const CudaRadixCiphertextFFI *numerator,
    const CudaRadixCiphertextFFI *denominator,
    int_goldschmidt_division_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {
  PUSH_RANGE("goldschmidt finalize")
  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  auto params = mem->params;
  uint32_t num_blocks = mem->num_blocks;

  // n is Q64.(fp-64); dropping the fractional blocks leaves the integer part.
  goldschmidt_blockshift<Torus>(streams, mem->quotient_tmp, mem->current_n,
                                (int32_t)num_blocks - (int32_t)mem->fp_blocks);

  // extra_terms = [bitnot(numerator) | 1], the two addends that turn q*d into
  // q*d - n once negated.
  CudaRadixCiphertextFFI not_numerator;
  as_radix_ciphertext_slice<Torus>(&not_numerator, mem->extra_terms, 0,
                                   num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, &not_numerator, 0,
                                           num_blocks, numerator, 0,
                                           num_blocks);
  host_bitnot<Torus>(streams, &not_numerator, params.message_modulus,
                     params.message_modulus, params.carry_modulus);
  copy_radix_ciphertext_slice_async<Torus>(
      stream, gpu_index, mem->extra_terms, num_blocks, 2 * num_blocks,
      mem->trivial_one, 0, num_blocks);

  host_mul_low_partial_sum<Torus>(streams, mem->term_sum, mem->quotient_tmp,
                                  denominator, mem->extra_terms, 2, false,
                                  mem->mul_low_mem, bsks, ksks);

  // Two copies of the sum, one per lookup: !message on the low half, !carry on
  // the high half.
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, mem->inverted, 0,
                                           num_blocks, mem->term_sum, 0,
                                           num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, mem->inverted,
                                           num_blocks, 2 * num_blocks,
                                           mem->term_sum, 0, num_blocks);
  host_apply_univariate_lut<Torus, KSTorus>(streams, mem->inverted,
                                            mem->inverted, mem->invert_lut,
                                            ksks, bsks);

  // C's blocks sit one position up; its lowest block is the complement of a
  // zero carry, i.e. message_modulus - 1.
  CudaRadixCiphertextFFI inverted_message, inverted_carry;
  as_radix_ciphertext_slice<Torus>(&inverted_message, mem->inverted, 0,
                                   num_blocks);
  as_radix_ciphertext_slice<Torus>(&inverted_carry, mem->inverted, num_blocks,
                                   2 * num_blocks);
  set_single_scalar_trivial_radix_ciphertext_async<Torus>(
      stream, gpu_index, mem->carry_shifted, params.message_modulus - 1,
      params.message_modulus, params.carry_modulus);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index,
                                           mem->carry_shifted, 1, num_blocks,
                                           &inverted_carry, 0, num_blocks - 1);

  // r = !M + !C + 2, summed through the column reduction rather than by plain
  // additions: three addends put up to 3 + 3 + 2 = 8 in the low block, i.e. a
  // carry of two, which a single-carry propagation cannot absorb. The reduction
  // brings every block back under 2 * (message_modulus - 1) first.
  //
  // The mul-low's term vector and column sum are both free at this point, and
  // sized far beyond three terms, so they are reused as is.
  CudaRadixCiphertextFFI remainder_terms;
  as_radix_ciphertext_slice<Torus>(&remainder_terms, mem->mul_low_mem->terms, 0,
                                   3 * num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, &remainder_terms,
                                           0, num_blocks, &inverted_message, 0,
                                           num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      stream, gpu_index, &remainder_terms, num_blocks, 2 * num_blocks,
      mem->carry_shifted, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      stream, gpu_index, &remainder_terms, 2 * num_blocks, 3 * num_blocks,
      mem->trivial_two, 0, num_blocks);
  host_integer_partial_sum_ciphertexts_vec<Torus>(
      streams, mem->remainder_tmp, mem->mul_low_mem->terms, bsks, ksks,
      mem->mul_low_mem->sum_mem, num_blocks, 3);
  host_propagate_single_carry<Torus>(streams, mem->remainder_tmp, nullptr,
                                     nullptr, mem->sc_prop_mem, bsks, ksks,
                                     outputFlag::FLAG_NONE, 0);

  // cmux_true = [q | r], cmux_false = [q + 1 | r - d]; the borrow out of
  // r - d is exactly "r did not reach d", i.e. q was already right.
  CudaRadixCiphertextFFI true_q, true_r, false_q, false_r;
  as_radix_ciphertext_slice<Torus>(&true_q, mem->cmux_true, 0, num_blocks);
  as_radix_ciphertext_slice<Torus>(&true_r, mem->cmux_true, num_blocks,
                                   2 * num_blocks);
  as_radix_ciphertext_slice<Torus>(&false_q, mem->cmux_false, 0, num_blocks);
  as_radix_ciphertext_slice<Torus>(&false_r, mem->cmux_false, num_blocks,
                                   2 * num_blocks);

  copy_radix_ciphertext_async<Torus>(stream, gpu_index, &true_q,
                                     mem->quotient_tmp);
  copy_radix_ciphertext_async<Torus>(stream, gpu_index, &true_r,
                                     mem->remainder_tmp);
  copy_radix_ciphertext_async<Torus>(stream, gpu_index, &false_q,
                                     mem->quotient_tmp);
  host_add_and_propagate_single_carry<Torus, KSTorus>(
      streams, &false_q, mem->trivial_one, nullptr, nullptr, mem->sc_prop_mem,
      bsks, ksks, outputFlag::FLAG_NONE, 0);
  host_integer_overflowing_sub<Torus>(
      streams, &false_r, mem->remainder_tmp, denominator, mem->overflow_block,
      nullptr, mem->borrow_mem, bsks, ksks, outputFlag::FLAG_OVERFLOW, 0);

  host_cmux<Torus, KSTorus>(streams, mem->cmux_result, mem->overflow_block,
                            mem->cmux_true, mem->cmux_false, mem->cmux_mem,
                            bsks, ksks);
  // TEMPORARY DEBUG: expose the uncorrected pair and the overflow flag.
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, quotient, 0,
                                           num_blocks, mem->quotient_tmp, 0,
                                           num_blocks);
  set_zero_radix_ciphertext_slice_async<Torus>(stream, gpu_index, remainder, 0,
                                               num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, remainder, 0, 1,
                                           mem->overflow_block, 0, 1);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, remainder, 1,
                                           num_blocks, mem->remainder_tmp, 0,
                                           num_blocks - 1);
  return;

  // Division by zero returns an all-ones quotient and the numerator, matching
  // the CPU backend's contract.
  copy_radix_ciphertext_async<Torus>(stream, gpu_index, &true_q,
                                     mem->trivial_max);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, &true_r, 0,
                                           num_blocks, numerator, 0,
                                           num_blocks);
  host_cmux<Torus, KSTorus>(streams, mem->cmux_false, mem->d_is_zero,
                            mem->cmux_true, mem->cmux_result, mem->cmux_mem,
                            bsks, ksks);

  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, quotient, 0,
                                           num_blocks, mem->cmux_false, 0,
                                           num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, remainder, 0,
                                           num_blocks, mem->cmux_false,
                                           num_blocks, 2 * num_blocks);
  POP_RANGE()
}

template <typename Torus>
__host__ void host_goldschmidt_division(
    CudaStreams streams, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, const CudaRadixCiphertextFFI *numerator,
    const CudaRadixCiphertextFFI *denominator,
    int_goldschmidt_division_buffer<Torus> *mem, uint32_t iterations,
    void *const *bsks, uint64_t *const *ksks) {
  PUSH_RANGE("goldschmidt division")
  uint32_t num_blocks = mem->num_blocks;
  PANIC_IF_FALSE(numerator->num_radix_blocks >= num_blocks &&
                     denominator->num_radix_blocks >= num_blocks,
                 "Cuda error (goldschmidt division): operands are narrower "
                 "than the shape this buffer was scratched for");
  PANIC_IF_FALSE(quotient->num_radix_blocks >= num_blocks &&
                     remainder->num_radix_blocks >= num_blocks,
                 "Cuda error (goldschmidt division): outputs are narrower "
                 "than the operands");

  goldschmidt_normalize<Torus, uint64_t>(streams, numerator, denominator, mem,
                                         bsks, ksks);
  goldschmidt_seed<Torus>(streams, mem, bsks, ksks);
  goldschmidt_iterations<Torus>(streams, mem, iterations, bsks, ksks);
  goldschmidt_finalize<Torus, uint64_t>(streams, quotient, remainder, numerator,
                                        denominator, mem, bsks, ksks);
  POP_RANGE()
}

template <typename Torus>
__host__ uint64_t scratch_cuda_goldschmidt_division(
    CudaStreams streams, int_goldschmidt_division_buffer<Torus> **mem_ptr,
    uint32_t num_blocks, uint32_t iterations, uint32_t lut_precision,
    int_radix_params params, bool allocate_gpu_memory) {
  PUSH_RANGE("scratch goldschmidt division")
  uint64_t size_tracker = 0;
  *mem_ptr = new int_goldschmidt_division_buffer<Torus>(
      streams, params, num_blocks, iterations, lut_precision,
      allocate_gpu_memory, size_tracker);
  POP_RANGE()
  return size_tracker;
}

#endif
