#pragma once

#include "integer/cmux.cuh"
#include "integer/div_rem_gs.h"
#include "integer/ilog2.cuh"
#include "integer/integer.cuh"
#include "integer/multiplication.cuh"
#include "integer/negation.cuh"
#include "integer/scalar_comparison.cuh"
#include "integer/subtraction.cuh"
#include "integer/vector_find.cuh"
#include "radix_ciphertext.cuh"

// Resizes and shifts a ciphertext array by a specified number of blocks, either
// left or right. output = input * (radix ^ shift)
//
template <typename Torus>
__host__ void
blockshift_resize(CudaStreams streams, CudaRadixCiphertextFFI *output,
                  const CudaRadixCiphertextFFI *input, int32_t shift)
{
    uint32_t new_size = output->num_radix_blocks;
    uint32_t input_size = input->num_radix_blocks;

    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output, 0, new_size);

    if (shift >= 0)
    {
        uint32_t u_shift = (uint32_t)shift;
        if (u_shift < new_size)
        {
            uint32_t space_available = new_size - u_shift;
            uint32_t blocks_to_copy = std::min(input_size, space_available);
            if (blocks_to_copy > 0)
            {
                copy_radix_ciphertext_slice_async<Torus>(
                    streams.stream(0), streams.gpu_index(0), output, u_shift,
                    u_shift + blocks_to_copy, input, 0, blocks_to_copy);
            }
        }
    }
    else
    {
        uint32_t abs_shift = (uint32_t)(-shift);
        if (abs_shift < input_size)
        {
            uint32_t source_blocks_avail = input_size - abs_shift;
            uint32_t blocks_to_copy = std::min(source_blocks_avail, new_size);
            if (blocks_to_copy > 0)
            {
                copy_radix_ciphertext_slice_async<Torus>(
                    streams.stream(0), streams.gpu_index(0), output, 0, blocks_to_copy,
                    input, abs_shift, abs_shift + blocks_to_copy);
            }
        }
    }
}

template <typename Torus, typename KSTorus>
__host__ void goldschmidt_normalize(CudaStreams streams,
                                    CudaRadixCiphertextFFI *d_is_zero,
                                    CudaRadixCiphertextFFI *leading_zeros_count,
                                    const CudaRadixCiphertextFFI *numerator,
                                    const CudaRadixCiphertextFFI *denominator,
                                    int_goldschmidt_division_buffer<Torus> *mem,
                                    void *const *bsks, KSTorus *const *ksks)
{

    // printf("goldschmidt_normalize: num_blocks=%d, intermediate_num_blocks=%d\n",
    //        numerator->num_radix_blocks, mem->intermediate_num_blocks);
    uint32_t num_blocks = numerator->num_radix_blocks;
    uint32_t intermediate_num_blocks = mem->intermediate_num_blocks;
    uint32_t batched_size = 3 * num_blocks;

    CudaRadixCiphertextFFI batched_nd;
    as_radix_ciphertext_slice<Torus>(
        &batched_nd, mem->full_precision_product_buffer, 0, batched_size);

    CudaRadixCiphertextFFI batched_d_view, batched_n_view;
    as_radix_ciphertext_slice<Torus>(&batched_d_view, &batched_nd, 0, num_blocks);
    as_radix_ciphertext_slice<Torus>(&batched_n_view, &batched_nd, num_blocks,
                                     batched_size);

    CudaRadixCiphertextFFI padded_leading_zeros_count;
    as_radix_ciphertext_slice<Torus>(&padded_leading_zeros_count,
                                     mem->padded_lhs_operand, 0, batched_size);

    host_integer_count_of_consecutive_bits<Torus, KSTorus>(
        streams, leading_zeros_count, denominator,
        mem->count_leading_zeros_buffer, bsks, ksks); // paral

    host_scalar_equality_check<Torus, KSTorus>(
        mem->sub_streams_1, d_is_zero, denominator, mem->d_zero_scalar,
        mem->is_denominator_zero_buffer, bsks, ksks, num_blocks,
        num_blocks); // paral

    blockshift_resize<Torus>(streams, &batched_d_view, denominator, 0); // kernel
    blockshift_resize<Torus>(streams, &batched_n_view, numerator, 0);

    blockshift_resize<Torus>(streams, &padded_leading_zeros_count,
                             leading_zeros_count, 0);

    host_shift_and_rotate_inplace<Torus, KSTorus>(
        streams, &batched_nd, &padded_leading_zeros_count,
        mem->normalize_batched_shift_buffer, bsks, ksks);

    int32_t d_shift_amount =
        (int32_t)intermediate_num_blocks - (int32_t)num_blocks;
    blockshift_resize<Torus>(streams, mem->current_denominator_Di,
                             &batched_d_view, d_shift_amount);

    int32_t n_shift_amount =
        (int32_t)intermediate_num_blocks - 2 * (int32_t)num_blocks;
    blockshift_resize<Torus>(streams, mem->current_numerator_Ni, &batched_n_view,
                             n_shift_amount);
}

// High-level host function that orchestrates the entire Goldschmidt division
// algorithm.
//
// 1. Normalize N and D by shifting out leading zeros so D's MSB is 1.
// 2. Fetch an initial approximation X0 ~ 1/D using a LUT, then compute N1 =
// N*X0 and D1 = D*X0.
// 3. Iteratively compute correction factors Xi = 2 - Di, updating N and D until
// D converges to 1 and N to the quotient.
// 4. Finalize by extracting the integer quotient Q, computing remainder R = N -
// Q*D, and applying corrections for negative remainders or division by zero. Q,
// R = N / D
//
template <typename Torus, class params>
__host__ void host_goldschmidt_division(
    CudaStreams streams, CudaRadixCiphertextFFI *quotient_out,
    CudaRadixCiphertextFFI *remainder_out,
    const CudaRadixCiphertextFFI *numerator,
    const CudaRadixCiphertextFFI *denominator,
    int_goldschmidt_division_buffer<Torus> *mem, uint32_t iterations,
    uint32_t lut_precision, void *const *bsks, uint64_t *const *ksks)
{
    CudaRadixCiphertextFFI leading_zeros_count;
    as_radix_ciphertext_slice<Torus>(
        &leading_zeros_count,
        mem->count_leading_zeros_buffer->prepare_mem->tmp_ct, 0,
        mem->count_leading_zeros_buffer->counter_num_blocks);

    // printf("counter_num_blocks=%d\n",
    //        mem->count_leading_zeros_buffer->counter_num_blocks);
    CudaRadixCiphertextFFI d_is_zero;
    as_radix_ciphertext_slice<Torus>(
        &d_is_zero, mem->is_denominator_zero_buffer->tmp_lwe_array_out, 0, 1);

    // printf("numerator->num_radix_blocks=%d, denominator->num_radix_blocks=%d\n",
    //        numerator->num_radix_blocks, denominator->num_radix_blocks);
    // printf("leading_zeros_count.num_radix_blocks=%d\n",
    //        leading_zeros_count.num_radix_blocks);
    // printf("d_is_zero.num_radix_blocks=%d\n", d_is_zero.num_radix_blocks);

    PUSH_RANGE("goldschmidt_normalize")
    goldschmidt_normalize<Torus, uint64_t>(streams, &d_is_zero,
                                           &leading_zeros_count, numerator,
                                           denominator, mem, bsks, ksks);
    POP_RANGE()
}