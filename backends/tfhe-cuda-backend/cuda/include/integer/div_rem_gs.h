#pragma once

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

template <typename Torus>
struct int_goldschmidt_division_buffer
{
    int_radix_params params;
    bool allocate_gpu_memory;
    uint32_t num_radix_blocks;
    uint32_t lut_precision;
    uint32_t intermediate_num_blocks;

    int_count_of_consecutive_bits_buffer<Torus> *count_leading_zeros_buffer;
    int_comparison_buffer<Torus> *is_denominator_zero_buffer;
    Torus *d_zero_scalar;

    CudaRadixCiphertextFFI *full_precision_product_buffer;
    CudaRadixCiphertextFFI *padded_lhs_operand;
    int_shift_and_rotate_buffer<Torus> *normalize_batched_shift_buffer;
    CudaRadixCiphertextFFI *current_numerator_Ni;
    CudaRadixCiphertextFFI *current_denominator_Di;

    CudaStreams sub_streams_1;

    int_goldschmidt_division_buffer(CudaStreams streams, int_radix_params params,
                                    uint32_t num_radix_blocks,
                                    uint32_t lut_precision,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker)
    {
        uint64_t prev_size = size_tracker;
        auto print_mem_usage = [&](const char *step_name)
        {
            uint64_t diff = size_tracker - prev_size;
            if (diff > 0)
            {
                printf("[Mem Profiling] %s : %llu bytes\n", step_name,
                       (unsigned long long)diff);
            }
            prev_size = size_tracker;
        };

        auto active_streams =
            streams.active_gpu_subset(2 * num_radix_blocks, params.pbs_type);
        sub_streams_1.create_on_same_gpus(active_streams);
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
        // print_mem_usage("Init Params (No alloc)");

        PUSH_RANGE("Goldschmidt Setup: count_leading_zeros");
        count_leading_zeros_buffer =
            new int_count_of_consecutive_bits_buffer<Torus>(
                streams, params, num_radix_blocks, num_radix_blocks, (Direction)1,
                (BitValue)0, allocate_gpu_memory, size_tracker);
        POP_RANGE();
        // print_mem_usage("count_leading_zeros_buffer");

        PUSH_RANGE("Goldschmidt Setup: is_denominator_zero");
        is_denominator_zero_buffer = new int_comparison_buffer<Torus>(
            streams, COMPARISON_TYPE::EQ, params, num_radix_blocks, false,
            allocate_gpu_memory, size_tracker);
        POP_RANGE();
        // print_mem_usage("is_denominator_zero_buffer");

        PUSH_RANGE("Goldschmidt Setup: d_zero_scalar");
        d_zero_scalar = (Torus *)cuda_malloc_with_size_tracking_async(
            num_radix_blocks * sizeof(Torus), streams.stream(0),
            streams.gpu_index(0), size_tracker, allocate_gpu_memory);
        if (allocate_gpu_memory)
        {
            cuda_memset_async(d_zero_scalar, 0, num_radix_blocks * sizeof(Torus),
                              streams.stream(0), streams.gpu_index(0));
        }
        POP_RANGE();

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
        normalize_batched_shift_buffer = new int_shift_and_rotate_buffer<Torus>(
            streams, LEFT_SHIFT, false, params, 3 * num_radix_blocks,
            allocate_gpu_memory, size_tracker);
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
    }

    void release(CudaStreams streams)
    {
        PUSH_RANGE("Release: clz");
        count_leading_zeros_buffer->release(streams);
        delete count_leading_zeros_buffer;
        POP_RANGE();

        PUSH_RANGE("Release: is_denom_zero");
        is_denominator_zero_buffer->release(streams);
        delete is_denominator_zero_buffer;
        POP_RANGE();

        PUSH_RANGE("Release: d_zero_scalar");
        if (allocate_gpu_memory)
            cuda_drop_async(d_zero_scalar, streams.stream(0), streams.gpu_index(0));
        POP_RANGE();

        release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                       full_precision_product_buffer,
                                       allocate_gpu_memory);
        delete full_precision_product_buffer;
        release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                       padded_lhs_operand, allocate_gpu_memory);
        delete padded_lhs_operand;
        normalize_batched_shift_buffer->release(streams);
        delete normalize_batched_shift_buffer;
        release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                       current_numerator_Ni, allocate_gpu_memory);
        delete current_numerator_Ni;
        release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                       current_denominator_Di, allocate_gpu_memory);
        delete current_denominator_Di;

        sub_streams_1.release();
    }
};