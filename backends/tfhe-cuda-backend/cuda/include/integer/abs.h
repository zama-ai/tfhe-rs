#pragma once
#include "bitwise_ops.h"
#include "integer_utilities.h"
#include "scalar_shifts.h"

template <typename Torus> struct int_abs_buffer {
  int_radix_params params;

  int_arithmetic_scalar_shift_buffer<Torus> *arithmetic_scalar_shift_mem;
  int_sc_prop_memory<Torus> *scp_mem;
  int_bitop_buffer<Torus> *bitxor_mem;

  CudaRadixCiphertextFFI *mask;
  bool allocate_gpu_memory;

  int_abs_buffer(CudaStreams streams, int_radix_params params,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory,
                 uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    arithmetic_scalar_shift_mem = new int_arithmetic_scalar_shift_buffer<Torus>(
        streams, SHIFT_OR_ROTATE_TYPE::RIGHT_SHIFT, params, num_radix_blocks,
        allocate_gpu_memory, size_tracker);
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    scp_mem = new int_sc_prop_memory<Torus>(streams, params, num_radix_blocks,
                                            requested_flag, allocate_gpu_memory,
                                            size_tracker);
    bitxor_mem = new int_bitop_buffer<Torus>(streams, BITOP_TYPE::BITXOR,
                                             params, num_radix_blocks,
                                             allocate_gpu_memory, size_tracker);

    mask = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mask, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    arithmetic_scalar_shift_mem->release(streams);
    scp_mem->release(streams);
    bitxor_mem->release(streams);

    delete arithmetic_scalar_shift_mem;
    delete scp_mem;
    delete bitxor_mem;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   mask, this->allocate_gpu_memory);
    delete mask;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
