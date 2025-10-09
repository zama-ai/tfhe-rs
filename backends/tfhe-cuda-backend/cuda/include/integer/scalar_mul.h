#pragma once
#include "integer_utilities.h"
#include "scalar_shifts.h"

template <typename Torus> struct int_scalar_mul_buffer {
  int_radix_params params;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_buffer;
  int_sum_ciphertexts_vec_memory<Torus> *sum_ciphertexts_vec_mem;
  CudaRadixCiphertextFFI *preshifted_buffer;
  CudaRadixCiphertextFFI *all_shifted_buffer;
  int_sc_prop_memory<Torus> *sc_prop_mem;
  bool anticipated_buffers_drop;
  bool gpu_memory_allocated;
  uint32_t num_ciphertext_bits;

  int_scalar_mul_buffer(CudaStreams streams, int_radix_params params,
                        uint32_t num_radix_blocks, uint32_t num_scalar_bits,
                        bool allocate_gpu_memory, bool anticipated_buffer_drop,
                        uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    this->anticipated_buffers_drop = anticipated_buffer_drop;

    uint32_t msg_bits = (uint32_t)std::log2(params.message_modulus);
    num_ciphertext_bits = msg_bits * num_scalar_bits;

    //// Contains all shifted values of lhs for shift in range (0..msg_bits)
    //// The idea is that with these we can create all other shift that are
    /// in / range (0..total_bits) for free (block rotation)
    preshifted_buffer = new CudaRadixCiphertextFFI;
    uint64_t anticipated_drop_mem = 0;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), preshifted_buffer,
        msg_bits * num_radix_blocks, params.big_lwe_dimension,
        anticipated_drop_mem, allocate_gpu_memory);

    all_shifted_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), all_shifted_buffer,
        num_ciphertext_bits * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    if (num_ciphertext_bits * num_radix_blocks >= num_radix_blocks + 2)
      logical_scalar_shift_buffer = new int_logical_scalar_shift_buffer<Torus>(
          streams, LEFT_SHIFT, params, num_radix_blocks, allocate_gpu_memory,
          all_shifted_buffer, anticipated_drop_mem);
    else
      logical_scalar_shift_buffer = new int_logical_scalar_shift_buffer<Torus>(
          streams, LEFT_SHIFT, params, num_radix_blocks, allocate_gpu_memory,
          anticipated_drop_mem);

    uint64_t last_step_mem = 0;
    if (num_ciphertext_bits > 0) {
      sum_ciphertexts_vec_mem = new int_sum_ciphertexts_vec_memory<Torus>(
          streams, params, num_radix_blocks, num_ciphertext_bits, true,
          allocate_gpu_memory, last_step_mem);
    }
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, params, num_radix_blocks, requested_flag, allocate_gpu_memory,
        last_step_mem);
    if (anticipated_buffer_drop) {
      size_tracker += std::max(anticipated_drop_mem, last_step_mem);
    } else {
      size_tracker += anticipated_drop_mem + last_step_mem;
    }
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   all_shifted_buffer, gpu_memory_allocated);
    if (num_ciphertext_bits > 0) {
      sum_ciphertexts_vec_mem->release(streams);
      delete sum_ciphertexts_vec_mem;
    }
    sc_prop_mem->release(streams);
    delete sc_prop_mem;
    delete all_shifted_buffer;
    release_buffers(streams);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }

  void release_buffers(CudaStreams streams) {
    if (preshifted_buffer) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     preshifted_buffer, gpu_memory_allocated);
      delete preshifted_buffer;
      preshifted_buffer = nullptr;
    }

    if (logical_scalar_shift_buffer) {
      logical_scalar_shift_buffer->release(streams);
      delete logical_scalar_shift_buffer;
      logical_scalar_shift_buffer = nullptr;
    }
  }
};

template <typename Torus> struct int_scalar_mul_high_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem;

  CudaRadixCiphertextFFI *tmp;

  int_scalar_mul_high_buffer(CudaStreams streams, const int_radix_params params,
                             uint32_t num_radix_blocks,
                             uint32_t num_scalar_bits,
                             const bool allocate_gpu_memory,
                             uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
        streams, RIGHT_SHIFT, params, 2 * num_radix_blocks, allocate_gpu_memory,
        size_tracker);

    this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
        streams, params, 2 * num_radix_blocks, num_scalar_bits,
        allocate_gpu_memory, true, size_tracker);

    this->tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {

    logical_scalar_shift_mem->release(streams);
    delete logical_scalar_shift_mem;

    scalar_mul_mem->release(streams);
    delete scalar_mul_mem;
    scalar_mul_mem = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), tmp,
                                   allocate_gpu_memory);
    delete tmp;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_signed_scalar_mul_high_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem;
  int_extend_radix_with_sign_msb_buffer<Torus> *extend_radix_mem;

  CudaRadixCiphertextFFI *tmp;

  int_signed_scalar_mul_high_buffer(CudaStreams streams,
                                    const int_radix_params params,
                                    uint32_t num_radix_blocks,
                                    uint32_t num_scalar_bits,
                                    const bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
        streams, RIGHT_SHIFT, params, 2 * num_radix_blocks, allocate_gpu_memory,
        size_tracker);

    this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
        streams, params, 2 * num_radix_blocks, num_scalar_bits,
        allocate_gpu_memory, true, size_tracker);

    this->tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp, 2 * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->extend_radix_mem = new int_extend_radix_with_sign_msb_buffer<Torus>(
        streams, params, num_radix_blocks, num_radix_blocks,
        allocate_gpu_memory, size_tracker);
  }

  void release(CudaStreams streams) {

    logical_scalar_shift_mem->release(streams);
    delete logical_scalar_shift_mem;

    scalar_mul_mem->release(streams);
    delete scalar_mul_mem;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), tmp,
                                   allocate_gpu_memory);
    delete tmp;

    extend_radix_mem->release(streams);
    delete extend_radix_mem;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
