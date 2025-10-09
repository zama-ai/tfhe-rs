#pragma once
#include "bitwise_ops.h"
#include "cast.h"
#include "integer_utilities.h"
#include "scalar_mul.h"

template <typename Torus> struct int_unsigned_scalar_div_mem {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *tmp_ffi = nullptr;

  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem = nullptr;
  int_scalar_mul_high_buffer<Torus> *scalar_mul_high_mem = nullptr;
  int_sc_prop_memory<Torus> *scp_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem = nullptr;

  int_unsigned_scalar_div_mem(CudaStreams streams,
                              const int_radix_params params,
                              uint32_t num_radix_blocks,
                              const CudaScalarDivisorFFI *scalar_divisor_ffi,
                              const bool allocate_gpu_memory,
                              uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    if (!scalar_divisor_ffi->is_abs_divisor_one) {
      if (scalar_divisor_ffi->is_divisor_pow2) {

        logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
            streams, RIGHT_SHIFT, params, num_radix_blocks, allocate_gpu_memory,
            size_tracker);

      } else if (scalar_divisor_ffi->divisor_has_more_bits_than_numerator) {

        tmp_ffi = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      } else if (scalar_divisor_ffi
                     ->is_chosen_multiplier_geq_two_pow_numerator) {

        logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
            streams, RIGHT_SHIFT, params, num_radix_blocks, allocate_gpu_memory,
            size_tracker);
        scalar_mul_high_mem = new int_scalar_mul_high_buffer<Torus>(
            streams, params, num_radix_blocks, scalar_divisor_ffi->active_bits,
            allocate_gpu_memory, size_tracker);
        scp_mem = new int_sc_prop_memory<Torus>(
            streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
            size_tracker);
        sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
            streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
            size_tracker);
        tmp_ffi = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      } else {

        logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
            streams, RIGHT_SHIFT, params, num_radix_blocks, allocate_gpu_memory,
            size_tracker);
        scalar_mul_high_mem = new int_scalar_mul_high_buffer<Torus>(
            streams, params, num_radix_blocks, scalar_divisor_ffi->active_bits,
            allocate_gpu_memory, size_tracker);
      }
    }
  }

  void release(CudaStreams streams) {

    if (logical_scalar_shift_mem != nullptr) {
      logical_scalar_shift_mem->release(streams);
      delete logical_scalar_shift_mem;
    }
    if (scalar_mul_high_mem != nullptr) {
      scalar_mul_high_mem->release(streams);
      delete scalar_mul_high_mem;
    }
    if (scp_mem != nullptr) {
      scp_mem->release(streams);
      delete scp_mem;
    }
    if (sub_and_propagate_mem != nullptr) {
      sub_and_propagate_mem->release(streams);
      delete sub_and_propagate_mem;
    }
    if (tmp_ffi != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_ffi, allocate_gpu_memory);
      delete tmp_ffi;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_signed_scalar_div_mem {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *tmp_ffi = nullptr;
  CudaRadixCiphertextFFI *xsign_ffi = nullptr;

  int_arithmetic_scalar_shift_buffer<Torus> *arithmetic_scalar_shift_mem =
      nullptr;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem = nullptr;
  int_signed_scalar_mul_high_buffer<Torus> *scalar_mul_high_mem = nullptr;
  int_sc_prop_memory<Torus> *scp_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem = nullptr;

  int_signed_scalar_div_mem(CudaStreams streams, const int_radix_params params,
                            uint32_t num_radix_blocks,
                            const CudaScalarDivisorFFI *scalar_divisor_ffi,
                            const bool allocate_gpu_memory,
                            uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    if (!scalar_divisor_ffi->chosen_multiplier_has_more_bits_than_numerator) {

      if (scalar_divisor_ffi->is_abs_divisor_one &&
          scalar_divisor_ffi->is_divisor_negative) {
        tmp_ffi = new CudaRadixCiphertextFFI;

        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      } else if (!scalar_divisor_ffi->is_abs_divisor_one) {

        tmp_ffi = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), tmp_ffi, num_radix_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

        arithmetic_scalar_shift_mem =
            new int_arithmetic_scalar_shift_buffer<Torus>(
                streams, RIGHT_SHIFT, params, num_radix_blocks,
                allocate_gpu_memory, size_tracker);

        if (scalar_divisor_ffi->is_divisor_pow2) {

          logical_scalar_shift_mem = new int_logical_scalar_shift_buffer<Torus>(
              streams, RIGHT_SHIFT, params, num_radix_blocks,
              allocate_gpu_memory, size_tracker);
          scp_mem = new int_sc_prop_memory<Torus>(
              streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
              size_tracker);

        } else {

          xsign_ffi = new CudaRadixCiphertextFFI;
          create_zero_radix_ciphertext_async<Torus>(
              streams.stream(0), streams.gpu_index(0), xsign_ffi,
              num_radix_blocks, params.big_lwe_dimension, size_tracker,
              allocate_gpu_memory);

          scalar_mul_high_mem = new int_signed_scalar_mul_high_buffer<Torus>(
              streams, params, num_radix_blocks,
              scalar_divisor_ffi->active_bits, allocate_gpu_memory,
              size_tracker);

          sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
              streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
              size_tracker);

          if (scalar_divisor_ffi->is_chosen_multiplier_geq_two_pow_numerator) {
            scp_mem = new int_sc_prop_memory<Torus>(
                streams, params, num_radix_blocks, FLAG_NONE,
                allocate_gpu_memory, size_tracker);
          }
        }
      }
    }
  }

  void release(CudaStreams streams) {

    if (arithmetic_scalar_shift_mem != nullptr) {
      arithmetic_scalar_shift_mem->release(streams);
      delete arithmetic_scalar_shift_mem;
    }
    if (logical_scalar_shift_mem != nullptr) {
      logical_scalar_shift_mem->release(streams);
      delete logical_scalar_shift_mem;
    }
    if (scalar_mul_high_mem != nullptr) {
      scalar_mul_high_mem->release(streams);
      delete scalar_mul_high_mem;
    }
    if (scp_mem != nullptr) {
      scp_mem->release(streams);
      delete scp_mem;
    }
    if (sub_and_propagate_mem != nullptr) {
      sub_and_propagate_mem->release(streams);
      delete sub_and_propagate_mem;
    }
    if (tmp_ffi != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_ffi, allocate_gpu_memory);
      delete tmp_ffi;
    }
    if (xsign_ffi != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     xsign_ffi, allocate_gpu_memory);
      delete xsign_ffi;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unsigned_scalar_div_rem_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *numerator_ct;

  int_unsigned_scalar_div_mem<Torus> *unsigned_div_mem;
  int_bitop_buffer<Torus> *bitop_mem = nullptr;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem = nullptr;

  int_unsigned_scalar_div_rem_buffer(
      CudaStreams streams, const int_radix_params params,
      uint32_t num_radix_blocks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
      uint32_t const active_bits_divisor, const bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->numerator_ct = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), numerator_ct, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->unsigned_div_mem = new int_unsigned_scalar_div_mem<Torus>(
        streams, params, num_radix_blocks, scalar_divisor_ffi,
        allocate_gpu_memory, size_tracker);

    if (scalar_divisor_ffi->is_divisor_pow2) {
      this->bitop_mem = new int_bitop_buffer<Torus>(
          streams, SCALAR_BITAND, params, num_radix_blocks, allocate_gpu_memory,
          size_tracker);
    } else {
      if (!scalar_divisor_ffi->is_divisor_zero &&
          !scalar_divisor_ffi->is_abs_divisor_one && num_radix_blocks != 0) {
        this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
            streams, params, num_radix_blocks, active_bits_divisor,
            allocate_gpu_memory, true, size_tracker);
      }
      this->sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
          streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
          size_tracker);
    }
  }

  void release(CudaStreams streams) {

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   numerator_ct, allocate_gpu_memory);
    delete numerator_ct;

    unsigned_div_mem->release(streams);
    delete unsigned_div_mem;

    if (bitop_mem != nullptr) {
      bitop_mem->release(streams);
      delete bitop_mem;
    }
    if (scalar_mul_mem != nullptr) {
      scalar_mul_mem->release(streams);
      delete scalar_mul_mem;
    }
    if (sub_and_propagate_mem != nullptr) {
      sub_and_propagate_mem->release(streams);
      delete sub_and_propagate_mem;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_signed_scalar_div_rem_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *numerator_ct;

  int_signed_scalar_div_mem<Torus> *signed_div_mem;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_mem = nullptr;
  int_scalar_mul_buffer<Torus> *scalar_mul_mem = nullptr;
  int_sub_and_propagate<Torus> *sub_and_propagate_mem;
  int_sc_prop_memory<Torus> *scp_mem;

  int_signed_scalar_div_rem_buffer(
      CudaStreams streams, const int_radix_params params,
      uint32_t num_radix_blocks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
      uint32_t const active_bits_divisor, const bool allocate_gpu_memory,
      uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->numerator_ct = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), numerator_ct, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->signed_div_mem = new int_signed_scalar_div_mem<Torus>(
        streams, params, num_radix_blocks, scalar_divisor_ffi,
        allocate_gpu_memory, size_tracker);

    this->scp_mem = new int_sc_prop_memory<Torus>(
        streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker);

    bool is_divisor_one = scalar_divisor_ffi->is_abs_divisor_one &&
                          !scalar_divisor_ffi->is_divisor_negative;

    if (!scalar_divisor_ffi->is_divisor_negative &&
        scalar_divisor_ffi->is_divisor_pow2) {
      this->logical_scalar_shift_mem =
          new int_logical_scalar_shift_buffer<Torus>(
              streams, LEFT_SHIFT, params, num_radix_blocks,
              allocate_gpu_memory, size_tracker);

    } else if (!scalar_divisor_ffi->is_divisor_zero && !is_divisor_one &&
               num_radix_blocks != 0) {
      this->scalar_mul_mem = new int_scalar_mul_buffer<Torus>(
          streams, params, num_radix_blocks, active_bits_divisor,
          allocate_gpu_memory, true, size_tracker);
    }

    this->sub_and_propagate_mem = new int_sub_and_propagate<Torus>(
        streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   numerator_ct, allocate_gpu_memory);
    delete numerator_ct;
    numerator_ct = nullptr;

    signed_div_mem->release(streams);
    delete signed_div_mem;
    signed_div_mem = nullptr;

    scp_mem->release(streams);
    delete scp_mem;
    scp_mem = nullptr;

    if (logical_scalar_shift_mem != nullptr) {
      logical_scalar_shift_mem->release(streams);
      delete logical_scalar_shift_mem;
      logical_scalar_shift_mem = nullptr;
    }
    if (scalar_mul_mem != nullptr) {
      scalar_mul_mem->release(streams);
      delete scalar_mul_mem;
      scalar_mul_mem = nullptr;
    }
    sub_and_propagate_mem->release(streams);
    delete sub_and_propagate_mem;
    sub_and_propagate_mem = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
