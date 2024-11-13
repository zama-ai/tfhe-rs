#ifndef CNCRT_CRYPTO_CUH
#define CNCRT_CRPYTO_CUH

#include "crypto/torus.cuh"
#include "device.h"
#include <cstdint>

/**
 * GadgetMatrix implements the iterator design pattern to decompose a set of
 * num_poly consecutive polynomials with degree params::degree. A total of
 * level_count levels is expected and each call to decompose_and_compress_next()
 * writes to the result the next level. It is also possible to advance an
 * arbitrary amount of levels by using decompose_and_compress_level().
 *
 * This class always decomposes the entire set of num_poly polynomials.
 * By default, it works on a single polynomial.
 */
#pragma once
template <typename T, class params> class GadgetMatrix {
private:
  uint32_t level_count;
  uint32_t base_log;
  uint32_t mask;
  uint32_t num_poly;
  T mask_mod_b;
  T *state;

public:
  __device__ GadgetMatrix(uint32_t base_log, uint32_t level_count, T *state,
                          uint32_t num_poly = 1)
      : base_log(base_log), level_count(level_count), num_poly(num_poly),
        state(state) {

    mask_mod_b = (1ll << base_log) - 1ll;
  }

  // Decomposes all polynomials at once
  __device__ void decompose_and_compress_next(double2 *result) {
    for (int j = 0; j < num_poly; j++) {
      auto result_slice = result + j * params::degree / 2;
      decompose_and_compress_next_polynomial(result_slice, j);
    }
  }

  // Decomposes a single polynomial
  __device__ void decompose_and_compress_next_polynomial(double2 *result,
                                                         int j) {
    uint32_t tid = threadIdx.x;
    auto state_slice = &state[j * params::degree];
    for (int i = 0; i < params::opt / 2; i++) {
      auto input1 = &state_slice[tid];
      auto input2 = &state_slice[tid + params::degree / 2];
      T res_re = *input1 & mask_mod_b;
      T res_im = *input2 & mask_mod_b;

      *input1 >>= base_log; // Update state
      *input2 >>= base_log; // Update state

      T carry_re = ((res_re - 1ll) | *input1) & res_re;
      T carry_im = ((res_im - 1ll) | *input2) & res_im;
      carry_re >>= (base_log - 1);
      carry_im >>= (base_log - 1);

      *input1 += carry_re; // Update state
      *input2 += carry_im; // Update state

      res_re -= carry_re << base_log;
      res_im -= carry_im << base_log;

      typecast_torus_to_double(res_re, result[tid].x);
      typecast_torus_to_double(res_im, result[tid].y);

      tid += params::degree / params::opt;
    }
    synchronize_threads_in_block();
  }

  __device__ void decompose_and_compress_level(double2 *result, int level) {
    for (int i = 0; i < level_count - level; i++)
      decompose_and_compress_next(result);
  }
};

template <typename Torus>
__device__ Torus decompose_one(Torus &state, Torus mask_mod_b, int base_log) {
  Torus res = state & mask_mod_b;
  state >>= base_log;
  Torus carry = ((res - 1ll) | state) & res;
  carry >>= base_log - 1;
  state += carry;
  res -= carry << base_log;
  return res;
}

#endif // CNCRT_CRPYTO_H
