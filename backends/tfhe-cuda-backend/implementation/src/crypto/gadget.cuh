#ifndef CNCRT_CRYPTO_CUH
#define CNCRT_CRPYTO_CUH

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
  uint32_t halfbg;
  uint32_t num_poly;
  T offset;
  int current_level;
  T mask_mod_b;
  T *state;

public:
  __device__ GadgetMatrix(uint32_t base_log, uint32_t level_count, T *state,
                          uint32_t num_poly = 1)
      : base_log(base_log), level_count(level_count), num_poly(num_poly),
        state(state) {

    mask_mod_b = (1ll << base_log) - 1ll;
    current_level = level_count;
    int tid = threadIdx.x;
    for (int i = 0; i < num_poly * params::opt; i++) {
      state[tid] >>= (sizeof(T) * 8 - base_log * level_count);
      tid += params::degree / params::opt;
    }
    synchronize_threads_in_block();
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
    if (j == 0)
      current_level -= 1;

    int tid = threadIdx.x;
    auto state_slice = state + j * params::degree;
    for (int i = 0; i < params::opt / 2; i++) {
      T res_re = state_slice[tid] & mask_mod_b;
      T res_im = state_slice[tid + params::degree / 2] & mask_mod_b;
      state_slice[tid] >>= base_log;
      state_slice[tid + params::degree / 2] >>= base_log;
      T carry_re = ((res_re - 1ll) | state_slice[tid]) & res_re;
      T carry_im =
          ((res_im - 1ll) | state_slice[tid + params::degree / 2]) & res_im;
      carry_re >>= (base_log - 1);
      carry_im >>= (base_log - 1);
      state_slice[tid] += carry_re;
      state_slice[tid + params::degree / 2] += carry_im;
      res_re -= carry_re << base_log;
      res_im -= carry_im << base_log;

      result[tid].x = (int32_t)res_re;
      result[tid].y = (int32_t)res_im;

      tid += params::degree / params::opt;
    }
    synchronize_threads_in_block();
  }

  // Decomposes a single polynomial
  __device__ void
  decompose_and_compress_next_polynomial_elements(double2 *result, int j) {
    if (j == 0)
      current_level -= 1;

    int tid = threadIdx.x;
    auto state_slice = state + j * params::degree;
    for (int i = 0; i < params::opt / 2; i++) {
      T res_re = state_slice[tid] & mask_mod_b;
      T res_im = state_slice[tid + params::degree / 2] & mask_mod_b;
      state_slice[tid] >>= base_log;
      state_slice[tid + params::degree / 2] >>= base_log;
      T carry_re = ((res_re - 1ll) | state_slice[tid]) & res_re;
      T carry_im =
          ((res_im - 1ll) | state_slice[tid + params::degree / 2]) & res_im;
      carry_re >>= (base_log - 1);
      carry_im >>= (base_log - 1);
      state_slice[tid] += carry_re;
      state_slice[tid + params::degree / 2] += carry_im;
      res_re -= carry_re << base_log;
      res_im -= carry_im << base_log;

      result[i].x = (int32_t)res_re;
      result[i].y = (int32_t)res_im;

      tid += params::degree / params::opt;
    }
    synchronize_threads_in_block();
  }

  __device__ void decompose_and_compress_level(double2 *result, int level) {
    for (int i = 0; i < level_count - level; i++)
      decompose_and_compress_next(result);
  }
};

template <typename T> class GadgetMatrixSingle {
private:
  uint32_t level_count;
  uint32_t base_log;
  uint32_t mask;
  uint32_t halfbg;
  T offset;

public:
  __device__ GadgetMatrixSingle(uint32_t base_log, uint32_t level_count)
      : base_log(base_log), level_count(level_count) {
    uint32_t bg = 1 << base_log;
    this->halfbg = bg / 2;
    this->mask = bg - 1;
    T temp = 0;
    for (int i = 0; i < this->level_count; i++) {
      temp += 1ULL << (sizeof(T) * 8 - (i + 1) * this->base_log);
    }
    this->offset = temp * this->halfbg;
  }

  __device__ T decompose_one_level_single(T element, uint32_t level) {
    T s = element + this->offset;
    uint32_t decal = (sizeof(T) * 8 - (level + 1) * this->base_log);
    T temp1 = (s >> decal) & this->mask;
    return (T)(temp1 - this->halfbg);
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
