#pragma once
#include "crypto/torus.cuh"
#include "device.h"
#include "fft128/f128.cuh"

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

// Define explicitly an arithmetic shift right with a cast to signed
template <typename T> __device__ T signed_shift_right(T value, int base_log) {
  if constexpr (sizeof(T) == 4) {
    return static_cast<T>(static_cast<int32_t>(value) >> base_log);
  } else if constexpr (sizeof(T) == 8) {
    return static_cast<T>(static_cast<int64_t>(value) >> base_log);
  } else if constexpr (sizeof(T) == 16) {
    return static_cast<T>(static_cast<__int128_t>(value) >> base_log);
  } else {
    return value >> base_log; // fallback for unusual sizes
  }
}

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

  __device__ void decompose_and_compress_next_128(double *result) {
    for (int j = 0; j < num_poly; j++) {
      auto result_slice = result + j * params::degree / 2 * 4;
      decompose_and_compress_next_polynomial_128(result_slice, j);
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

      *input1 = signed_shift_right<T>(*input1, base_log); // Update state
      *input2 = signed_shift_right<T>(*input2, base_log); // Update state

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
    __syncthreads();
  }

  // Decomposes a single polynomial
  __device__ void decompose_and_compress_next_polynomial_128(double *result,
                                                             int j) {
    uint32_t tid = threadIdx.x;
    auto state_slice = &state[j * params::degree];
    for (int i = 0; i < params::opt / 2; i++) {
      auto input1 = &state_slice[tid];
      auto input2 = &state_slice[tid + params::degree / 2];
      T res_re = *input1 & mask_mod_b;
      T res_im = *input2 & mask_mod_b;

      *input1 = signed_shift_right<T>(*input1, base_log);
      *input2 = signed_shift_right<T>(*input2, base_log);

      T carry_re = ((res_re - 1ll) | *input1) & res_re;
      T carry_im = ((res_im - 1ll) | *input2) & res_im;
      carry_re >>= (base_log - 1);
      carry_im >>= (base_log - 1);

      *input1 += carry_re; // Update state
      *input2 += carry_im; // Update state

      res_re -= carry_re << base_log;
      res_im -= carry_im << base_log;

      auto out_re = u128_to_signed_to_f128(res_re);
      auto out_im = u128_to_signed_to_f128(res_im);

      auto out_re_hi = result + 0 * params::degree / 2;
      auto out_re_lo = result + 1 * params::degree / 2;
      auto out_im_hi = result + 2 * params::degree / 2;
      auto out_im_lo = result + 3 * params::degree / 2;

      out_re_hi[tid] = out_re.hi;
      out_re_lo[tid] = out_re.lo;
      out_im_hi[tid] = out_im.hi;
      out_im_lo[tid] = out_im.lo;

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  __device__ void decompose_and_compress_level(double2 *result, int level) {
    for (int i = 0; i < level_count - level; i++)
      decompose_and_compress_next(result);
  }

  __device__ void decompose_and_compress_level_128(double *result, int level) {
    for (int i = 0; i < level_count - level; i++)
      decompose_and_compress_next_128(result);
  }
};

// Performs the decomposition for 2_2 params, assumes level_count = 1
// this specialized version it is needed if we plan to keep everything in regs
template <typename T, class params, uint32_t base_log>
__device__ void decompose_and_compress_level_2_2_params(double2 *result,
                                                        T *state) {
  constexpr T mask_mod_b = (1ll << base_log) - 1ll;
  for (int i = 0; i < params::opt / 2; i++) {
    auto input1 = state[i];
    auto input2 = state[i + params::opt / 2];
    T res_re = input1 & mask_mod_b;
    T res_im = input2 & mask_mod_b;

    input1 = signed_shift_right<T>(input1, base_log); // Update state
    input2 = signed_shift_right<T>(input2, base_log); // Update state

    T carry_re = ((res_re - 1ll) | input1) & res_re;
    T carry_im = ((res_im - 1ll) | input2) & res_im;
    carry_re >>= (base_log - 1);
    carry_im >>= (base_log - 1);

    res_re -= carry_re << base_log;
    res_im -= carry_im << base_log;

    typecast_torus_to_double(res_re, result[i].x);
    typecast_torus_to_double(res_im, result[i].y);
  }
}

template <typename Torus>
__device__ Torus decompose_one(Torus &state, Torus mask_mod_b, int base_log) {
  Torus res = state & mask_mod_b;
  state = signed_shift_right<Torus>(state, base_log);

  Torus carry = ((res - 1ll) | state) & res;
  carry >>= base_log - 1;
  state += carry;
  res -= carry << base_log;
  return res;
}

// Level `level` of the Fourier buffers a block publishes, given the base of the
// first one.
template <class params>
__device__ __forceinline__ double *get_current_fft_level(double *fft,
                                                         uint32_t level) {
  return fft + (ptrdiff_t)level * (params::degree / 2 * 4);
}

// ACC * (X^j - 1) at one coefficient, followed by the decomposer rounding.
// Together these are multiply_by_monomial_negacyclic_and_sub_polynomial_in_regs
// and init_decomposer_state_inplace_2_2_params, taken one coefficient at a time
// so the rotated accumulator never lands in an array.
template <typename T, class params, uint32_t base_log, uint32_t level_count>
__device__ __forceinline__ T rotated_decomposer_state_128(const T *accumulator,
                                                          int position, int jj,
                                                          bool flip) {
  constexpr int degree = params::degree;
  const int t = position - jj;
  const T sv = accumulator[t & (degree - 1)];
  const T cv = accumulator[position];
  const bool neg = (bool)((t >> 31) & 1) ^ flip;
  const T st = neg ? (T)0 - sv - cv : sv - cv;
  return init_decomposer_state_2_2_params<T, base_log, level_count>(st);
}

// First level of the decomposition, taken while the state is still full width.
// Returns the balanced digit and narrows the state to base_log *
// (level_count - 1) bits in `next`. Truncating after the shift is exact: the
// value is sign-extended, so its low word already carries the sign.
template <typename T, uint32_t base_log>
__device__ __forceinline__ uint64_t
decompose_first_level_and_narrow_128(T st, uint64_t &next) {
  constexpr uint64_t mask_mod_b = (1ull << base_log) - 1ull;
  uint64_t res = (uint64_t)st & mask_mod_b;
  const uint64_t shifted = (uint64_t)signed_shift_right<T>(st, base_log);
  uint64_t carry = ((res - 1ull) | shifted) & res;
  carry >>= (base_log - 1);
  next = shifted + carry;
  return res - (carry << base_log);
}

// Rotation, decomposer init and the first decomposition level in one pass over
// the accumulator, writing the digits of level level_count - 1 to `result` and
// leaving the narrowed state in `state`.
//
// Fused so the first level is taken while the state is still 128-bit the next
// levels are calculated using only 64-bit cause the decomposition frees half of
// them.
//
// Iterates pairs because coefficients i and i + opt/2 share one packed output
// slot; they sit exactly degree/2 apart.
template <typename T, class params, uint32_t base_log, uint32_t level_count>
__device__ void
rotate_and_decompose_first_level_128(double *result, uint64_t *state,
                                     const T *accumulator, uint32_t j) {
  constexpr int degree = params::degree;
  constexpr int half_degree = degree / 2;
  static_assert(base_log <= 52, "a decomposition digit must fit in 53 bits for "
                                "small_signed_to_f128 to be exact");

  const int jj = (int)(j & (uint32_t)(degree - 1));
  const bool flip = j >= (uint32_t)degree;

  auto out_re_hi = result + 0 * half_degree;
  auto out_re_lo = result + 1 * half_degree;
  auto out_im_hi = result + 2 * half_degree;
  auto out_im_lo = result + 3 * half_degree;

  uint32_t tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    const int j_idx = i + params::opt / 2;
    const T st_re =
        rotated_decomposer_state_128<T, params, base_log, level_count>(
            accumulator, (int)tid, jj, flip);
    const T st_im =
        rotated_decomposer_state_128<T, params, base_log, level_count>(
            accumulator, (int)tid + half_degree, jj, flip);

    const uint64_t res_re =
        decompose_first_level_and_narrow_128<T, base_log>(st_re, state[i]);
    const uint64_t res_im =
        decompose_first_level_and_narrow_128<T, base_log>(st_im, state[j_idx]);

    const auto out_re = small_signed_to_f128((__uint128_t)res_re);
    const auto out_im = small_signed_to_f128((__uint128_t)res_im);
    out_re_hi[tid] = out_re.hi;
    out_re_lo[tid] = out_re.lo;
    out_im_hi[tid] = out_im.hi;
    out_im_lo[tid] = out_im.lo;

    tid += params::degree / params::opt;
  }
}

// Follows the same logic than 2_2 params decomposition but for 128-bit
// we require the level loop. The main difference with the non-tbc version
// is that that this uses the states in registers and all the level calculations
// are done in registers as well, shared memory writing is only done once at
// the end of the function.
//
// One level of the gadget decomposition, walking a NARROW decomposer state.
//
// init_decomposer_state leaves exactly base_log * level_count significant bits
// (72 at the noise-squashing shape). The caller consumes the first level while
// the __uint128_t state is still live -- that shift drops the state to
// base_log * (level_count - 1) bits (48), which fits a single uint64_t -- so by
// the time this runs the state is one plain word per coefficient and every walk
// is uniform. There is no high word and no first-level special case here.
//
// The state is unsigned storage holding a signed value: signed_shift_right
// supplies the arithmetic shift, and small_signed_to_f128 the signed
// reinterpretation of the digit. The digit is a balanced residue that fits 53
// bits, so it converts with a single signed cast and an exact zero lo limb.
// This is needed to release the register pressure.
template <class params, uint32_t base_log>
__device__ void decompose_and_compress_one_level_narrow_128(double *result,
                                                            uint64_t *state) {
  constexpr uint64_t mask_mod_b = (1ull << base_log) - 1ull;
  static_assert(base_log <= 52, "a decomposition digit must fit in 53 bits for "
                                "small_signed_to_f128 to be exact");

  uint32_t tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    const int j = i + params::opt / 2;
    uint64_t in_re = state[i], in_im = state[j];
    uint64_t res_re = in_re & mask_mod_b;
    uint64_t res_im = in_im & mask_mod_b;

    in_re = signed_shift_right<uint64_t>(in_re, base_log);
    in_im = signed_shift_right<uint64_t>(in_im, base_log);

    uint64_t carry_re = ((res_re - 1ull) | in_re) & res_re;
    uint64_t carry_im = ((res_im - 1ull) | in_im) & res_im;
    carry_re >>= (base_log - 1);
    carry_im >>= (base_log - 1);

    state[i] = in_re + carry_re; // Update state
    state[j] = in_im + carry_im; // Update state

    res_re -= carry_re << base_log;
    res_im -= carry_im << base_log;

    auto out_re = small_signed_to_f128((__uint128_t)res_re);
    auto out_im = small_signed_to_f128((__uint128_t)res_im);

    auto out_re_hi = result + 0 * params::degree / 2;
    auto out_re_lo = result + 1 * params::degree / 2;
    auto out_im_hi = result + 2 * params::degree / 2;
    auto out_im_lo = result + 3 * params::degree / 2;
    out_re_hi[tid] = out_re.hi;
    out_re_lo[tid] = out_re.lo;
    out_im_hi[tid] = out_im.hi;
    out_im_lo[tid] = out_im.lo;
    tid += params::degree / params::opt;
  }
  __syncthreads();
}

// Rotates the accumulator and writes EVERY decomposition level to its Fourier
// buffer, `fft` being the base of level 0.
//
// Counterpart of decompose_and_compress_level_128_tbc, which produces only the
// one level its block owns. Here a single block owns them all, so the state is
// walked once: the last level comes out of the rotation pass while it is still
// full width, and the rest walk the narrowed state.
//
// The caller must not read the accumulator afterwards -- level 0 aliases it.
template <typename T, class params, uint32_t base_log, uint32_t level_count>
__device__ void rotate_and_decompose_all_levels_128(double *fft,
                                                    const T *accumulator,
                                                    uint32_t j) {
  uint64_t state[params::opt];
  rotate_and_decompose_first_level_128<T, params, base_log, level_count>(
      get_current_fft_level<params>(fft, level_count - 1), state, accumulator,
      j);
  __syncthreads(); // the remaining levels may now overwrite the accumulator

  // Rolled: unrolling inflates the live range without buying overlap.
#pragma unroll 1
  for (uint32_t k = 0; k < level_count - 1; k++) {
    decompose_and_compress_one_level_narrow_128<params, base_log>(
        get_current_fft_level<params>(fft, level_count - 2 - k), state);
  }
}

template <typename T, class params, uint32_t base_log, uint32_t level_count>
__device__ void decompose_and_compress_level_128_tbc(double *result, T *state,
                                                     int level) {
  constexpr T mask_mod_b = (1ll << base_log) - 1ll;

  uint32_t tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    T res_re, res_im;
    T carry_im, carry_re;
    for (int l = 0; l < level_count - level; l++) {
      auto input1 = state[i];
      auto input2 = state[i + params::opt / 2];
      res_re = input1 & mask_mod_b;
      res_im = input2 & mask_mod_b;

      input1 = signed_shift_right<T>(input1, base_log); // Update state
      input2 = signed_shift_right<T>(input2, base_log); // Update state

      carry_re = ((res_re - 1ll) | input1) & res_re;
      carry_im = ((res_im - 1ll) | input2) & res_im;
      carry_re >>= (base_log - 1);
      carry_im >>= (base_log - 1);

      state[i] = input1 + carry_re;                   // Update state
      state[i + params::opt / 2] = input2 + carry_im; // Update state
    }

    res_re -= carry_re << base_log;
    res_im -= carry_im << base_log;
    auto out_re = u128_to_signed_to_f128(res_re);
    auto out_im = u128_to_signed_to_f128(res_im);

    auto out_re_hi = result + 0 * params::degree / 2;
    auto out_re_lo = result + 1 * params::degree / 2;
    auto out_im_hi = result + 2 * params::degree / 2;
    auto out_im_lo = result + 3 * params::degree / 2;

    out_re_hi[tid] = out_re.hi;
    out_re_lo[tid] = out_re.lo;
    out_im_hi[tid] = out_im.hi;
    out_im_lo[tid] = out_im.lo;

    tid += params::degree / params::opt;
  }
  __syncthreads();
}
