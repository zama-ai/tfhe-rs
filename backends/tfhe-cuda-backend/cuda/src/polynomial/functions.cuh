#ifndef GPU_POLYNOMIAL_FUNCTIONS_CUH
#define GPU_POLYNOMIAL_FUNCTIONS_CUH

#include "crypto/torus.cuh"
#include "device.h"

// Return A if C == 0 and B if C == 1
#define SEL(A, B, C) ((-(C) & ((A) ^ (B))) ^ (A))

/*
 *  function compresses decomposed buffer into half size complex buffer for fft
 */
template <class params>
__device__ void real_to_complex_compressed(int16_t *src, double2 *dst) {
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    dst[tid].x = __int2double_rn(src[2 * tid]);
    dst[tid].y = __int2double_rn(src[2 * tid + 1]);
    tid += params::degree / params::opt;
  }
}

template <typename T, int elems_per_thread, int block_size>
__device__ void copy_polynomial(T *source, T *dst) {
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < elems_per_thread; i++) {
    dst[tid] = source[tid];
    tid = tid + block_size;
  }
}

/*
 * Receives num_poly  concatenated polynomials of type T. For each:
 *
 * Performs acc = acc * (X^ä + 1) if zeroAcc = false
 * Performs acc = 0 if zeroAcc
 * takes single buffer and calculates inplace.
 *
 *  By default, it works on a single polynomial.
 */
template <typename T, int elems_per_thread, int block_size>
__device__ void divide_by_monomial_negacyclic_inplace(T *accumulator, T *input,
                                                      uint32_t j, bool zeroAcc,
                                                      uint32_t num_poly = 1) {
  constexpr int degree = block_size * elems_per_thread;
  for (int z = 0; z < num_poly; z++) {
    T *accumulator_slice = (T *)accumulator + (ptrdiff_t)(z * degree);
    T *input_slice = (T *)input + (ptrdiff_t)(z * degree);

    int tid = threadIdx.x;
    if (zeroAcc) {
      for (int i = 0; i < elems_per_thread; i++) {
        accumulator_slice[tid] = 0;
        tid += block_size;
      }
    } else {
      tid = threadIdx.x;
      for (int i = 0; i < elems_per_thread; i++) {
        if (j < degree) {
          // if (tid < degree - j)
          //  accumulator_slice[tid] = input_slice[tid + j];
          // else
          //  accumulator_slice[tid] = -input_slice[tid - degree + j];
          int x = tid + j - SEL(degree, 0, tid < degree - j);
          accumulator_slice[tid] =
              SEL(-1, 1, tid < degree - j) * input_slice[x];
        } else {
          int32_t jj = j - degree;
          // if (tid < degree - jj)
          //  accumulator_slice[tid] = -input_slice[tid + jj];
          // else
          //  accumulator_slice[tid] = input_slice[tid - degree + jj];
          int x = tid + jj - SEL(degree, 0, tid < degree - jj);
          accumulator_slice[tid] =
              SEL(1, -1, tid < degree - jj) * input_slice[x];
        }
        tid += block_size;
      }
    }
  }
}

/*
 * Receives num_poly  concatenated polynomials of type T. For each:
 *
 * Performs result_acc = acc * (X^ä - 1) - acc
 * takes single buffer as input and returns a single rotated buffer
 *
 *  By default, it works on a single polynomial.
 */
template <typename T, int elems_per_thread, int block_size>
__device__ void multiply_by_monomial_negacyclic_and_sub_polynomial(
    T *acc, T *result_acc, uint32_t j, uint32_t num_poly = 1) {
  constexpr int degree = block_size * elems_per_thread;
  for (int z = 0; z < num_poly; z++) {
    T *acc_slice = (T *)acc + (ptrdiff_t)(z * degree);
    T *result_acc_slice = (T *)result_acc + (ptrdiff_t)(z * degree);
    int tid = threadIdx.x;
    for (int i = 0; i < elems_per_thread; i++) {
      if (j < degree) {
        // if (tid < j)
        //  result_acc_slice[tid] = -acc_slice[tid - j + degree]-acc_slice[tid];
        // else
        //  result_acc_slice[tid] = acc_slice[tid - j] - acc_slice[tid];
        int x = tid - j + SEL(0, degree, tid < j);
        result_acc_slice[tid] =
            SEL(1, -1, tid < j) * acc_slice[x] - acc_slice[tid];
      } else {
        int32_t jj = j - degree;
        // if (tid < jj)
        //  result_acc_slice[tid] = acc_slice[tid - jj + degree]-acc_slice[tid];
        // else
        //  result_acc_slice[tid] = -acc_slice[tid - jj] - acc_slice[tid];
        int x = tid - jj + SEL(0, degree, tid < jj);
        result_acc_slice[tid] =
            SEL(-1, 1, tid < jj) * acc_slice[x] - acc_slice[tid];
      }
      tid += block_size;
    }
  }
}

/*
 * Receives num_poly  concatenated polynomials of type T. For each performs a
 * rounding to increase accuracy of the PBS. Calculates inplace.
 *
 *  By default, it works on a single polynomial.
 */
template <typename T, int elems_per_thread, int block_size>
__device__ void round_to_closest_multiple_inplace(T *rotated_acc, int base_log,
                                                  int level_count,
                                                  uint32_t num_poly = 1) {
  constexpr int degree = block_size * elems_per_thread;
  for (int z = 0; z < num_poly; z++) {
    T *rotated_acc_slice = (T *)rotated_acc + (ptrdiff_t)(z * degree);
    int tid = threadIdx.x;
    for (int i = 0; i < elems_per_thread; i++) {
      T x_acc = rotated_acc_slice[tid];
      T shift = sizeof(T) * 8 - level_count * base_log;
      T mask = 1ll << (shift - 1);
      T b_acc = (x_acc & mask) >> (shift - 1);
      T res_acc = x_acc >> shift;
      res_acc += b_acc;
      res_acc <<= shift;
      rotated_acc_slice[tid] = res_acc;
      tid = tid + block_size;
    }
  }
}

template <typename Torus, class params>
__device__ void add_to_torus(double2 *m_values, Torus *result,
                             bool init_torus = false) {
  Torus mx = (sizeof(Torus) == 4) ? UINT32_MAX : UINT64_MAX;
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    double v1 = m_values[tid].x;
    double v2 = m_values[tid].y;

    double frac = v1 - floor(v1);
    frac *= mx;
    double carry = frac - floor(frac);
    frac += (carry >= 0.5);

    Torus V1 = 0;
    typecast_double_to_torus<Torus>(frac, V1);

    frac = v2 - floor(v2);
    frac *= mx;
    carry = frac - floor(v2);
    frac += (carry >= 0.5);

    Torus V2 = 0;
    typecast_double_to_torus<Torus>(frac, V2);

    if (init_torus) {
      result[tid] = V1;
      result[tid + params::degree / 2] = V2;
    } else {
      result[tid] += V1;
      result[tid + params::degree / 2] += V2;
    }
    tid = tid + params::degree / params::opt;
  }
}

// Extracts the body of a GLWE.
// k is the offset to find the body element / polynomial in the lwe_array_out /
// accumulator
template <typename Torus, class params>
__device__ void sample_extract_body(Torus *lwe_array_out, Torus *accumulator,
                                    uint32_t k) {
  // Set first coefficient of the accumulator as the body of the LWE sample
  lwe_array_out[k * params::degree] = accumulator[k * params::degree];
}

// Extracts the mask from num_poly polynomials individually
template <typename Torus, class params>
__device__ void sample_extract_mask(Torus *lwe_array_out, Torus *accumulator,
                                    uint32_t num_poly = 1) {
  for (int z = 0; z < num_poly; z++) {
    Torus *lwe_array_out_slice =
        (Torus *)lwe_array_out + (ptrdiff_t)(z * params::degree);
    Torus *accumulator_slice =
        (Torus *)accumulator + (ptrdiff_t)(z * params::degree);

    // Set ACC = -ACC
    int tid = threadIdx.x;
#pragma unroll
    for (int i = 0; i < params::opt; i++) {
      accumulator_slice[tid] = -accumulator_slice[tid];
      tid = tid + params::degree / params::opt;
    }
    synchronize_threads_in_block();

    // Reverse the accumulator
    tid = threadIdx.x;
    Torus result[params::opt];
#pragma unroll
    for (int i = 0; i < params::opt; i++) {
      result[i] = accumulator_slice[params::degree - tid - 1];
      tid = tid + params::degree / params::opt;
    }
    synchronize_threads_in_block();
    tid = threadIdx.x;
#pragma unroll
    for (int i = 0; i < params::opt; i++) {
      accumulator_slice[tid] = result[i];
      tid = tid + params::degree / params::opt;
    }
    synchronize_threads_in_block();

    // Perform ACC * X
    // (equivalent to multiply_by_monomial_negacyclic_inplace(1))
    tid = threadIdx.x;
    result[params::opt];
    for (int i = 0; i < params::opt; i++) {
      // if (tid < 1)
      //  result[i] = -accumulator_slice[tid - 1 + params::degree];
      // else
      //  result[i] = accumulator_slice[tid - 1];
      int x = tid - 1 + SEL(0, params::degree, tid < 1);
      result[i] = SEL(1, -1, tid < 1) * accumulator_slice[x];
      tid += params::degree / params::opt;
    }
    synchronize_threads_in_block();
    tid = threadIdx.x;
    for (int i = 0; i < params::opt; i++) {
      accumulator_slice[tid] = result[i];
      tid += params::degree / params::opt;
    }
    synchronize_threads_in_block();

    // Copy to the mask of the LWE sample
    tid = threadIdx.x;
#pragma unroll
    for (int i = 0; i < params::opt; i++) {
      lwe_array_out_slice[tid] = accumulator_slice[tid];
      tid = tid + params::degree / params::opt;
    }
  }
}

#endif
