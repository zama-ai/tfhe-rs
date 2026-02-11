#ifndef GPU_POLYNOMIAL_FUNCTIONS_CUH
#define GPU_POLYNOMIAL_FUNCTIONS_CUH

#include "crypto/torus.cuh"
#include "device.h"
#include "fft128/f128.cuh"
#include "parameters.cuh"

// Return A if C == 0 and B if C == 1
#define SEL(A, B, C) ((-(C) & ((A) ^ (B))) ^ (A))

template <typename T, int elems_per_thread, int block_size>
__device__ void copy_polynomial(const T *__restrict__ source, T *dst) {
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < elems_per_thread; i++) {
    dst[tid] = source[tid];
    tid = tid + block_size;
  }
}
template <typename T, int elems_per_thread, int block_size>
__device__ void copy_polynomial_in_regs(const T *__restrict__ source, T *dst) {
#pragma unroll
  for (int i = 0; i < elems_per_thread; i++) {
    dst[i] = source[threadIdx.x + i * block_size];
  }
}

template <typename T, int elems_per_thread, int block_size>
__device__ void copy_polynomial_from_regs(const T *__restrict__ source,
                                          T *dst) {
#pragma unroll
  for (int i = 0; i < elems_per_thread; i++) {
    dst[threadIdx.x + i * block_size] = source[i];
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
__device__ void
divide_by_monomial_negacyclic_inplace(T *accumulator,
                                      const T *__restrict__ input, uint32_t j,
                                      bool zeroAcc, uint32_t num_poly = 1) {
  constexpr int degree = block_size * elems_per_thread;
  for (int z = 0; z < num_poly; z++) {
    T *accumulator_slice = &accumulator[z * degree];
    const T *input_slice = &input[z * degree];

    int tid = threadIdx.x;
    if (zeroAcc) {
      for (int i = 0; i < elems_per_thread; i++) {
        accumulator_slice[tid] = 0;
        tid += block_size;
      }
    } else {
      if (j < degree) {
        for (int i = 0; i < elems_per_thread; i++) {
          // if (tid < degree - j)
          //  accumulator_slice[tid] = input_slice[tid + j];
          // else
          //  accumulator_slice[tid] = -input_slice[tid - degree + j];
          int x = tid + j - SEL(degree, 0, tid < degree - j);
          accumulator_slice[tid] =
              SEL(-1, 1, tid < degree - j) * input_slice[x];
          tid += block_size;
        }
      } else {
        int32_t jj = j - degree;
        for (int i = 0; i < elems_per_thread; i++) {
          // if (tid < degree - jj)
          //  accumulator_slice[tid] = -input_slice[tid + jj];
          // else
          //  accumulator_slice[tid] = input_slice[tid - degree + jj];
          int x = tid + jj - SEL(degree, 0, tid < degree - jj);
          accumulator_slice[tid] =
              SEL(1, -1, tid < degree - jj) * input_slice[x];
          tid += block_size;
        }
      }
    }
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
__device__ void divide_by_monomial_negacyclic_2_2_params_inplace(
    T *accumulator, const T *__restrict__ input, uint32_t j) {
  constexpr int degree = block_size * elems_per_thread;
  int tid = threadIdx.x;
  if (j < degree) {
    for (int i = 0; i < elems_per_thread; i++) {
      int x = tid + j - SEL(degree, 0, tid < degree - j);
      accumulator[i] = SEL(-1, 1, tid < degree - j) * input[x];
      tid += block_size;
    }
  } else {
    int32_t jj = j - degree;
    for (int i = 0; i < elems_per_thread; i++) {
      int x = tid + jj - SEL(degree, 0, tid < degree - jj);
      accumulator[i] = SEL(1, -1, tid < degree - jj) * input[x];
      tid += block_size;
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
 * Receives num_poly  concatenated polynomials of type T. For each:
 *
 * Performs result_acc = acc * (X^ä - 1) - acc
 * takes single buffer as input and returns a single rotated buffer
 * result_acc must be in registers
 * acc must be in shared memory
 *  By default, it works on a single polynomial.
 */
template <typename T, int elems_per_thread, int block_size>
__device__ void multiply_by_monomial_negacyclic_and_sub_polynomial_in_regs(
    T *acc, T *result_acc, uint32_t j) {
  constexpr int degree = block_size * elems_per_thread;
  int tid = threadIdx.x;
  for (int i = 0; i < elems_per_thread; i++) {
    if (j < degree) {
      int x = tid - j + SEL(0, degree, tid < j);
      result_acc[i] = SEL(1, -1, tid < j) * acc[x] - acc[tid];
    } else {
      int32_t jj = j - degree;
      int x = tid - jj + SEL(0, degree, tid < jj);
      result_acc[i] = SEL(-1, 1, tid < jj) * acc[x] - acc[tid];
    }
    tid += block_size;
  }
}
// Same as above but acc is in registers. This is used in the specialized 2_2
// params where we can keep the accumulator in registers to avoid
// synchronizations and shared memory usage
template <typename T, int elems_per_thread, int block_size>
__device__ void multiply_by_monomial_negacyclic_and_sub_polynomial_both_in_regs(
    T *acc, T *acc_in_regs, T *result_acc, uint32_t j) {
  constexpr int degree = block_size * elems_per_thread;
  int tid = threadIdx.x;
  for (int i = 0; i < elems_per_thread; i++) {
    if (j < degree) {
      int x = tid - j + SEL(0, degree, tid < j);
      result_acc[i] = SEL(1, -1, tid < j) * acc[x] - acc_in_regs[i];
    } else {
      int32_t jj = j - degree;
      int x = tid - jj + SEL(0, degree, tid < jj);
      result_acc[i] = SEL(-1, 1, tid < jj) * acc[x] - acc_in_regs[i];
    }
    tid += block_size;
  }
}

/*
 * Receives num_poly  concatenated polynomials of type T. For each performs a
 * rounding to increase accuracy of the PBS. Calculates inplace.
 *
 *  By default, it works on a single polynomial.
 */
template <typename T, int elems_per_thread, int block_size>
__device__ void init_decomposer_state_inplace(T *rotated_acc, int base_log,
                                              int level_count,
                                              uint32_t num_poly = 1) {
  constexpr int degree = block_size * elems_per_thread;
  for (int z = 0; z < num_poly; z++) {
    T *rotated_acc_slice = &rotated_acc[z * degree];
    uint32_t tid = threadIdx.x;
    for (int i = 0; i < elems_per_thread; i++) {
      T x_acc = rotated_acc_slice[tid];
      rotated_acc_slice[tid] =
          init_decomposer_state(x_acc, base_log, level_count);
      tid = tid + block_size;
    }
  }
}

/*
 * Receives num_poly  concatenated polynomials of type T. For each performs a
 * rounding to increase accuracy of the PBS. Calculates inplace.
 *
 *  By default, it works on a single polynomial.
 */
template <typename T, int elems_per_thread, uint32_t block_size,
          uint32_t base_log, int level_count>
__device__ void init_decomposer_state_inplace_2_2_params(T *rotated_acc) {
  for (int i = 0; i < elems_per_thread; i++) {
    T x_acc = rotated_acc[i];
    rotated_acc[i] =
        init_decomposer_state_2_2_params<T, base_log, level_count>(x_acc);
  }
}

/**
 * In case of classical PBS, this method should accumulate the result.
 * In case of multi-bit PBS, it should overwrite.
 */
template <typename Torus, class params>
__device__ void add_to_torus(double2 *m_values, Torus *result,
                             bool overwrite_result = false) {
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    double double_real = m_values[tid].x;
    double double_imag = m_values[tid].y;

    Torus torus_real = 0;
    typecast_double_round_to_torus<Torus>(double_real, torus_real);

    Torus torus_imag = 0;
    typecast_double_round_to_torus<Torus>(double_imag, torus_imag);

    if (overwrite_result) {
      result[tid] = torus_real;
      result[tid + params::degree / 2] = torus_imag;
    } else {
      result[tid] += torus_real;
      result[tid + params::degree / 2] += torus_imag;
    }
    tid = tid + params::degree / params::opt;
  }
}

/**
 * In case of classical PBS, this method should accumulate the result.
 * In case of multi-bit PBS, it should overwrite.
 */
template <typename Torus, class params>
__device__ void add_to_torus_2_2_params(double2 *m_values, Torus *result) {
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    double double_real = m_values[i].x;
    double double_imag = m_values[i].y;

    Torus torus_real = 0;
    typecast_double_round_to_torus<Torus>(double_real, torus_real);

    Torus torus_imag = 0;
    typecast_double_round_to_torus<Torus>(double_imag, torus_imag);

    result[i] = torus_real;
    result[i + params::opt / 2] = torus_imag;

    tid = tid + params::degree / params::opt;
  }
}
/**
 * In case of 2_2_classical PBS, this method should accumulate the result.
 * and the result is stored in shared memory
 */
template <typename Torus, class params>
__device__ void add_to_torus_2_2_params_using_shared(double2 *m_values,
                                                     Torus *result) {
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    double double_real = m_values[i].x;
    double double_imag = m_values[i].y;

    Torus torus_real = 0;
    typecast_double_round_to_torus<Torus>(double_real, torus_real);

    Torus torus_imag = 0;
    typecast_double_round_to_torus<Torus>(double_imag, torus_imag);

    result[tid] += torus_real;
    result[tid + params::degree / 2] += torus_imag;

    tid = tid + params::degree / params::opt;
  }
}

/**
 * In case of 2_2_classical PBS, this method should accumulate the result.
 * and the result is stored in shared memory
 */
template <typename Torus, class params>
__device__ void add_to_torus_2_2_params_using_regs(double2 *m_values,
                                                   Torus *result) {
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    double double_real = m_values[i].x;
    double double_imag = m_values[i].y;

    Torus torus_real = 0;
    typecast_double_round_to_torus<Torus>(double_real, torus_real);

    Torus torus_imag = 0;
    typecast_double_round_to_torus<Torus>(double_imag, torus_imag);

    result[i] += torus_real;
    result[i + params::opt / 2] += torus_imag;
  }
}
/**
 * In case of classical PBS, this method should accumulate the result.
 * In case of multi-bit PBS, it should overwrite.
 */
template <typename Torus, class params>
__device__ void add_to_torus_128(double *re_hi, double *re_lo, double *im_hi,
                                 double *im_lo, Torus *result,
                                 bool overwrite_result = false) {
  constexpr double normalization = 1. / (params::degree / 2);
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    f128 f128_real(re_hi[tid] * normalization, re_lo[tid] * normalization);
    f128 f128_imag(im_hi[tid] * normalization, im_lo[tid] * normalization);

    Torus torus_real = u128_from_torus_f128(f128_real);
    Torus torus_imag = u128_from_torus_f128(f128_imag);

    if (overwrite_result) {
      result[tid] = torus_real;
      result[tid + params::degree / 2] = torus_imag;
    } else {
      result[tid] += torus_real;
      result[tid + params::degree / 2] += torus_imag;
    }
    tid = tid + params::degree / params::opt;
  }
}

// Extracts the body of the nth-LWE in a GLWE.
template <typename Torus, class params>
__device__ void sample_extract_body(Torus *lwe_array_out, Torus const *glwe,
                                    uint32_t glwe_dimension, uint32_t nth = 0) {
  // Set first coefficient of the glwe as the body of the LWE sample
  if (threadIdx.x == 0) {
    lwe_array_out[glwe_dimension * params::degree] =
        glwe[glwe_dimension * params::degree + nth];
  }
}

// Extracts the mask from the nth-LWE in a GLWE.
template <typename Torus, class params>
__device__ void sample_extract_mask(Torus *lwe_array_out, Torus const *glwe,
                                    uint32_t glwe_dimension = 1,
                                    uint32_t nth = 0) {
  for (int z = 0; z < glwe_dimension; z++) {
    Torus *lwe_array_out_slice =
        (Torus *)lwe_array_out + (ptrdiff_t)(z * params::degree);
    Torus *glwe_slice = (Torus *)glwe + (ptrdiff_t)(z * params::degree);

    __syncthreads();
    // Reverse the glwe
    // Set ACC = -ACC
    int tid = threadIdx.x;
    Torus result[params::opt];
#pragma unroll
    for (int i = 0; i < params::opt; i++) {
      auto x = glwe_slice[params::degree - tid - 1];
      result[i] = SEL(-x, x, tid >= params::degree - nth);
      tid = tid + params::degree / params::opt;
    }
    __syncthreads();

    // Perform ACC * X
    // (equivalent to multiply_by_monomial_negacyclic_inplace(1))
    // Copy to the mask of the LWE sample
    tid = threadIdx.x;
    for (int i = 0; i < params::opt; i++) {
      // if (tid < 1)
      //  result[i] = -glwe_slice[tid - 1 + params::degree];
      // else
      //  result[i] = glwe_slice[tid - 1];
      uint32_t dst_idx = tid + 1 + nth;
      if (dst_idx == params::degree)
        lwe_array_out_slice[0] = -result[i];
      else {
        dst_idx =
            SEL(dst_idx, dst_idx - params::degree, dst_idx >= params::degree);
        lwe_array_out_slice[dst_idx] = result[i];
      }

      tid += params::degree / params::opt;
    }
  }
}

#endif
