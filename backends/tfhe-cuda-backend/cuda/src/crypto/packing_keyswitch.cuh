#ifndef CNCRT_FAST_KS_CUH
#define CNCRT_FAST_KS_CUH

#undef NDEBUG

#include "device.h"
#include "gadget.cuh"
#include "helper_multi_gpu.h"
#include "keyswitch.cuh"
#include "linearalgebra/multiplication.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include "torus.cuh"
#include "utils/helper.cuh"
#include <thread>
#include <vector>

// Finish the keyswitching operation and prepare GLWEs for accumulation.
// 1. Finish the keyswitching computation partially performed with a GEMM:
//  - negate the dot product between the GLWE and KSK polynomial
//  - add the GLWE message for the N-th polynomial coeff in the message poly
// 2. Rotate each of the GLWE . KSK poly dot products to
//    prepare them for accumulation into a single GLWE
template <typename Torus>
__global__ void polynomial_accumulate_monic_monomial_mul_many_neg_and_add_C(
    Torus *in_glwe_buffer, Torus *out_glwe_buffer, Torus const *lwe_array,
    uint32_t lwe_dimension, uint32_t num_glwes, uint32_t polynomial_size,
    uint32_t glwe_dimension) {

  uint32_t glwe_id = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t degree = glwe_id; // lwe 0 rotate 0, lwe 1 rotate 1, .. , lwe
                             // poly_size-1 rotate poly_size-1
  uint32_t coeffIdx = blockIdx.y * blockDim.y + threadIdx.y;

  if (glwe_id >= num_glwes)
    return;
  if (coeffIdx >= polynomial_size)
    return;

  auto in_poly =
      in_glwe_buffer + glwe_id * polynomial_size * (glwe_dimension + 1);
  auto out_result =
      out_glwe_buffer + glwe_id * polynomial_size * (glwe_dimension + 1);
  if (coeffIdx == 0) {
    // Add the message value of the input LWE (`C`) to the N-th coefficient
    // in the GLWE . KSK dot product

    // The C is added to the first position of the last polynomial in the GLWE
    // which has (glwe_dimension+1) polynomials
    // The C value is extracted as the last value of the LWE ct. (of index
    // glwe_id) the LWEs have (polynomial_size + 1) values
    in_poly[polynomial_size * glwe_dimension] =
        lwe_array[glwe_id * (lwe_dimension + 1) + lwe_dimension] -
        in_poly[polynomial_size * glwe_dimension];

    for (int gi = 1; gi < glwe_dimension; ++gi)
      in_poly[coeffIdx + gi * polynomial_size] =
          -in_poly[coeffIdx + gi * polynomial_size];

  } else {
    // Otherwise simply negate the input coefficient
    for (int gi = 1; gi < glwe_dimension + 1; ++gi)
      in_poly[coeffIdx + gi * polynomial_size] =
          -in_poly[coeffIdx + gi * polynomial_size];
  }
  // Negate all the coefficients for rotation for the first poly
  in_poly[coeffIdx] = -in_poly[coeffIdx];

  // rotate the body
  polynomial_accumulate_monic_monomial_mul<Torus>(
      out_result, in_poly, degree, coeffIdx, polynomial_size, 1, true);
  // rotate the mask too
  for (int gi = 1; gi < glwe_dimension + 1; ++gi)
    polynomial_accumulate_monic_monomial_mul<Torus>(
        out_result + gi * polynomial_size, in_poly + gi * polynomial_size,
        degree, coeffIdx, polynomial_size, 1, true);
}

template <typename Torus>
__host__ void host_packing_keyswitch_lwe_list_to_glwe(
    cudaStream_t stream, uint32_t gpu_index, Torus *glwe_out,
    Torus const *lwe_array_in, Torus const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_lwes) {

  // Optimization of packing keyswitch when packing many LWEs

  cuda_set_device(gpu_index);
  check_cuda_error(cudaGetLastError());

  int glwe_accumulator_size = (glwe_dimension + 1) * polynomial_size;

  // The fast path of PKS uses the scratch buffer (d_mem) differently than the
  // old path: it needs to store the decomposed masks in the first half of this
  // buffer and the keyswitched GLWEs in the second half of the buffer. Thus the
  // scratch buffer for the fast path must determine the half-size of the
  // scratch buffer as the max between the size of the GLWE and the size of the
  // LWE-mask times two (to keep both decomposition state and decomposed
  // intermediate value)
  int memory_unit = glwe_accumulator_size > lwe_dimension * 2
                        ? glwe_accumulator_size
                        : lwe_dimension * 2;

  // ping pong the buffer between successive calls
  // split the buffer in two parts of this size
  auto d_mem_0 = (Torus *)fp_ks_buffer;
  auto d_mem_1 = d_mem_0 + num_lwes * memory_unit;

  // Set the scratch buffer to 0 as it is used to accumulate
  // decomposition temporary results
  cuda_memset_async(
      d_mem_1, 0, safe_mul_sizeof<Torus>((size_t)num_lwes, (size_t)memory_unit),
      stream, gpu_index);
  check_cuda_error(cudaGetLastError());

  // decompose LWEs
  // don't decompose LWE body - the LWE has lwe_size + 1 elements. The last
  // element, the body is ignored by rounding down the number of blocks assuming
  // here that the LWE dimension is a multiple of the block size
  dim3 grid_decomp(CEIL_DIV(num_lwes, BLOCK_SIZE_DECOMP),
                   CEIL_DIV(lwe_dimension, BLOCK_SIZE_DECOMP));
  dim3 threads_decomp(BLOCK_SIZE_DECOMP, BLOCK_SIZE_DECOMP);

  // decompose first level
  decompose_vectorize_init<Torus, Torus>
      <<<grid_decomp, threads_decomp, 0, stream>>>(lwe_array_in, d_mem_0,
                                                   lwe_dimension, num_lwes,
                                                   base_log, level_count);
  check_cuda_error(cudaGetLastError());

  // gemm to ks the individual LWEs to GLWEs
  dim3 grid_gemm(CEIL_DIV(glwe_accumulator_size, BLOCK_SIZE_GEMM),
                 CEIL_DIV(num_lwes, BLOCK_SIZE_GEMM));
  dim3 threads_gemm(BLOCK_SIZE_GEMM * THREADS_GEMM);

  auto stride_KSK_buffer = glwe_accumulator_size * level_count;

  uint32_t shared_mem_size = get_shared_mem_size_tgemm<Torus>();
  // Shared memory requirement is 4096, 8192, and 16384 bytes respectively for
  // 32, 64, and 128-bit Torus elements
  // Sanity check: the shared memory size is a constant defined by the algorithm
  GPU_ASSERT(shared_mem_size <= 1024 * sizeof(Torus),
             "GEMM kernel error: shared memory required might be too large");

  tgemm<Torus, BLOCK_SIZE_GEMM, THREADS_GEMM>
      <<<grid_gemm, threads_gemm, shared_mem_size, stream>>>(
          num_lwes, glwe_accumulator_size, lwe_dimension, d_mem_0, fp_ksk_array,
          stride_KSK_buffer, d_mem_1, glwe_accumulator_size);
  check_cuda_error(cudaGetLastError());

  auto ksk_block_size = glwe_accumulator_size;

  for (int li = 1; li < level_count; ++li) {
    decompose_vectorize_step_inplace<Torus, Torus>
        <<<grid_decomp, threads_decomp, 0, stream>>>(
            d_mem_0, lwe_dimension, num_lwes, base_log, level_count);
    check_cuda_error(cudaGetLastError());

    tgemm<Torus, BLOCK_SIZE_GEMM, THREADS_GEMM>
        <<<grid_gemm, threads_gemm, shared_mem_size, stream>>>(
            num_lwes, glwe_accumulator_size, lwe_dimension, d_mem_0,
            fp_ksk_array + li * ksk_block_size, stride_KSK_buffer, d_mem_1,
            glwe_accumulator_size);
    check_cuda_error(cudaGetLastError());
  }

  // should we include the mask in the rotation ??
  dim3 grid_rotate(CEIL_DIV(num_lwes, BLOCK_SIZE_DECOMP),
                   CEIL_DIV(polynomial_size, BLOCK_SIZE_DECOMP));
  dim3 threads_rotate(BLOCK_SIZE_DECOMP, BLOCK_SIZE_DECOMP);
  // rotate the GLWEs
  polynomial_accumulate_monic_monomial_mul_many_neg_and_add_C<Torus>
      <<<grid_rotate, threads_rotate, 0, stream>>>(
          d_mem_1, d_mem_0, lwe_array_in, lwe_dimension, num_lwes,
          polynomial_size, glwe_dimension);
  check_cuda_error(cudaGetLastError());

  dim3 grid_accumulate(
      CEIL_DIV(polynomial_size * (glwe_dimension + 1), BLOCK_SIZE_DECOMP));
  dim3 threads_accum(BLOCK_SIZE_DECOMP);

  // accumulate to a single glwe
  accumulate_glwes<Torus><<<grid_accumulate, threads_accum, 0, stream>>>(
      glwe_out, d_mem_0, glwe_dimension, polynomial_size, num_lwes);

  check_cuda_error(cudaGetLastError());
}

#endif
