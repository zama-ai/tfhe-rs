#ifndef CUDA_INTEGER_GOLDSCHMIDT_DIVISION_CUH
#define CUDA_INTEGER_GOLDSCHMIDT_DIVISION_CUH

#include "integer/cmux.cuh"
#include "integer/goldschmidt_division.h"
#include "integer/ilog2.cuh"
#include "integer/integer.cuh"
#include "integer/multiplication.cuh"
#include "integer/negation.cuh"
#include "integer/scalar_comparison.cuh"
#include "integer/subtraction.cuh"
#include "integer/vector_find.cuh"
#include "radix_ciphertext.cuh"

// Resizes and shifts a ciphertext array by a specified number of blocks, either
// left or right. output = input * (radix ^ shift)
//
template <typename Torus>
__host__ void
blockshift_resize(CudaStreams streams, CudaRadixCiphertextFFI *output,
                  const CudaRadixCiphertextFFI *input, int32_t shift) {
  uint32_t new_size = output->num_radix_blocks;
  uint32_t input_size = input->num_radix_blocks;

  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), output, 0, new_size);

  if (shift >= 0) {
    uint32_t u_shift = (uint32_t)shift;
    if (u_shift < new_size) {
      uint32_t space_available = new_size - u_shift;
      uint32_t blocks_to_copy = std::min(input_size, space_available);
      if (blocks_to_copy > 0) {
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0), output, u_shift,
            u_shift + blocks_to_copy, input, 0, blocks_to_copy);
      }
    }
  } else {
    uint32_t abs_shift = (uint32_t)(-shift);
    if (abs_shift < input_size) {
      uint32_t source_blocks_avail = input_size - abs_shift;
      uint32_t blocks_to_copy = std::min(source_blocks_avail, new_size);
      if (blocks_to_copy > 0) {
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0), output, 0, blocks_to_copy,
            input, abs_shift, abs_shift + blocks_to_copy);
      }
    }
  }
}

// Performs a saturated multiplication of two 64-bit integers to prevent
// overflow. result = min(a * b, UINT64_MAX)
//
static uint64_t mul_add_core_sat_mul_u64(uint64_t a, uint64_t b) {
  if (a == 0 || b == 0)
    return 0;
  if (a > UINT64_MAX / b)
    return UINT64_MAX;
  return a * b;
}

// Computes the saturated power of a 64-bit base raised to a 32-bit exponent.
// result = min(base ^ exp, UINT64_MAX)
//
static uint64_t mul_add_core_sat_pow_u64(uint64_t base, uint32_t exp) {
  uint64_t result = 1;
  for (uint32_t i = 0; i < exp; i++) {
    if (result > UINT64_MAX / base)
      return UINT64_MAX;
    result *= base;
  }
  return result;
}

// Calculates the maximum possible value generated during a triangular
// multiplication matrix computation.
//
static uint64_t mul_add_core_triangular_mul_max_u64(uint64_t columns,
                                                    uint64_t block_size) {
  uint64_t bs_pow_cp1 =
      mul_add_core_sat_pow_u64(block_size, (uint32_t)(columns + 1));
  uint64_t term1 = mul_add_core_sat_mul_u64(columns, bs_pow_cp1);

  uint64_t bs_pow_c = mul_add_core_sat_pow_u64(block_size, (uint32_t)columns);
  uint64_t term2 = mul_add_core_sat_mul_u64(columns + 1, bs_pow_c);

  if (term1 < term2)
    return 0;
  return term1 - term2 + 1;
}

// Computes the maximum possible value for a general multiplication matrix,
// combining triangular and rectangular parts.
//
static uint64_t mul_add_core_general_mul_max_u64(uint64_t columns,
                                                 uint64_t block_size,
                                                 uint64_t rhs_length) {
  if (columns <= rhs_length) {
    return mul_add_core_triangular_mul_max_u64(columns, block_size);
  }
  uint64_t tri = mul_add_core_triangular_mul_max_u64(rhs_length, block_size);

  uint64_t bs_pow_r =
      mul_add_core_sat_pow_u64(block_size, (uint32_t)rhs_length);
  uint64_t bs_pow_diff =
      mul_add_core_sat_pow_u64(block_size, (uint32_t)(columns - rhs_length));
  uint64_t factor_a = mul_add_core_sat_mul_u64(rhs_length, bs_pow_r);
  uint64_t factor_b =
      (bs_pow_diff == UINT64_MAX) ? UINT64_MAX : bs_pow_diff - 1;
  uint64_t factor_c = block_size - 1;

  uint64_t extra = mul_add_core_sat_mul_u64(
      mul_add_core_sat_mul_u64(factor_a, factor_b), factor_c);

  if (tri > UINT64_MAX - extra)
    return UINT64_MAX;
  return tri + extra;
}

// Determines the maximum number of columns (blocks) that can be evaluated
// before exceeding the target precision.
//
static uint32_t mul_add_find_max_columns(uint32_t block_size,
                                         uint32_t rhs_length,
                                         uint32_t precision) {
  if (rhs_length == 0)
    return UINT32_MAX;
  uint64_t target = 1ULL << precision;
  uint64_t columns = 0;
  while (columns < 1000000) {
    uint64_t val = mul_add_core_general_mul_max_u64(
        columns, (uint64_t)block_size, (uint64_t)rhs_length);
    if (val >= target)
      return (columns > 0) ? (uint32_t)(columns - 1) : 0;
    columns++;
  }
  return (uint32_t)(columns - 1);
}

// Identifies which block combinations are necessary for the current precision
// level and creates mapping indices.
//
static uint32_t mul_add_core_compute_useful_block_map(
    uint32_t num_blocks_left, uint32_t num_blocks_right,
    uint32_t block_columns_to_skip, uint32_t message_modulus, uint32_t *h_map,
    uint32_t *h_lut_indexes, uint64_t *degrees_out,
    uint32_t &useful_total_out) {

  uint32_t lhs_block_count = num_blocks_left;
  uint32_t rhs_block_count = num_blocks_right;
  uint32_t lsb_count = lhs_block_count * rhs_block_count;

  uint32_t idx = 0;

  for (uint32_t rhs = 0; rhs < rhs_block_count; rhs++) {
    for (uint32_t lhs = 0; lhs < lhs_block_count; lhs++) {
      uint32_t output_col = rhs + lhs;
      if (output_col >= block_columns_to_skip) {
        h_map[idx] = rhs * lhs_block_count + lhs;
        h_lut_indexes[idx] = 0;
        idx++;
      }
    }
  }
  uint32_t useful_lsb_count = idx;

  if (lhs_block_count > 1) {
    for (uint32_t rhs = 0; rhs < rhs_block_count; rhs++) {
      for (uint32_t lhs = 0; lhs < lhs_block_count - 1; lhs++) {
        uint32_t output_col = rhs + lhs + 1;
        if (output_col >= block_columns_to_skip + 1) {
          h_map[idx] = lsb_count + rhs * (lhs_block_count - 1) + lhs;
          h_lut_indexes[idx] = 1;
          idx++;
        }
      }
    }
  }
  useful_total_out = idx;

  for (uint32_t i = 0; i < rhs_block_count * lhs_block_count; i++) {
    uint32_t rhs = i / lhs_block_count;
    uint32_t b = i % lhs_block_count;
    bool valid = (b >= rhs);
    bool skip = (b < block_columns_to_skip);
    degrees_out[i] = (valid && !skip) ? (uint64_t)(message_modulus - 1) : 0;
  }

  uint64_t *msb_degrees = &degrees_out[rhs_block_count * lhs_block_count];
  for (uint32_t i = 0; i < rhs_block_count * lhs_block_count; i++) {
    uint32_t rhs = i / lhs_block_count;
    uint32_t b = i % lhs_block_count;
    bool valid = (b >= rhs + 1) && (lhs_block_count > 1);
    bool skip = (b < block_columns_to_skip + 1);
    msb_degrees[i] = (valid && !skip) ? (uint64_t)(message_modulus - 2) : 0;
  }

  return useful_lsb_count;
}

// Resets the temporary buffers used for storing intermediate products to zero.
//
template <typename Torus>
__host__ void mul_add_clear_multiplication_buffers(
    CudaStreams streams, int_goldschmidt_division_buffer<Torus> *mem) {
  auto mul_mem = mem->mul_mem;
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0),
      mem->full_precision_product_buffer, 0,
      mem->full_precision_product_buffer->num_radix_blocks);
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->padded_lhs_operand, 0,
      mem->padded_lhs_operand->num_radix_blocks);
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mul_mem->vector_result_sb, 0,
      mul_mem->vector_result_sb->num_radix_blocks);
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mul_mem->block_mul_res, 0,
      mul_mem->block_mul_res->num_radix_blocks);
}

// Pads the left-hand side operand with zeros and shifts it appropriately before
// multiplication. lhs_ext = lhs_padded * (radix ^ rescaling)
//
template <typename Torus>
__host__ uint32_t mul_add_prepare_and_pad_lhs(
    CudaStreams streams, const CudaRadixCiphertextFFI *lhs,
    int_goldschmidt_division_buffer<Torus> *mem, uint32_t result_len,
    uint32_t rhs_block_count, int32_t rescaling) {
  uint32_t padded_lhs_block_count =
      std::min(result_len + rhs_block_count + (uint32_t)std::abs(rescaling),
               mem->full_precision_product_buffer->max_num_radix_blocks);

  CudaRadixCiphertextFFI lhs_ext;
  as_radix_ciphertext_slice<Torus>(&lhs_ext, mem->padded_lhs_operand, 0,
                                   padded_lhs_block_count);
  blockshift_resize<Torus>(streams, &lhs_ext, lhs, 0);

  return padded_lhs_block_count;
}

// Copies the addition operand into the result buffer, or fills it with zeros if
// no operand is provided. result = added (or 0)
//
template <typename Torus>
__host__ void
mul_add_copy_added_or_zero_result(CudaStreams streams,
                                  CudaRadixCiphertextFFI *result,
                                  const CudaRadixCiphertextFFI *added) {
  if (added != nullptr) {
    blockshift_resize<Torus>(streams, result, added, 0);
  } else {
    set_zero_radix_ciphertext_slice_async<Torus>(streams.stream(0),
                                                 streams.gpu_index(0), result,
                                                 0, result->num_radix_blocks);
  }
}

// Executes the cross-multiplication of radix blocks between the left and right
// operands on the GPU. matrix[i, j] = lhs[i] * rhs[j]
//
template <typename Torus, class params>
__host__ void mul_add_evaluate_cross_multiplication_matrix(
    CudaStreams streams, int_asymmetric_mul_memory<Torus> *mul_mem,
    const CudaRadixCiphertextFFI *lhs_ext, const CudaRadixCiphertextFFI *rhs,
    uint32_t lhs_block_count, uint32_t rhs_block_count) {

  int lsb_count = (int)(lhs_block_count * rhs_block_count);

  auto vector_result_lsb = mul_mem->vector_result_sb;
  CudaRadixCiphertextFFI vector_result_msb;
  as_radix_ciphertext_slice<Torus>(&vector_result_msb, vector_result_lsb,
                                   lsb_count,
                                   vector_result_lsb->num_radix_blocks);

  auto vector_lsb_rhs = mul_mem->block_mul_res;
  CudaRadixCiphertextFFI vector_msb_rhs;
  as_radix_ciphertext_slice<Torus>(&vector_msb_rhs, mul_mem->block_mul_res,
                                   lsb_count,
                                   mul_mem->block_mul_res->num_radix_blocks);

  dim3 grid(lsb_count, 1, 1);
  dim3 thds(params::degree / params::opt, 1, 1);

  cuda_set_device(streams.gpu_index(0));
  all_shifted_lhs_rhs_asymmetric<Torus, params>
      <<<grid, thds, 0, streams.stream(0)>>>(
          (Torus *)lhs_ext->ptr, (Torus *)vector_result_lsb->ptr,
          (Torus *)vector_result_msb.ptr, (Torus *)rhs->ptr,
          (Torus *)vector_lsb_rhs->ptr, (Torus *)vector_msb_rhs.ptr,
          lhs_block_count);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__global__ void gather_radix_blocks_kernel(Torus *__restrict__ compact_sb,
                                           Torus *__restrict__ compact_res,
                                           const Torus *__restrict__ full_sb,
                                           const Torus *__restrict__ full_res,
                                           const uint32_t *__restrict__ map,
                                           uint32_t block_size) {

  uint32_t compact_idx = blockIdx.x;
  uint32_t full_idx = map[compact_idx];

  uint32_t compact_offset = compact_idx * block_size;
  uint32_t full_offset = full_idx * block_size;

  for (uint32_t tid = threadIdx.x; tid < block_size; tid += blockDim.x) {
    compact_sb[compact_offset + tid] = full_sb[full_offset + tid];
    compact_res[compact_offset + tid] = full_res[full_offset + tid];
  }
}

template <typename Torus>
__global__ void scatter_radix_blocks_kernel(
    Torus *__restrict__ full_res, const Torus *__restrict__ compact_res,
    const uint32_t *__restrict__ map, uint32_t block_size) {

  uint32_t compact_idx = blockIdx.x;
  uint32_t full_idx = map[compact_idx];

  uint32_t compact_offset = compact_idx * block_size;
  uint32_t full_offset = full_idx * block_size;

  for (uint32_t tid = threadIdx.x; tid < block_size; tid += blockDim.x) {
    full_res[full_offset + tid] = compact_res[compact_offset + tid];
  }
}

// Applies Programmable Bootstrapping to reduce the noise and evaluate the
// multiplication of active blocks.
//
template <typename Torus>
__host__ bool mul_add_evaluate_bivariate_pbs_on_active_blocks(
    CudaStreams streams, int_goldschmidt_division_buffer<Torus> *mem,
    uint32_t lhs_block_count, uint32_t rhs_block_count,
    uint32_t block_columns_to_skip, void *const *bsks, uint64_t *const *ksks) {

  auto mul_mem = mem->mul_mem;
  int lsb_count = (int)(lhs_block_count * rhs_block_count);
  int msb_count = (lhs_block_count <= 1)
                      ? 0
                      : (int)((lhs_block_count - 1) * rhs_block_count);
  int total_lsb_msb = lsb_count + msb_count;

  auto message_modulus = mul_mem->params.message_modulus;

  PUSH_RANGE("compute_useful_block_map")
  uint32_t useful_total = 0;
  uint32_t useful_lsb_count = mul_add_core_compute_useful_block_map(
      lhs_block_count, rhs_block_count, block_columns_to_skip, message_modulus,
      mem->h_map, mem->h_lut_idx, mul_mem->vector_result_sb->degrees,
      useful_total);
  POP_RANGE()

  if (useful_total == 0)
    return false;

  uint32_t compact_offset = (uint32_t)total_lsb_msb;

  PUSH_RANGE("setup_compact_views")
  CudaRadixCiphertextFFI compact_sb_view;
  as_radix_ciphertext_slice<Torus>(&compact_sb_view, mul_mem->vector_result_sb,
                                   compact_offset,
                                   compact_offset + useful_total);

  CudaRadixCiphertextFFI compact_res_view;
  as_radix_ciphertext_slice<Torus>(&compact_res_view, mul_mem->block_mul_res,
                                   compact_offset,
                                   compact_offset + useful_total);

  cuda_memcpy_async_to_gpu(mem->d_map, mem->h_map,
                           useful_total * sizeof(uint32_t), streams.stream(0),
                           streams.gpu_index(0));
  POP_RANGE()

  uint32_t block_size = compact_sb_view.lwe_dimension + 1;

  PUSH_RANGE("copy_to_compact_views_gpu")
  cuda_set_device(streams.gpu_index(0));
  gather_radix_blocks_kernel<Torus>
      <<<useful_total, 256, 0, streams.stream(0)>>>(
          (Torus *)compact_sb_view.ptr, (Torus *)compact_res_view.ptr,
          (Torus *)mul_mem->vector_result_sb->ptr,
          (Torus *)mul_mem->block_mul_res->ptr, mem->d_map, block_size);
  check_cuda_error(cudaGetLastError());
  POP_RANGE()

  PUSH_RANGE("setup_and_broadcast_luts")
  auto luts_array = mul_mem->luts_array;
  cuda_set_value_async<Torus>(streams.stream(0), streams.gpu_index(0),
                              luts_array->get_lut_indexes(0, 0), Torus(0),
                              useful_lsb_count);
  if (useful_total > useful_lsb_count) {
    cuda_set_value_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        luts_array->get_lut_indexes(0, useful_lsb_count), Torus(1),
        useful_total - useful_lsb_count);
  }

  auto active_streams =
      streams.active_gpu_subset(useful_total, mul_mem->params.pbs_type);
  luts_array->broadcast_lut(active_streams, false);
  POP_RANGE()

  PUSH_RANGE("apply_bivariate_lookup_table")
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, &compact_res_view, &compact_res_view, &compact_sb_view, bsks,
      ksks, luts_array, useful_total, message_modulus);
  POP_RANGE()

  PUSH_RANGE("copy_back_to_results_gpu")
  scatter_radix_blocks_kernel<Torus>
      <<<useful_total, 256, 0, streams.stream(0)>>>(
          (Torus *)mul_mem->block_mul_res->ptr, (Torus *)compact_res_view.ptr,
          mem->d_map, block_size);
  check_cuda_error(cudaGetLastError());
  POP_RANGE()

  PUSH_RANGE("update_degrees_cpu")
  for (uint32_t i = 0; i < useful_total; ++i) {
    uint32_t dst_idx = mem->h_map[i];
    if (mem->h_lut_idx[i] == 0) {
      mul_mem->block_mul_res->degrees[dst_idx] = message_modulus - 1;
    } else {
      mul_mem->block_mul_res->degrees[dst_idx] = message_modulus - 2;
    }
  }
  POP_RANGE()

  return true;
}

// Reconstructs the evaluated least and most significant bits back into a
// coherent ciphertext structure.
//
template <typename Torus, class params>
__host__ void mul_add_reassemble_evaluated_blocks(
    CudaStreams streams, int_asymmetric_mul_memory<Torus> *mul_mem,
    uint32_t lhs_block_count, uint32_t rhs_block_count, int big_lwe_size) {
  int lsb_count = (int)(lhs_block_count * rhs_block_count);

  auto vector_result_lsb = mul_mem->block_mul_res;
  CudaRadixCiphertextFFI vector_result_msb;
  as_radix_ciphertext_slice<Torus>(&vector_result_msb, mul_mem->block_mul_res,
                                   lsb_count,
                                   mul_mem->block_mul_res->num_radix_blocks);

  cuda_set_device(streams.gpu_index(0));
  fill_radix_from_lsb_msb_asymmetric<Torus, params>
      <<<rhs_block_count * lhs_block_count, params::degree / params::opt, 0,
         streams.stream(0)>>>((Torus *)mul_mem->vector_result_sb->ptr,
                              (Torus *)vector_result_lsb->ptr,
                              (Torus *)vector_result_msb.ptr, big_lwe_size,
                              lhs_block_count, rhs_block_count);
  check_cuda_error(cudaGetLastError());

  auto vector_result_sb = mul_mem->vector_result_sb;
  auto block_mul_res = mul_mem->block_mul_res;

  for (uint32_t i = 0; i < (uint32_t)lsb_count; i++) {
    uint64_t deg = block_mul_res->degrees[i];
    vector_result_sb->degrees[i] = deg;
    if (deg > 0)
      vector_result_sb->noise_levels[i] = 1;
  }

  if (lhs_block_count > 1) {
    for (uint32_t rhs = 0; rhs < rhs_block_count; rhs++) {
      for (uint32_t b = 0; b < lhs_block_count - 1; b++) {
        uint32_t src_idx =
            (uint32_t)lsb_count + rhs * (lhs_block_count - 1) + b;
        uint32_t dst_idx =
            (uint32_t)lsb_count + rhs * lhs_block_count + (b + 1);

        uint64_t deg = block_mul_res->degrees[src_idx];
        vector_result_sb->degrees[dst_idx] = deg;
        if (deg > 0)
          vector_result_sb->noise_levels[dst_idx] = 1;
      }
    }
  }
}

// Sums the evaluated block matrix columns and propagates the carries to form
// the final multiplication result. result = sum(matrix_columns) + added
//
template <typename Torus>
__host__ void mul_add_sum_matrix_and_propagate_carries(
    CudaStreams streams, CudaRadixCiphertextFFI *result,
    const CudaRadixCiphertextFFI *added,
    int_goldschmidt_division_buffer<Torus> *mem, uint32_t lhs_block_count,
    uint32_t rhs_block_count, int32_t rescaling, void *const *bsks,
    uint64_t *const *ksks) {

  auto mul_mem = mem->mul_mem;
  uint32_t num_terms = 2 * rhs_block_count;

  if (added != nullptr) {
    int32_t added_shift = (int32_t)rhs_block_count - rescaling;
    uint32_t added_term_offset = num_terms * lhs_block_count;
    CudaRadixCiphertextFFI added_term_slot;
    as_radix_ciphertext_slice<Torus>(
        &added_term_slot, mul_mem->vector_result_sb, added_term_offset,
        added_term_offset + lhs_block_count);
    blockshift_resize<Torus>(streams, &added_term_slot, added, added_shift);
    num_terms += 1;
  }

  CudaRadixCiphertextFFI sum_output;
  as_radix_ciphertext_slice<Torus>(
      &sum_output, mem->full_precision_product_buffer, 0, lhs_block_count);

  host_integer_partial_sum_ciphertexts_vec<Torus>(
      streams, &sum_output, mul_mem->vector_result_sb, bsks, ksks,
      mul_mem->sum_ciphertexts_mem, lhs_block_count, num_terms);

  host_propagate_single_carry<Torus>(streams, &sum_output, nullptr, nullptr,
                                     mul_mem->sc_prop_mem, bsks, ksks,
                                     outputFlag::FLAG_NONE, 0);

  int32_t final_shift = -(int32_t)rhs_block_count + rescaling;
  blockshift_resize<Torus>(streams, result, &sum_output, final_shift);
}

// Performs fixed-point multiplication with an optional addition and rescales
// the result by shifting blocks. result = (lhs * rhs) * (radix ^ rescaling) +
// added
//
template <typename Torus, class params>
__host__ void host_mul_add_fixed_point_with_rescaling(
    CudaStreams streams, CudaRadixCiphertextFFI *result,
    const CudaRadixCiphertextFFI *lhs, const CudaRadixCiphertextFFI *rhs,
    const CudaRadixCiphertextFFI *added, int32_t rescaling, uint32_t precision,
    int_goldschmidt_division_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {
  PUSH_RANGE("MUL_ADD")

  uint32_t result_len = result->num_radix_blocks;
  uint32_t rhs_block_count = rhs->num_radix_blocks;

  if (rhs_block_count == 0) {
    // RHS = 0  =>  LHS * RHS = 0
    // Result = (0 * Radix^rescaling) + Added  =>  Result = Added
    mul_add_copy_added_or_zero_result<Torus>(streams, result, added);
    POP_RANGE()
    return;
  }

  PUSH_RANGE("mul_add_clear_multiplication_buffers")
  // Buffer_Matrix = 0
  mul_add_clear_multiplication_buffers<Torus>(streams, mem);
  POP_RANGE()

  PUSH_RANGE("mul_add_prepare_and_pad_lhs")
  // LHS_ext = LHS * Radix^(rescaling)
  // (Pads with zeros and shifts LHS by the 'rescaling' factor)
  uint32_t padded_lhs_block_count = mul_add_prepare_and_pad_lhs<Torus>(
      streams, lhs, mem, result_len, rhs_block_count, rescaling);
  POP_RANGE()

  CudaRadixCiphertextFFI lhs_ext;
  as_radix_ciphertext_slice<Torus>(&lhs_ext, mem->padded_lhs_operand, 0,
                                   padded_lhs_block_count);

  PUSH_RANGE("mul_add_evaluate_cross_multiplication_matrix")
  // M[i, j] = LHS_ext[i] * RHS[j]
  // ∀ i ∈ [0, padded_lhs_block_count - 1], ∀ j ∈ [0, rhs_block_count - 1]
  mul_add_evaluate_cross_multiplication_matrix<Torus, params>(
      streams, mem->mul_mem, &lhs_ext, rhs, padded_lhs_block_count,
      rhs_block_count);
  POP_RANGE()

  PUSH_RANGE("mul_add_find_max_columns")
  // Threshold_k = argmax_k( weight(k) < 2^precision )
  // Finds the column index 'k' below which M[i, j] bits are too small to
  // matter.
  uint32_t block_columns_to_skip = mul_add_find_max_columns(
      mem->mul_mem->params.message_modulus, rhs_block_count, precision);
  POP_RANGE()

  PUSH_RANGE("mul_add_evaluate_bivariate_pbs_on_active_blocks")
  // M_eval[i, j] = PBS( M[i, j] )
  // ∀ (i, j) where (i + j) >= Threshold_k
  bool has_useful_blocks =
      mul_add_evaluate_bivariate_pbs_on_active_blocks<Torus>(
          streams, mem, padded_lhs_block_count, rhs_block_count,
          block_columns_to_skip, bsks, ksks);
  POP_RANGE()

  PUSH_RANGE("mul_add_copy_added_or_zero_result")
  if (!has_useful_blocks) {
    // Sum(M_eval) ≈ 0
    // Result = 0 + Added  =>  Result = Added
    mul_add_copy_added_or_zero_result<Torus>(streams, result, added);
    POP_RANGE()
    POP_RANGE()
    return;
  }
  POP_RANGE()

  PUSH_RANGE("mul_add_reassemble_evaluated_blocks")
  // Vector_LSB[k], Vector_MSB[k] <- M_eval[i, j]
  // Reassembles the 2D matrix into 1D arrays of Least/Most Significant Bits.
  mul_add_reassemble_evaluated_blocks<Torus, params>(
      streams, mem->mul_mem, padded_lhs_block_count, rhs_block_count,
      lhs_ext.lwe_dimension + 1);
  POP_RANGE()

  PUSH_RANGE("mul_add_sum_matrix_and_propagate_carries")
  // Result = Sum( M_eval ) + Added + Carries
  mul_add_sum_matrix_and_propagate_carries<Torus>(
      streams, result, added, mem, padded_lhs_block_count, rhs_block_count,
      rescaling, bsks, ksks);
  POP_RANGE()
  POP_RANGE()
}

// Wrapper for fixed-point multiplication without applying any shifting or
// rescaling. result = lhs * rhs + added
//
template <typename Torus, class params>
__host__ void host_mul_add_fixed_point(
    CudaStreams streams, CudaRadixCiphertextFFI *result,
    const CudaRadixCiphertextFFI *lhs, const CudaRadixCiphertextFFI *rhs,
    const CudaRadixCiphertextFFI *added, uint32_t precision,
    int_goldschmidt_division_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {
  host_mul_add_fixed_point_with_rescaling<Torus, params>(
      streams, result, lhs, rhs, added, 0, precision, mem, bsks, ksks);
}

// Normalizes the numerator and denominator by shifting out leading zeros to
// prepare for initial approximation. N = N * 2^lz, D = D * 2^lz
//
template <typename Torus, typename KSTorus>
__host__ void goldschmidt_normalize(CudaStreams streams,
                                    CudaRadixCiphertextFFI *d_is_zero,
                                    CudaRadixCiphertextFFI *leading_zeros_count,
                                    const CudaRadixCiphertextFFI *numerator,
                                    const CudaRadixCiphertextFFI *denominator,
                                    int_goldschmidt_division_buffer<Torus> *mem,
                                    void *const *bsks, KSTorus *const *ksks) {

  uint32_t num_blocks = numerator->num_radix_blocks;
  uint32_t intermediate_num_blocks = mem->intermediate_num_blocks;
  uint32_t batched_size = 3 * num_blocks;

  CudaRadixCiphertextFFI batched_nd;
  as_radix_ciphertext_slice<Torus>(
      &batched_nd, mem->full_precision_product_buffer, 0, batched_size);

  CudaRadixCiphertextFFI batched_d_view, batched_n_view;
  as_radix_ciphertext_slice<Torus>(&batched_d_view, &batched_nd, 0, num_blocks);
  as_radix_ciphertext_slice<Torus>(&batched_n_view, &batched_nd, num_blocks,
                                   batched_size);

  CudaRadixCiphertextFFI padded_leading_zeros_count;
  as_radix_ciphertext_slice<Torus>(&padded_leading_zeros_count,
                                   mem->padded_lhs_operand, 0, batched_size);

  host_integer_count_of_consecutive_bits<Torus, KSTorus>(
      streams, leading_zeros_count, denominator,
      mem->count_leading_zeros_buffer, bsks, ksks); // paral

  host_scalar_equality_check<Torus, KSTorus>(
      streams, d_is_zero, denominator, mem->d_zero_scalar,
      mem->is_denominator_zero_buffer, bsks, ksks, num_blocks,
      num_blocks); // paral

  blockshift_resize<Torus>(streams, &batched_d_view, denominator, 0); // kernel
  blockshift_resize<Torus>(streams, &batched_n_view, numerator, 0);

  blockshift_resize<Torus>(streams, &padded_leading_zeros_count,
                           leading_zeros_count, 0);

  host_shift_and_rotate_inplace<Torus, KSTorus>(
      streams, &batched_nd, &padded_leading_zeros_count,
      mem->normalize_batched_shift_buffer, bsks, ksks);

  int32_t d_shift_amount =
      (int32_t)intermediate_num_blocks - (int32_t)num_blocks;
  blockshift_resize<Torus>(streams, mem->current_denominator_Di,
                           &batched_d_view, d_shift_amount);

  int32_t n_shift_amount =
      (int32_t)intermediate_num_blocks - 2 * (int32_t)num_blocks;
  blockshift_resize<Torus>(streams, mem->current_numerator_Ni, &batched_n_view,
                           n_shift_amount);
}

// Looks up an initial approximation of 1/D and multiplies it with N and D to
// start the iterations. X0 is the initial scaling factor evaluated via a Lookup
// Table such that X0 ~ 1/D. N1 = N * X0, D1 = D * X0
//
template <typename Torus, class params>
__host__ void goldschmidt_initial_approximation(
    CudaStreams streams, CudaRadixCiphertextFFI *n_updated,
    CudaRadixCiphertextFFI *d_updated, const CudaRadixCiphertextFFI *numerator,
    const CudaRadixCiphertextFFI *denominator, uint32_t lut_precision,
    int_goldschmidt_division_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {

  uint32_t bits_per_block = log2_int(mem->params.message_modulus);
  uint32_t block_length_fp = mem->intermediate_num_blocks;

  CudaRadixCiphertextFFI denominator_msb_for_approx;
  CudaRadixCiphertextFFI initial_approximation_X0;
  CudaRadixCiphertextFFI is_approx_match_found;

  as_radix_ciphertext_slice<Torus>(&denominator_msb_for_approx, mem->x_long, 0,
                                   mem->num_x0_blocks);
  as_radix_ciphertext_slice<Torus>(
      &initial_approximation_X0, mem->next_numerator_Ni, 0, mem->num_x0_blocks);
  as_radix_ciphertext_slice<Torus>(&is_approx_match_found, mem->x_long,
                                   mem->num_x0_blocks, mem->num_x0_blocks + 1);

  int32_t shift_amount = (int32_t)((lut_precision + 1) / bits_per_block) -
                         (int32_t)block_length_fp;

  blockshift_resize<Torus>(streams, &denominator_msb_for_approx, denominator,
                           shift_amount);

  host_unchecked_match_value<Torus>(
      streams, &initial_approximation_X0, &is_approx_match_found,
      &denominator_msb_for_approx, mem->host_approx_lut_inputs,
      mem->host_approx_lut_outputs, mem->approx_lut_eval_buffer, bsks,
      (Torus *const *)ksks);

  uint32_t precision =
      bits_per_block * initial_approximation_X0.num_radix_blocks;

  uint32_t padding = initial_approximation_X0.num_radix_blocks;
  uint32_t stride = block_length_fp + padding;
  uint32_t batched_len = stride + block_length_fp;

  CudaRadixCiphertextFFI batched_lhs, batched_added, batched_result;

  as_radix_ciphertext_slice<Torus>(&batched_lhs, mem->mul_low_terms_assembled,
                                   0, batched_len);
  as_radix_ciphertext_slice<Torus>(&batched_added, mem->mul_low_terms_assembled,
                                   batched_len, 2 * batched_len);
  as_radix_ciphertext_slice<Torus>(&batched_result,
                                   mem->mul_low_terms_assembled,
                                   2 * batched_len, 3 * batched_len);

  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &batched_lhs, 0, batched_len);
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &batched_added, 0, batched_len);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &batched_lhs, 0, block_length_fp,
      numerator, 0, block_length_fp);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &batched_lhs, stride,
      batched_len, denominator, 0, block_length_fp);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &batched_added, 0,
      block_length_fp, numerator, 0, block_length_fp);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &batched_added, stride,
      batched_len, denominator, 0, block_length_fp);

  host_mul_add_fixed_point<Torus, params>(
      streams, &batched_result, &batched_lhs, &initial_approximation_X0,
      &batched_added, precision, mem, bsks, ksks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), n_updated, 0, block_length_fp,
      &batched_result, 0, block_length_fp);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), d_updated, 0, block_length_fp,
      &batched_result, stride, batched_len);
}

// Executes the core Goldschmidt loop to iteratively refine the quotient and
// drive the denominator to 1. Xi is the iterative correction factor computed as
// Xi = 2 - Di. N_{i+1} = N_i * Xi, D_{i+1} = D_i * Xi
//
template <typename Torus, class params>
__host__ void
goldschmidt_iterations(CudaStreams streams,
                       int_goldschmidt_division_buffer<Torus> *mem,
                       uint32_t iterations, uint32_t &current_precision_bits,
                       void *const *bsks, uint64_t *const *ksks) {

  uint32_t bits_per_block = log2_int(mem->params.message_modulus);
  uint32_t fixed_point_length = mem->intermediate_num_blocks;

  for (uint32_t i = 0; i < iterations; i++) {
    uint32_t precision_blocks =
        (current_precision_bits + bits_per_block - 1) / bits_per_block;
    uint32_t factor_x_highest_block = current_precision_bits / bits_per_block;
    uint32_t factor_x_lowest_block = factor_x_highest_block + precision_blocks;

    CudaRadixCiphertextFFI extracted_denominator_slice;
    int32_t current_denom_length =
        mem->current_denominator_Di->num_radix_blocks;

    int32_t extract_d_start_offset = factor_x_highest_block;
    int32_t extract_d_end_offset =
        factor_x_highest_block + current_denom_length;

    int32_t denom_slice_first_idx =
        std::max(0, current_denom_length - extract_d_end_offset);
    int32_t denom_slice_last_idx =
        std::max(0, std::min(current_denom_length,
                             current_denom_length - extract_d_start_offset));

    as_radix_ciphertext_slice<Torus>(
        &extracted_denominator_slice, mem->current_denominator_Di,
        denom_slice_first_idx, denom_slice_last_idx);

    uint32_t extracted_d_blocks_count =
        denom_slice_last_idx - denom_slice_first_idx;
    mem->x_long->num_radix_blocks = extracted_d_blocks_count;

    if (extracted_d_blocks_count > 0) {
      host_negation<Torus>(streams, mem->x_long, &extracted_denominator_slice,
                           mem->params.message_modulus,
                           mem->params.carry_modulus, extracted_d_blocks_count);
    }

    CudaRadixCiphertextFFI factor_x_slice;
    int32_t negated_d_length = mem->x_long->num_radix_blocks;
    int32_t extract_x_start_offset = 0;
    int32_t extract_x_end_offset =
        factor_x_lowest_block - factor_x_highest_block;

    int32_t factor_x_first_idx =
        std::max(0, negated_d_length - extract_x_end_offset);
    int32_t factor_x_last_idx =
        std::max(0, std::min(negated_d_length,
                             negated_d_length - extract_x_start_offset));

    as_radix_ciphertext_slice<Torus>(&factor_x_slice, mem->x_long,
                                     factor_x_first_idx, factor_x_last_idx);

    uint32_t target_precision_bits = factor_x_lowest_block * bits_per_block;
    int32_t rescaling_shift = -(int32_t)factor_x_highest_block;
    uint32_t rhs_block_count = factor_x_last_idx - factor_x_first_idx;

    mem->next_numerator_Ni->num_radix_blocks = fixed_point_length;

    if (i < iterations - 1) {
      mem->next_denominator_Di->num_radix_blocks = fixed_point_length;

      CudaRadixCiphertextFFI batched_lhs, batched_added, batched_result;

      uint32_t padding = rhs_block_count;
      uint32_t stride = fixed_point_length + padding;
      uint32_t batched_len = stride + fixed_point_length;

      as_radix_ciphertext_slice<Torus>(
          &batched_lhs, mem->mul_low_terms_assembled, 0, batched_len);
      as_radix_ciphertext_slice<Torus>(&batched_added,
                                       mem->mul_low_terms_assembled,
                                       batched_len, 2 * batched_len);
      as_radix_ciphertext_slice<Torus>(&batched_result,
                                       mem->mul_low_terms_assembled,
                                       2 * batched_len, 3 * batched_len);

      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &batched_lhs, 0,
          batched_len);
      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &batched_added, 0,
          batched_len);

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &batched_lhs, 0,
          fixed_point_length, mem->current_numerator_Ni, 0, fixed_point_length);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &batched_lhs, stride,
          batched_len, mem->current_denominator_Di, 0, fixed_point_length);

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &batched_added, 0,
          fixed_point_length, mem->current_numerator_Ni, 0, fixed_point_length);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &batched_added, stride,
          batched_len, mem->current_denominator_Di, 0, fixed_point_length);

      host_mul_add_fixed_point_with_rescaling<Torus, params>(
          streams, &batched_result, &batched_lhs, &factor_x_slice,
          &batched_added, rescaling_shift, target_precision_bits, mem, bsks,
          ksks);

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem->next_numerator_Ni, 0,
          fixed_point_length, &batched_result, 0, fixed_point_length);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem->next_denominator_Di, 0,
          fixed_point_length, &batched_result, stride, batched_len);

      current_precision_bits = 2 * current_precision_bits - 1;
      std::swap(mem->current_denominator_Di, mem->next_denominator_Di);

    } else {
      host_mul_add_fixed_point_with_rescaling<Torus, params>(
          streams, mem->next_numerator_Ni, mem->current_numerator_Ni,
          &factor_x_slice, mem->current_numerator_Ni, rescaling_shift,
          target_precision_bits, mem, bsks, ksks);
    }

    std::swap(mem->current_numerator_Ni, mem->next_numerator_Ni);
  }
}

// Computes the final quotient and remainder, applying corrections if the
// remainder is negative, and handles zero division. Q = floor(N/D), R = N - Q*D
//
template <typename Torus, class params>
__host__ void goldschmidt_finalize(CudaStreams streams,
                                   CudaRadixCiphertextFFI *quotient_out,
                                   CudaRadixCiphertextFFI *remainder_out,
                                   const CudaRadixCiphertextFFI *numerator,
                                   const CudaRadixCiphertextFFI *denominator,
                                   const CudaRadixCiphertextFFI *d_is_zero,
                                   int_goldschmidt_division_buffer<Torus> *mem,
                                   void *const *bsks, uint64_t *const *ksks) {
  // improve mem use

  uint32_t num_blocks = numerator->num_radix_blocks;

  int32_t q_shift = -(int32_t)(mem->intermediate_num_blocks - num_blocks);

  CudaRadixCiphertextFFI q_tmp, q_plus_1, q_is_ok, q_corrected, r_corrected,
      r_if_too_small;
  as_radix_ciphertext_slice<Torus>(&q_tmp, mem->next_numerator_Ni, 0,
                                   num_blocks);
  as_radix_ciphertext_slice<Torus>(&q_plus_1, mem->next_denominator_Di,
                                   num_blocks, 2 * num_blocks);
  as_radix_ciphertext_slice<Torus>(&q_is_ok, mem->x_long, num_blocks,
                                   num_blocks + 1);
  as_radix_ciphertext_slice<Torus>(&r_if_too_small, mem->x_long, 0, num_blocks);
  as_radix_ciphertext_slice<Torus>(&q_corrected, mem->next_numerator_Ni,
                                   num_blocks, 2 * num_blocks);
  as_radix_ciphertext_slice<Torus>(&r_corrected, mem->next_denominator_Di,
                                   num_blocks, 2 * num_blocks);

  blockshift_resize<Torus>(streams, &q_tmp, mem->current_numerator_Ni, q_shift);

  host_compute_terms_for_mul_low<Torus, params>(
      streams, mem->mul_low_terms_assembled, &q_tmp, denominator, bsks, ksks,
      mem->mul_mem);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     mem->numerator_bitnot, numerator);
  host_bitnot<Torus>(streams, mem->numerator_bitnot,
                     mem->params.message_modulus, mem->params.message_modulus,
                     mem->params.carry_modulus);

  uint32_t mul_terms_count = 2 * num_blocks;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->mul_low_terms_assembled,
      mul_terms_count * num_blocks, (mul_terms_count + 1) * num_blocks,
      mem->numerator_bitnot, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->mul_low_terms_assembled,
      (mul_terms_count + 1) * num_blocks, (mul_terms_count + 2) * num_blocks,
      mem->trivial_1, 0, num_blocks);

  host_integer_partial_sum_ciphertexts_vec<Torus>(
      streams, mem->r_partial_sum, mem->mul_low_terms_assembled, bsks, ksks,
      mem->finalize_mul_low_sum_mem, num_blocks, mul_terms_count + 2);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->r_partial_sum_batched, 0,
      num_blocks, mem->r_partial_sum, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->r_partial_sum_batched,
      num_blocks, 2 * num_blocks, mem->r_partial_sum, 0, num_blocks);

  host_apply_univariate_lut<Torus, uint64_t>(
      streams, mem->r_msg_and_carry_batched, mem->r_partial_sum_batched,
      mem->finalize_extract_invert_batched_lut, ksks, bsks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->r_message_blocks, 0,
      num_blocks, mem->r_msg_and_carry_batched, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->r_carry_blocks, 0,
      num_blocks, mem->r_msg_and_carry_batched, num_blocks, 2 * num_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->r_carry_shifted, 1,
      num_blocks, mem->r_carry_blocks, 0, num_blocks - 1);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem->r_carry_shifted, 0, 1,
      mem->trivial_msg_modulus_minus_1, 0, 1);

  host_add_and_propagate_single_carry<Torus, uint64_t>(
      streams, mem->r_message_blocks, mem->r_carry_shifted, nullptr, nullptr,
      mem->finalize_sc_prop_mem, bsks, ksks, outputFlag::FLAG_NONE,
      0); // paral ?

  host_add_and_propagate_single_carry<Torus, uint64_t>(
      streams, mem->r_message_blocks, mem->trivial_2, nullptr, nullptr,
      mem->finalize_sc_prop_mem, bsks, ksks, outputFlag::FLAG_NONE,
      0); // paral ?

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     mem->r_partial_sum, mem->r_message_blocks);

  host_integer_overflowing_sub<Torus>(streams, &r_if_too_small,
                                      mem->r_partial_sum, denominator, &q_is_ok,
                                      nullptr, mem->finalize_borrow_prop_mem,
                                      bsks, ksks, outputFlag::FLAG_OVERFLOW, 0);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &q_plus_1, &q_tmp);
  host_add_and_propagate_single_carry<Torus, uint64_t>(
      streams, &q_plus_1, mem->trivial_1, nullptr, nullptr,
      mem->finalize_sc_prop_mem, bsks, ksks, outputFlag::FLAG_NONE, 0);

  uint32_t batch_size = 2 * num_blocks;

  CudaRadixCiphertextFFI cmux_true_branch, cmux_false_branch, cmux_batch_result;

  as_radix_ciphertext_slice<Torus>(&cmux_true_branch, mem->padded_lhs_operand,
                                   0, batch_size);
  as_radix_ciphertext_slice<Torus>(&cmux_false_branch, mem->padded_lhs_operand,
                                   batch_size, 2 * batch_size);
  as_radix_ciphertext_slice<Torus>(
      &cmux_batch_result, mem->full_precision_product_buffer, 0, batch_size);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &cmux_true_branch, 0, num_blocks,
      &q_tmp, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &cmux_true_branch, num_blocks,
      batch_size, mem->r_partial_sum, 0, num_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &cmux_false_branch, 0,
      num_blocks, &q_plus_1, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &cmux_false_branch, num_blocks,
      batch_size, &r_if_too_small, 0, num_blocks);

  host_cmux<Torus, uint64_t>(streams, &cmux_batch_result, &q_is_ok,
                             &cmux_true_branch, &cmux_false_branch,
                             mem->finalize_cmux_mem, bsks, ksks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &cmux_true_branch, 0, num_blocks,
      mem->trivial_max, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &cmux_true_branch, num_blocks,
      batch_size, numerator, 0, num_blocks);

  host_cmux<Torus, uint64_t>(streams, &cmux_false_branch, d_is_zero,
                             &cmux_true_branch, &cmux_batch_result,
                             mem->finalize_cmux_mem, bsks, ksks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), quotient_out, 0, num_blocks,
      &cmux_false_branch, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), remainder_out, 0, num_blocks,
      &cmux_false_branch, num_blocks, batch_size);
}

// High-level host function that orchestrates the entire Goldschmidt division
// algorithm.
//
// 1. Normalize N and D by shifting out leading zeros so D's MSB is 1.
// 2. Fetch an initial approximation X0 ~ 1/D using a LUT, then compute N1 =
// N*X0 and D1 = D*X0.
// 3. Iteratively compute correction factors Xi = 2 - Di, updating N and D until
// D converges to 1 and N to the quotient.
// 4. Finalize by extracting the integer quotient Q, computing remainder R = N -
// Q*D, and applying corrections for negative remainders or division by zero. Q,
// R = N / D
//
template <typename Torus, class params>
__host__ void host_goldschmidt_division(
    CudaStreams streams, CudaRadixCiphertextFFI *quotient_out,
    CudaRadixCiphertextFFI *remainder_out,
    const CudaRadixCiphertextFFI *numerator,
    const CudaRadixCiphertextFFI *denominator,
    int_goldschmidt_division_buffer<Torus> *mem, uint32_t iterations,
    uint32_t lut_precision, void *const *bsks, uint64_t *const *ksks) {

  CudaRadixCiphertextFFI leading_zeros_count;
  as_radix_ciphertext_slice<Torus>(
      &leading_zeros_count,
      mem->count_leading_zeros_buffer->prepare_mem->tmp_ct, 0,
      mem->count_leading_zeros_buffer->counter_num_blocks);

  CudaRadixCiphertextFFI d_is_zero;
  as_radix_ciphertext_slice<Torus>(
      &d_is_zero, mem->is_denominator_zero_buffer->tmp_lwe_array_out, 0, 1);

  PUSH_RANGE("goldschmidt_normalize")
  goldschmidt_normalize<Torus, uint64_t>(streams, &d_is_zero,
                                         &leading_zeros_count, numerator,
                                         denominator, mem, bsks, ksks);
  POP_RANGE()

  PUSH_RANGE("goldschmidt_initial_approximation")
  goldschmidt_initial_approximation<Torus, params>(
      streams, mem->current_numerator_Ni, mem->current_denominator_Di,
      mem->current_numerator_Ni, mem->current_denominator_Di, lut_precision,
      mem, bsks, ksks);
  POP_RANGE()

  PUSH_RANGE("goldschmidt_iterations")
  uint32_t current_precision_bits = lut_precision;
  goldschmidt_iterations<Torus, params>(streams, mem, iterations,
                                        current_precision_bits, bsks, ksks);
  POP_RANGE()

  PUSH_RANGE("goldschmidt_finalize")
  goldschmidt_finalize<Torus, params>(streams, quotient_out, remainder_out,
                                      numerator, denominator, &d_is_zero, mem,
                                      bsks, ksks);
  POP_RANGE()
}

template <typename Torus>
__host__ uint64_t scratch_cuda_goldschmidt_division(
    CudaStreams streams, int_goldschmidt_division_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, uint32_t lut_precision,
    bool allocate_gpu_memory) {
  PUSH_RANGE("scratch_cuda_goldschmidt_division")
  uint64_t size_tracker = 0;

  *mem_ptr = new int_goldschmidt_division_buffer<Torus>(
      streams, params, num_radix_blocks, lut_precision, allocate_gpu_memory,
      size_tracker);
  POP_RANGE()

  return size_tracker;
}

#endif
