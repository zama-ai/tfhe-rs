#ifndef ILOG2_CUH
#define ILOG2_CUH

#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "multiplication.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_prepare_count_of_consecutive_bits_buffer_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count,
    int_prepare_count_of_consecutive_bits_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, Direction dir,
    BitValue bit_value, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_prepare_count_of_consecutive_bits_buffer<Torus>(
      streams, gpu_indexes, gpu_count, dir, bit_value, params, num_radix_blocks,
      allocate_gpu_memory, &size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ uint64_t scratch_cuda_count_of_consecutive_bits_buffer_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_count_of_consecutive_bits_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, Direction dir,
    BitValue bit_value, uint32_t requested_flag_in, uint32_t uses_carry,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_count_of_consecutive_bits_buffer<Torus>(
      streams, gpu_indexes, gpu_count, dir, bit_value, params,
      requested_flag_in, uses_carry, num_radix_blocks, allocate_gpu_memory,
      &size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_cuda_prepare_count_of_consecutive_bits_buffer_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input,
    int_prepare_count_of_consecutive_bits_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI *tmp_ffi = mem_ptr->copy_ct;

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, tmp_ffi, input, bsks, ksks,
      ms_noise_reduction_key, mem_ptr->uni_lut, output->num_radix_blocks);

  if (mem_ptr->dir == LEADING) {
    host_radix_blocks_reverse_inplace<Torus>((cudaStream_t *)streams,
                                             gpu_indexes, tmp_ffi);
  }

  host_compute_prefix_sum_hillis_steele<Torus>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, output, tmp_ffi,
      mem_ptr->bi_lut, bsks, ksks, ms_noise_reduction_key,
      output->num_radix_blocks);
}

template <typename Torus>
__host__ void host_cuda_count_of_consecutive_bits_buffer_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input,
    int_count_of_consecutive_bits_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  // Prepare count of consecutive bits
  //
  if (input->num_radix_blocks != mem_ptr->prepared->num_radix_blocks) {
    PANIC("Cuda error: input's number of radix blocks should be equal to the "
          "output's number of radix blocks");
  }

  auto *mem_prep = (int_prepare_count_of_consecutive_bits_buffer<Torus>
                        *)(mem_ptr->prepare_buf);

  host_cuda_prepare_count_of_consecutive_bits_buffer_kb(
      streams, gpu_indexes, gpu_count, mem_ptr->prepared, input, mem_prep, bsks,
      ksks, ms_noise_reduction_key);

  // Compute sum of consecutive bits
  //
  auto *terms_ffi = (CudaRadixCiphertextFFI *)mem_ptr->terms;

  for (uint32_t i = 0; i < mem_ptr->prepared->num_radix_blocks; ++i) {

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], terms_ffi, i * mem_ptr->counter_num_blocks,
        i * mem_ptr->counter_num_blocks + 1, mem_ptr->prepared, i, i + 1);
  }

  auto *mem_sum = (int_sum_ciphertexts_vec_memory<Torus> *)(mem_ptr->sum_mem);

  if (terms_ffi->num_radix_blocks % output->num_radix_blocks != 0) {
    PANIC("Cuda error: input vector length should be a multiple of the "
          "output's number of radix blocks");
  }

  switch (mem_sum->params.polynomial_size) {
  case 512:
    host_integer_partial_sum_ciphertexts_vec_kb<Torus, AmortizedDegree<512>>(
        streams, gpu_indexes, gpu_count, output, terms_ffi, bsks,
        (uint64_t **)ksks, ms_noise_reduction_key, mem_sum,
        output->num_radix_blocks,
        terms_ffi->num_radix_blocks / output->num_radix_blocks, nullptr);
    break;
  case 1024:
    host_integer_partial_sum_ciphertexts_vec_kb<Torus, AmortizedDegree<1024>>(
        streams, gpu_indexes, gpu_count, output, terms_ffi, bsks,
        (uint64_t **)ksks, ms_noise_reduction_key, mem_sum,
        output->num_radix_blocks,
        terms_ffi->num_radix_blocks / output->num_radix_blocks, nullptr);
    break;
  case 2048:
    host_integer_partial_sum_ciphertexts_vec_kb<Torus, AmortizedDegree<2048>>(
        streams, gpu_indexes, gpu_count, output, terms_ffi, bsks,
        (uint64_t **)ksks, ms_noise_reduction_key, mem_sum,
        output->num_radix_blocks,
        terms_ffi->num_radix_blocks / output->num_radix_blocks, nullptr);
    break;
  case 4096:
    host_integer_partial_sum_ciphertexts_vec_kb<Torus, AmortizedDegree<4096>>(
        streams, gpu_indexes, gpu_count, output, terms_ffi, bsks,
        (uint64_t **)ksks, ms_noise_reduction_key, mem_sum,
        output->num_radix_blocks,
        terms_ffi->num_radix_blocks / output->num_radix_blocks, nullptr);
    break;
  case 8192:
    host_integer_partial_sum_ciphertexts_vec_kb<Torus, AmortizedDegree<8192>>(
        streams, gpu_indexes, gpu_count, output, terms_ffi, bsks,
        (uint64_t **)ksks, ms_noise_reduction_key, mem_sum,
        output->num_radix_blocks,
        terms_ffi->num_radix_blocks / output->num_radix_blocks, nullptr);
    break;
  case 16384:
    host_integer_partial_sum_ciphertexts_vec_kb<Torus, AmortizedDegree<16384>>(
        streams, gpu_indexes, gpu_count, output, terms_ffi, bsks,
        (uint64_t **)ksks, ms_noise_reduction_key, mem_sum,
        output->num_radix_blocks,
        terms_ffi->num_radix_blocks / output->num_radix_blocks, nullptr);
    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial "
          "size. Supported N's are powers of two in the interval "
          "[256..16384].");
  }

  // Propagate single carry
  //
  auto *mem_scp = (int_sc_prop_memory<Torus> *)(mem_ptr->scp_mem);

  host_propagate_single_carry<Torus>(
      streams, gpu_indexes, gpu_count, output, mem_ptr->out_carry,
      mem_ptr->in_carry, mem_scp, bsks, (uint64_t **)ksks,
      ms_noise_reduction_key, mem_scp->requested_flag, mem_scp->use_carry);
}

#endif
