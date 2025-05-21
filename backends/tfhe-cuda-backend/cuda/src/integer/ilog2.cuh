#ifndef ILOG2_CUH
#define ILOG2_CUH

#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include <inttypes.h>

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

#endif
