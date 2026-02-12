#pragma once

#include "device.h"
#include "integer/integer.h"
#include "integer/radix_ciphertext.h"
#include "integer/rerand.h"
#include "integer/rerand_utilities.h"
#include "utils/helper.cuh"
#include "utils/helper_profile.cuh"
#include "zk/zk_utilities.h"

template <typename Torus, class params>
void host_rerand_inplace(
    CudaStreams const streams, Torus *lwe_array,
    const Torus *lwe_flattened_encryptions_of_zero_compact_array_in,
    Torus *const *ksk, int_rerand_mem<Torus> *mem_ptr) {
  auto zero_lwes = mem_ptr->tmp_zero_lwes;
  auto num_lwes = mem_ptr->num_lwes;
  auto ksed_zero_lwes = mem_ptr->tmp_ksed_zero_lwes;
  auto lwe_trivial_indexes = mem_ptr->lwe_trivial_indexes;
  auto ksk_params = mem_ptr->params;
  auto output_dimension = ksk_params.small_lwe_dimension;
  auto input_dimension = ksk_params.big_lwe_dimension;
  auto ks_level = ksk_params.ks_level;
  auto ks_base_log = ksk_params.ks_base_log;
  auto message_modulus = ksk_params.message_modulus;
  auto carry_modulus = ksk_params.carry_modulus;

  GPU_ASSERT(sizeof(Torus) == 8,
             "Cuda error: expand is only supported on 64 bits");

  // Expand encryptions of zero
  // Wraps the input into a flattened_compact_lwe_lists type
  auto compact_lwe_lists = flattened_compact_lwe_lists<Torus>(
      const_cast<Torus *>(lwe_flattened_encryptions_of_zero_compact_array_in),
      &num_lwes, (uint32_t)1, input_dimension);
  auto h_expand_jobs = mem_ptr->h_expand_jobs;
  auto d_expand_jobs = mem_ptr->d_expand_jobs;

  auto output_index = 0;
  for (auto list_index = 0; list_index < compact_lwe_lists.num_compact_lists;
       ++list_index) {
    auto list = compact_lwe_lists.get_device_compact_list(list_index);
    for (auto lwe_index = 0; lwe_index < list.total_num_lwes; ++lwe_index) {
      h_expand_jobs[output_index] =
          expand_job<Torus>(list.get_mask(), list.get_body(lwe_index));
      output_index++;
    }
  }
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_expand_jobs, h_expand_jobs,
      safe_mul_sizeof<expand_job<Torus>>(compact_lwe_lists.total_num_lwes),
      streams.stream(0), streams.gpu_index(0), true);

  host_lwe_expand<Torus, params>(streams.stream(0), streams.gpu_index(0),
                                 zero_lwes, d_expand_jobs, num_lwes);

  // Keyswitch
  execute_keyswitch_async<Torus>(
      streams.get_ith(0), ksed_zero_lwes, lwe_trivial_indexes, zero_lwes,
      lwe_trivial_indexes, ksk, input_dimension, output_dimension, ks_base_log,
      ks_level, num_lwes, true, mem_ptr->ks_tmp_buf_vec);

  // Add ks output to ct
  // Check sizes
  CudaRadixCiphertextFFI lwes_ffi;
  into_radix_ciphertext(&lwes_ffi, lwe_array, num_lwes, output_dimension);
  CudaRadixCiphertextFFI ksed_zero_lwes_ffi;
  into_radix_ciphertext(&ksed_zero_lwes_ffi, ksed_zero_lwes, num_lwes,
                        output_dimension);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &lwes_ffi,
                       &lwes_ffi, &ksed_zero_lwes_ffi, num_lwes,
                       message_modulus, carry_modulus);
  release_cpu_radix_ciphertext_async(&lwes_ffi);
  release_cpu_radix_ciphertext_async(&ksed_zero_lwes_ffi);
  compact_lwe_lists.release();
}

template <typename Torus>
__host__ uint64_t scratch_cuda_rerand(CudaStreams streams,
                                      int_rerand_mem<Torus> **mem_ptr,
                                      uint32_t num_lwes,
                                      int_radix_params params,
                                      bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_rerand_mem<Torus>(streams, params, num_lwes,
                                       allocate_gpu_memory, size_tracker);
  return size_tracker;
}
