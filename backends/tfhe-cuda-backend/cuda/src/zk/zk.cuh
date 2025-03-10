#ifndef CUDA_ZK_CUH
#define CUDA_ZK_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "expand.cuh"
#include "helper_multi_gpu.h"
#include "integer/integer_utilities.h"
#include "keyswitch/ks_enums.h"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/functions.cuh"
#include "utils/helper.cuh"
#include "utils/helper_multi_gpu.cuh"
#include "utils/kernel_dimensions.cuh"
#include "zk/zk_utilities.h"
#include <functional>

template <typename Torus>
__host__ void host_expand_without_verification(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, const Torus *lwe_compact_array_in,
    zk_expand_mem<Torus> *mem_ptr, KS_TYPE ks_type, void *const *bsks,
    Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {
  // Expand
  auto expanded_lwes = mem_ptr->tmp_expanded_lwes;
  auto num_lwes = mem_ptr->num_lwes;
  auto lwe_dimension = mem_ptr->params.big_lwe_dimension;
  auto d_compact_list_length_per_lwe = mem_ptr->d_compact_list_length_per_lwe;
  auto d_lwe_compact_input_indexes = mem_ptr->d_lwe_compact_input_indexes;
  if (sizeof(Torus) == 8) {
    cuda_lwe_expand_64(streams[0], gpu_indexes[0], expanded_lwes,
                       lwe_compact_array_in, lwe_dimension, num_lwes,
                       d_compact_list_length_per_lwe,
                       d_lwe_compact_input_indexes);

  } else
    PANIC("Cuda error: expand is only supported on 64 bits")

  // Keyswitch from small to big key if needed
  auto lut = mem_ptr->message_and_carry_extract_luts;

  if (ks_type == SMALL_TO_BIG) {
    auto ksed_small_to_big_expanded_lwes =
        mem_ptr->tmp_ksed_small_to_big_expanded_lwes;
    std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

    auto params = lut->params;
    auto big_lwe_dimension = params.big_lwe_dimension;
    auto small_lwe_dimension = params.small_lwe_dimension;
    auto ks_level = params.ks_level;
    auto ks_base_log = params.ks_base_log;

    // apply keyswitch to BIG
    execute_keyswitch_async<Torus>(
        streams, gpu_indexes, 1, ksed_small_to_big_expanded_lwes,
        lwe_trivial_indexes_vec[0], expanded_lwes, lwe_trivial_indexes_vec[0],
        ksks, small_lwe_dimension, big_lwe_dimension, ks_base_log, ks_level,
        num_lwes);
  }

  // Apply LUT
  cuda_memset_async(lwe_array_out, 0,
                    (lwe_dimension + 1) * num_lwes * 2 * sizeof(Torus),
                    streams[0], gpu_indexes[0]);
  auto output = new CudaRadixCiphertextFFI;
  into_radix_ciphertext(output, lwe_array_out, 2 * num_lwes, lwe_dimension);
  auto input = new CudaRadixCiphertextFFI;
  into_radix_ciphertext(input, expanded_lwes, 2 * num_lwes, lwe_dimension);

  auto message_and_carry_extract_luts = mem_ptr->message_and_carry_extract_luts;
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, output, input, bsks, ksks,
      ms_noise_reduction_key, message_and_carry_extract_luts, 2 * num_lwes);
}

template <typename Torus>
__host__ void scratch_cuda_expand_without_verification(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, zk_expand_mem<Torus> **mem_ptr,
    const uint32_t *num_lwes_per_compact_list, const bool *is_boolean_array,
    uint32_t num_compact_lists, int_radix_params params,
    bool allocate_gpu_memory) {

  *mem_ptr = new zk_expand_mem<Torus>(
      streams, gpu_indexes, gpu_count, params, num_lwes_per_compact_list,
      is_boolean_array, num_compact_lists, allocate_gpu_memory);
}

#endif // CUDA_ZK_CUH
