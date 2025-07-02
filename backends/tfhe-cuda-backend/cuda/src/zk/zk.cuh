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
    uint32_t gpu_count, Torus *lwe_array_out,
    const Torus *lwe_flattened_compact_array_in, zk_expand_mem<Torus> *mem_ptr,
    Torus *const *casting_keys, void *const *bsks, Torus *const *compute_ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {
  // Expand
  auto casting_key_type = mem_ptr->casting_key_type;
  auto expanded_lwes = mem_ptr->tmp_expanded_lwes;
  auto num_lwes = mem_ptr->num_lwes;
  auto lwe_dimension = (casting_key_type == KS_TYPE::BIG_TO_SMALL
                            ? mem_ptr->casting_params.big_lwe_dimension
                            : mem_ptr->casting_params.small_lwe_dimension);
  auto d_lwe_compact_input_indexes = mem_ptr->d_lwe_compact_input_indexes;
  auto d_body_id_per_compact_list = mem_ptr->d_body_id_per_compact_list;
  if (sizeof(Torus) == 8) {
    cuda_lwe_expand_64(streams[0], gpu_indexes[0], expanded_lwes,
                       lwe_flattened_compact_array_in, lwe_dimension, num_lwes,
                       d_lwe_compact_input_indexes, d_body_id_per_compact_list);

  } else
    PANIC("Cuda error: expand is only supported on 64 bits")

  auto ksks = casting_keys;
  auto lwe_array_input = expanded_lwes;
  auto message_and_carry_extract_luts = mem_ptr->message_and_carry_extract_luts;

  auto lut = mem_ptr->message_and_carry_extract_luts;
  if (casting_key_type == SMALL_TO_BIG) {
    // Keyswitch from small to big key if needed
    auto ksed_small_to_big_expanded_lwes =
        mem_ptr->tmp_ksed_small_to_big_expanded_lwes;
    std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

    auto casting_params = mem_ptr->casting_params;
    auto casting_output_dimension = casting_params.big_lwe_dimension;
    auto casting_input_dimension = casting_params.small_lwe_dimension;
    auto casting_ks_level = casting_params.ks_level;
    auto casting_ks_base_log = casting_params.ks_base_log;

    // apply keyswitch to BIG
    execute_keyswitch_async<Torus>(
        streams, gpu_indexes, 1, ksed_small_to_big_expanded_lwes,
        lwe_trivial_indexes_vec[0], expanded_lwes, lwe_trivial_indexes_vec[0],
        casting_keys, casting_input_dimension, casting_output_dimension,
        casting_ks_base_log, casting_ks_level, num_lwes);

    // In this case, the next keyswitch will use the compute ksk
    ksks = compute_ksks;
    lwe_array_input = ksed_small_to_big_expanded_lwes;
  }

  // Apply LUT
  cuda_memset_async(lwe_array_out, 0,
                    (lwe_dimension + 1) * num_lwes * 2 * sizeof(Torus),
                    streams[0], gpu_indexes[0]);
  auto output = new CudaRadixCiphertextFFI;
  into_radix_ciphertext(output, lwe_array_out, 2 * num_lwes, lwe_dimension);
  auto input = new CudaRadixCiphertextFFI;
  into_radix_ciphertext(input, lwe_array_input, 2 * num_lwes, lwe_dimension);
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, output, input, bsks, ksks,
      ms_noise_reduction_key, message_and_carry_extract_luts, 2 * num_lwes);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_expand_without_verification(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, zk_expand_mem<Torus> **mem_ptr,
    const uint32_t *num_lwes_per_compact_list, const bool *is_boolean_array,
    uint32_t num_compact_lists, int_radix_params computing_params,
    int_radix_params casting_params, KS_TYPE casting_key_type,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new zk_expand_mem<Torus>(
      streams, gpu_indexes, gpu_count, computing_params, casting_params,
      casting_key_type, num_lwes_per_compact_list, is_boolean_array,
      num_compact_lists, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

#endif // CUDA_ZK_CUH
