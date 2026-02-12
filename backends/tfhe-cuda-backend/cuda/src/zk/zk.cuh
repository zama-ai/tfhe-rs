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
#include "zk/zk_enums.h"
#include "zk/zk_utilities.h"
#include <functional>

/*
 * =============================================================================
 * GPU Expand Algorithm: Overview
 * =============================================================================
 *
 * The expand algorithm transforms compact ciphertexts into standard LWE
 * ciphertexts. Compact ciphertexts save space by sharing a single mask across
 * multiple encrypted messages.
 *
 * -----------------------------------------------------------------------------
 * INPUT STRUCTURE (lwe_flattened_compact_array_in)
 * -----------------------------------------------------------------------------
 *
 * A contiguous array of concatenated compact ciphertext lists:
 *
 *  ┌─────────────────────────────────────────────────────────────────────────┐
 *  │            lwe_flattened_compact_array_in (GPU memory)                  │
 *  └─────────────────────────────────────────────────────────────────────────┘
 *  ┌────────────────────────────────┬────────────────────────────────────────┐
 *  │      Compact List 0            │           Compact List 1 │...
 *  └────────────────────────────────┴────────────────────────────────────────┘
 *
 *  Each compact list structure:
 *  ┌─────────────────────────────────────────────┬────────┬────────┬─────────┐
 *  │  Shared Mask (lwe_dimension coefficients)   │ Body 0 │ Body 1 │ Body 2
 * │... │  [a_0, a_1, ..., a_{n-1}]                   │  b_0   │  b_1   │  b_2 │
 *  └─────────────────────────────────────────────┴────────┴────────┴─────────┘
 *  │<────────── lwe_dimension ──────────────────>│<── num_lwes_in_list ─────>│
 *
 * -----------------------------------------------------------------------------
 * EXPAND PROCESS
 * -----------------------------------------------------------------------------
 *
 * 1. LWE Expansion (lwe_expand kernel):
 *    Each (mask, body_i) pair becomes a standard LWE by rotating the mask
 *    by i positions: LWE_i = (rotate(mask, i), body_i)
 *
 * 2. Message/Carry Extraction (PBS with LUTs):
 *    Each expanded LWE contains packed data. PBS extracts both parts:
 *
 *    Input LWE_i ──PBS──> Output[2i]   (message extraction LUT)
 *                   └───> Output[2i+1] (carry extraction LUT)
 *
 *    For boolean values, sanitization LUTs clamp output to {0, 1}.
 *
 * -----------------------------------------------------------------------------
 * OUTPUT STRUCTURE (lwe_array_out)
 * -----------------------------------------------------------------------------
 *
 *  ┌─────────────────────────────────────────────────────────────────────────┐
 *  │             lwe_array_out (2 * num_lwes standard LWEs)                  │
 *  └─────────────────────────────────────────────────────────────────────────┘
 *  ┌──────────────┬──────────────┬──────────────┬──────────────┬─────────────┐
 *  │  LWE 0 (msg) │ LWE 0 (carry)│  LWE 1 (msg) │ LWE 1 (carry)│    ...      │
 *  └──────────────┴──────────────┴──────────────┴──────────────┴─────────────┘
 *
 *  Each output LWE: [mask (lwe_dimension), body (1)] = lwe_dimension + 1
 * elements
 *
 * See zk_utilities.h for detailed documentation on the is_boolean array and
 * LUT indexing logic.
 * =============================================================================
 */

template <typename Torus, class params>
__host__ void host_expand_without_verification(
    CudaStreams streams, Torus *lwe_array_out,
    const Torus *lwe_flattened_compact_array_in, zk_expand_mem<Torus> *mem_ptr,
    Torus *const *casting_keys, void *const *bsks, Torus *const *compute_ksks) {
  // Expand
  auto casting_key_type = mem_ptr->casting_key_type;
  auto expanded_lwes = mem_ptr->tmp_expanded_lwes;
  auto num_lwes = mem_ptr->num_lwes;
  auto lwe_dimension = (casting_key_type == KS_TYPE::BIG_TO_SMALL
                            ? mem_ptr->casting_params.big_lwe_dimension
                            : mem_ptr->casting_params.small_lwe_dimension);

  GPU_ASSERT(sizeof(Torus) == 8,
             "Cuda error: expand is only supported on 64 bits");

  // Wraps the input into a flattened_compact_lwe_lists type
  auto compact_lwe_lists = flattened_compact_lwe_lists(
      const_cast<Torus *>(lwe_flattened_compact_array_in),
      mem_ptr->num_lwes_per_compact_list, mem_ptr->num_compact_lists,
      lwe_dimension);
  auto h_expand_jobs = mem_ptr->h_expand_jobs;
  auto d_expand_jobs = mem_ptr->d_expand_jobs;

  auto output_index = 0;
  for (auto list_index = 0; list_index < compact_lwe_lists.num_compact_lists;
       ++list_index) {
    auto list = compact_lwe_lists.get_device_compact_list(list_index);
    for (auto lwe_index = 0; lwe_index < list.total_num_lwes; ++lwe_index) {
      h_expand_jobs[output_index] =
          expand_job(list.get_mask(), list.get_body(lwe_index));
      output_index++;
    }
  }
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_expand_jobs, h_expand_jobs,
      safe_mul_sizeof<expand_job<Torus>>(compact_lwe_lists.total_num_lwes),
      streams.stream(0), streams.gpu_index(0), true);

  if (mem_ptr->expand_kind == EXPAND_KIND::NO_CASTING) {
    host_lwe_expand<Torus, params>(streams.stream(0), streams.gpu_index(0),
                                   lwe_array_out, d_expand_jobs, num_lwes);
    return;
  }

  host_lwe_expand<Torus, params>(streams.stream(0), streams.gpu_index(0),
                                 expanded_lwes, d_expand_jobs, num_lwes);

  auto lwe_array_input = expanded_lwes;
  auto ksks = casting_keys;
  auto message_and_carry_extract_luts = mem_ptr->message_and_carry_extract_luts;

  auto lut = mem_ptr->message_and_carry_extract_luts;
  if (casting_key_type == SMALL_TO_BIG) {
    if (mem_ptr->expand_kind == EXPAND_KIND::SANITY_CHECK) {
      PANIC("SANITY_CHECK not supported for SMALL_TO_BIG casting");
    }
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
        streams.get_ith(0), ksed_small_to_big_expanded_lwes,
        lwe_trivial_indexes_vec[0], expanded_lwes, lwe_trivial_indexes_vec[0],
        casting_keys, casting_input_dimension, casting_output_dimension,
        casting_ks_base_log, casting_ks_level, num_lwes,
        lut->using_trivial_lwe_indexes, lut->ks_tmp_buf_vec);

    // In this case, the next keyswitch will use the compute ksk
    ksks = compute_ksks;
    lwe_array_input = ksed_small_to_big_expanded_lwes;
  }

  // Apply LUT
  cuda_memset_async(lwe_array_out, 0,
                    safe_mul_sizeof<Torus>((size_t)(lwe_dimension + 1),
                                           (size_t)num_lwes, (size_t)2),
                    streams.stream(0), streams.gpu_index(0));
  CudaRadixCiphertextFFI output;
  into_radix_ciphertext(&output, lwe_array_out, 2 * num_lwes, lwe_dimension);
  CudaRadixCiphertextFFI input;
  into_radix_ciphertext(&input, lwe_array_input, 2 * num_lwes, lwe_dimension);
  // This is a special case only for our noise sanity checks
  // If we are doing a SANITY_CHECK expand, we just apply the identity LUT
  // This replicates the CPU fallback behaviour of the casting expand
  if (mem_ptr->expand_kind == EXPAND_KIND::SANITY_CHECK) {
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &output, &input, bsks, ksks, mem_ptr->identity_lut,
        2 * num_lwes);
    return;
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &output, &input, bsks, ksks, message_and_carry_extract_luts,
      2 * num_lwes);
  release_cpu_radix_ciphertext_async(&input);
  release_cpu_radix_ciphertext_async(&output);
  compact_lwe_lists.release();
}

template <typename Torus>
__host__ uint64_t scratch_cuda_expand_without_verification(
    CudaStreams streams, zk_expand_mem<Torus> **mem_ptr,
    const uint32_t *num_lwes_per_compact_list, const bool *is_boolean_array,
    const uint32_t is_boolean_array_len, uint32_t num_compact_lists,
    int_radix_params computing_params, int_radix_params casting_params,
    KS_TYPE casting_key_type, bool allocate_gpu_memory,
    EXPAND_KIND expand_kind) {

  uint64_t size_tracker = 0;
  *mem_ptr = new zk_expand_mem<Torus>(
      streams, computing_params, casting_params, casting_key_type,
      num_lwes_per_compact_list, is_boolean_array, is_boolean_array_len,
      num_compact_lists, allocate_gpu_memory, size_tracker, expand_kind);
  return size_tracker;
}

#endif // CUDA_ZK_CUH
