#ifndef CUDA_INTEGER_CMUX_CUH
#define CUDA_INTEGER_CMUX_CUH

#include "integer.cuh"
#include "integer/cmux.h"
#include "radix_ciphertext.cuh"

template <typename Torus, typename KSTorus>
__host__ void zero_out_if(CudaStreams streams,
                          CudaRadixCiphertextFFI *lwe_array_out,
                          CudaRadixCiphertextFFI const *lwe_array_input,
                          CudaRadixCiphertextFFI const *lwe_condition,
                          int_zero_out_if_buffer<Torus> *mem_ptr,
                          int_radix_lut<Torus> *predicate, void *const *bsks,
                          KSTorus *const *ksks, uint32_t num_radix_blocks) {
  PANIC_IF_FALSE(
      lwe_array_out->num_radix_blocks >= num_radix_blocks &&
          lwe_array_input->num_radix_blocks >= num_radix_blocks,
      "Cuda error: input or output radix ciphertexts does not have enough "
      "blocks");

  PANIC_IF_FALSE(
      lwe_array_out->lwe_dimension == lwe_array_input->lwe_dimension &&
          lwe_array_input->lwe_dimension == lwe_condition->lwe_dimension,
      "Cuda error: input and output radix ciphertexts must have the same "
      "lwe dimension");

  cuda_set_device(streams.gpu_index(0));
  auto params = mem_ptr->params;

  // We can't use integer_radix_apply_bivariate_lookup_table since the
  // second operand is not an array
  auto tmp_lwe_array_input = mem_ptr->tmp;
  host_pack_bivariate_blocks_with_single_block<Torus>(
      streams, tmp_lwe_array_input, predicate->lwe_indexes_in, lwe_array_input,
      lwe_condition, predicate->lwe_indexes_in, params.message_modulus,
      num_radix_blocks);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, lwe_array_out, tmp_lwe_array_input, bsks, ksks, predicate,
      num_radix_blocks);
}

template <typename Torus, typename KSTorus>
__host__ void host_cmux(CudaStreams streams,
                        CudaRadixCiphertextFFI *lwe_array_out,
                        CudaRadixCiphertextFFI const *lwe_condition,
                        CudaRadixCiphertextFFI const *lwe_array_true,
                        CudaRadixCiphertextFFI const *lwe_array_false,
                        int_cmux_buffer<Torus> *mem_ptr, void *const *bsks,
                        KSTorus *const *ksks) {

  if (lwe_array_out->num_radix_blocks != lwe_array_true->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  if (lwe_array_out->num_radix_blocks != lwe_array_false->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")

  auto num_radix_blocks = lwe_array_out->num_radix_blocks;
  auto params = mem_ptr->params;
  Torus lwe_size = params.big_lwe_dimension + 1;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->buffer_in, 0,
      num_radix_blocks, lwe_array_true, 0, num_radix_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->buffer_in,
      num_radix_blocks, 2 * num_radix_blocks, lwe_array_false, 0,
      num_radix_blocks);
  for (uint i = 0; i < 2 * num_radix_blocks; i++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->condition_array, i,
        i + 1, lwe_condition, 0, 1);
  }
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, mem_ptr->buffer_out, mem_ptr->buffer_in,
      mem_ptr->condition_array, bsks, ksks, mem_ptr->predicate_lut,
      2 * num_radix_blocks, params.message_modulus);

  // If the condition was true, true_ct will have kept its value and false_ct
  // will be 0 If the condition was false, true_ct will be 0 and false_ct will
  // have kept its value
  CudaRadixCiphertextFFI mem_true;
  CudaRadixCiphertextFFI mem_false;
  as_radix_ciphertext_slice<Torus>(&mem_true, mem_ptr->buffer_out, 0,
                                   num_radix_blocks);
  as_radix_ciphertext_slice<Torus>(&mem_false, mem_ptr->buffer_out,
                                   num_radix_blocks, 2 * num_radix_blocks);

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &mem_true,
                       &mem_true, &mem_false, num_radix_blocks,
                       params.message_modulus, params.carry_modulus);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, lwe_array_out, &mem_true, bsks, ksks,
      mem_ptr->message_extract_lut, num_radix_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_cmux(CudaStreams streams,
                                    int_cmux_buffer<Torus> **mem_ptr,
                                    std::function<Torus(Torus)> predicate_lut_f,
                                    uint32_t num_radix_blocks,
                                    int_radix_params params,
                                    bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_cmux_buffer<Torus>(streams, predicate_lut_f, params,
                                        num_radix_blocks, allocate_gpu_memory,
                                        size_tracker);
  return size_tracker;
}

// Batched CMUX: for each of num_entries ciphertexts, selects lwe_array_true
// where the condition is 1, lwe_array_false where the condition is 0.
// Each condition in lwe_conditions is a single LWE block per entry.
//
// Default mode (replicate_true == false):
//
//  lwe_conditions   lwe_array_true     lwe_array_false
//  (1 block each)   (B blocks/entry)   (B blocks/entry)
//  ┌──┬──┬───┬──┐   ┌──┬──┬───┬──┐    ┌──┬──┬───┬──┐
//  │c0│c1│...│cN│   │t0│t1│...│tN│    │f0│f1│...│fN│
//  └──┴──┴───┴──┘   └──┴──┴───┴──┘    └──┴──┴───┴──┘
//
//  o0 = (c0==1) ? t0 : f0
//  o1 = (c1==1) ? t1 : f1
//       ...
//  oN = (cN==1) ? tN : fN
//
//                    lwe_array_out
//                    (B blocks/entry)
//                    ┌──┬──┬───┬──┐
//                    │o0│o1│...│oN│
//                    └──┴──┴───┴──┘
//
// Replicate mode (replicate_true == true):
// lwe_array_true is a single ciphertext of B blocks, reused for every entry.
//
//  lwe_conditions   lwe_array_true     lwe_array_false
//  (1 block each)   (B blocks, shared)  (B blocks/entry)
//  ┌──┬──┬───┬──┐   ┌──────┐            ┌──┬──┬───┬──┐
//  │c0│c1│...│cN│   │  t   │            │f0│f1│...│fN│
//  └──┴──┴───┴──┘   └──────┘            └──┴──┴───┴──┘
//
//  o0 = (c0==1) ? t : f0
//  o1 = (c1==1) ? t : f1
//       ...
//  oN = (cN==1) ? t : fN
//
//                    lwe_array_out
//                    (B blocks/entry)
//                    ┌──┬──┬───┬──┐
//                    │o0│o1│...│oN│
//                    └──┴──┴───┴──┘
template <typename Torus, typename KSTorus>
__host__ void
host_cmux_batch(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
                CudaRadixCiphertextFFI const *lwe_array_true,
                CudaRadixCiphertextFFI const *lwe_array_false,
                CudaRadixCiphertextFFI const *lwe_conditions,
                int_cmux_batch_buffer<Torus> *mem_ptr, void *const *bsks,
                KSTorus *const *ksks, uint32_t num_entries,
                uint32_t num_blocks_per_ct, bool replicate_true = false) {

  auto params = mem_ptr->params;
  uint32_t total_num_blocks =
      static_cast<uint32_t>(safe_mul(static_cast<size_t>(num_entries),
                                     static_cast<size_t>(num_blocks_per_ct)));

  cuda_set_device(streams.gpu_index(0));

  // Step 1: pack bivariate CMUX inputs
  // For each entry, put (true_value, condition) into the true branch and
  // (false_value, condition) into the false branch.
  CudaRadixCiphertextFFI packed_true, packed_false;
  as_radix_ciphertext_slice<Torus>(&packed_true, mem_ptr->tmp_packed, 0,
                                   total_num_blocks);
  as_radix_ciphertext_slice<Torus>(&packed_false, mem_ptr->tmp_packed,
                                   total_num_blocks, 2 * total_num_blocks);

  host_pack_bivariate_blocks_with_per_ct_single_block<Torus>(
      streams, &packed_true, lwe_array_true, lwe_conditions,
      params.message_modulus, num_entries, num_blocks_per_ct, replicate_true);

  host_pack_bivariate_blocks_with_per_ct_single_block<Torus>(
      streams, &packed_false, lwe_array_false, lwe_conditions,
      params.message_modulus, num_entries, num_blocks_per_ct);

  // Step 2: evaluate CMUX predicate on both branches
  // The LUT zeroes out the branch that does not match: true branch is zeroed
  // where condition==0, false branch is zeroed where condition==1.
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->buffer_out, mem_ptr->tmp_packed, bsks, ksks,
      mem_ptr->predicate_lut, 2 * total_num_blocks);

  // Step 3: combine branches
  // Exactly one branch is non-zero per entry, so addition yields the CMUX
  // result.
  CudaRadixCiphertextFFI true_out, false_out;
  as_radix_ciphertext_slice<Torus>(&true_out, mem_ptr->buffer_out, 0,
                                   total_num_blocks);
  as_radix_ciphertext_slice<Torus>(&false_out, mem_ptr->buffer_out,
                                   total_num_blocks, 2 * total_num_blocks);

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &true_out,
                       &true_out, &false_out, total_num_blocks,
                       params.message_modulus, params.carry_modulus);

  // Step 4: message extraction
  // Clean up noise and carry bits introduced by the addition.
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, lwe_array_out, &true_out, bsks, ksks,
      mem_ptr->message_extract_lut, total_num_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_cmux_batch(
    CudaStreams streams, int_cmux_batch_buffer<Torus> **mem_ptr,
    std::function<Torus(Torus)> predicate_lut_f, uint32_t num_entries,
    uint32_t num_blocks_per_ct, int_radix_params params,
    bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_cmux_batch_buffer<Torus>(
      streams, predicate_lut_f, params, num_entries, num_blocks_per_ct,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}
#endif
