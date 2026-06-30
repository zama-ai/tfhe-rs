#ifndef CUDA_INTEGER_OPRF_CUH
#define CUDA_INTEGER_OPRF_CUH

#include "integer/integer.cuh"
#include "integer/oprf.h"
#include "integer/rerand.cuh"
#include "integer/scalar_mul.cuh"
#include "integer/scalar_shifts.cuh"

template <typename Torus>
uint64_t scratch_cuda_integer_grouped_oprf(
    CudaStreams streams, int_grouped_oprf_memory<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks_to_process,
    uint32_t message_bits_per_block, uint64_t total_random_bits,
    bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;

  *mem_ptr = new int_grouped_oprf_memory<Torus>(
      streams, params, num_blocks_to_process, message_bits_per_block,
      total_random_bits, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
void host_integer_grouped_oprf(CudaStreams streams,
                               CudaRadixCiphertextFFI *radix_lwe_out,
                               const Torus *seeded_lwe_input,
                               uint32_t num_blocks_to_process,
                               int_grouped_oprf_memory<Torus> *mem_ptr,
                               void *const *bsks) {

  auto active_streams = streams.active_gpu_subset(num_blocks_to_process,
                                                  mem_ptr->params.pbs_type);
  auto lut = mem_ptr->luts;

  if (active_streams.count() == 1) {
    execute_pbs_async<Torus, Torus>(
        streams.get_ith(0), (Torus *)(radix_lwe_out->ptr), lut->lwe_indexes_out,
        lut->lut_vec, lut->lut_indexes_vec,
        const_cast<Torus *>(seeded_lwe_input), lut->lwe_indexes_in, bsks,
        lut->buffer, mem_ptr->params.glwe_dimension,
        mem_ptr->params.small_lwe_dimension, mem_ptr->params.polynomial_size,
        mem_ptr->params.pbs_base_log, mem_ptr->params.pbs_level,
        mem_ptr->params.grouping_factor, num_blocks_to_process,
        mem_ptr->params.pbs_type, 1, 0);
  } else {
    std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
    std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
    std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

    lut->multi_gpu_scatter_barrier.local_streams_wait_for_stream_0(
        active_streams);

    PUSH_RANGE("scatter")
    multi_gpu_scatter_lwe_async<Torus>(
        active_streams, lwe_array_in_vec, seeded_lwe_input, lut->lwe_indexes_in,
        lut->using_trivial_lwe_indexes, lut->lwe_aligned_vec, lut->event_pool,
        active_streams.count(), num_blocks_to_process,
        mem_ptr->params.small_lwe_dimension + 1);
    POP_RANGE()

    execute_pbs_async<Torus, Torus>(
        active_streams, lwe_after_pbs_vec, lwe_trivial_indexes_vec,
        lut->lut_vec, lut->lut_indexes_vec, lwe_array_in_vec,
        lwe_trivial_indexes_vec, bsks, lut->buffer,
        mem_ptr->params.glwe_dimension, mem_ptr->params.small_lwe_dimension,
        mem_ptr->params.polynomial_size, mem_ptr->params.pbs_base_log,
        mem_ptr->params.pbs_level, mem_ptr->params.grouping_factor,
        num_blocks_to_process, mem_ptr->params.pbs_type, 1, 0);

    PUSH_RANGE("gather")
    multi_gpu_gather_lwe_async<Torus>(
        active_streams, (Torus *)radix_lwe_out->ptr, lwe_after_pbs_vec,
        lut->lwe_indexes_out, lut->using_trivial_lwe_indexes,
        lut->lwe_aligned_vec, lut->event_pool, num_blocks_to_process,
        mem_ptr->params.big_lwe_dimension + 1);
    POP_RANGE()
    lut->multi_gpu_gather_barrier.stream_0_wait_for_local_streams(
        active_streams);
  }

  for (uint32_t i = 0; i < num_blocks_to_process; i++) {
    auto lut_index = mem_ptr->h_lut_indexes[i];
    radix_lwe_out->degrees[i] = mem_ptr->luts->degrees[lut_index];
    radix_lwe_out->noise_levels[i] = NoiseLevel::NOMINAL;
  }

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), radix_lwe_out,
                       radix_lwe_out, mem_ptr->plaintext_corrections,
                       num_blocks_to_process, mem_ptr->params.message_modulus,
                       mem_ptr->params.carry_modulus);
}

template <typename Torus>
uint64_t scratch_cuda_integer_grouped_oprf_custom_range(
    CudaStreams streams, int_grouped_oprf_custom_range_memory<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks_intermediate,
    uint32_t message_bits_per_block, uint64_t num_input_random_bits,
    uint32_t num_scalar_bits, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;

  *mem_ptr = new int_grouped_oprf_custom_range_memory<Torus>(
      streams, params, num_blocks_intermediate, message_bits_per_block,
      num_input_random_bits, num_scalar_bits, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
void host_integer_grouped_oprf_custom_range(
    CudaStreams streams, CudaRadixCiphertextFFI *radix_lwe_out,
    uint32_t num_blocks_intermediate, const Torus *seeded_lwe_input,
    const Torus *decomposed_scalar, const Torus *has_at_least_one_set,
    uint32_t num_scalars, uint32_t shift,
    int_grouped_oprf_custom_range_memory<Torus> *mem_ptr, void *const *bsks,
    void *const *compute_bsks, Torus *const *ksks) {

  CudaRadixCiphertextFFI *computation_buffer = mem_ptr->tmp_oprf_output;
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), computation_buffer, 0,
      num_blocks_intermediate);

  host_integer_grouped_oprf<Torus>(
      streams, computation_buffer, seeded_lwe_input,
      mem_ptr->num_random_input_blocks, mem_ptr->grouped_oprf_memory, bsks);

  host_integer_scalar_mul_radix<Torus>(
      streams, computation_buffer, decomposed_scalar, has_at_least_one_set,
      mem_ptr->scalar_mul_buffer, compute_bsks, ksks,
      mem_ptr->params.message_modulus, num_scalars);

  host_logical_scalar_shift_inplace<Torus>(
      streams, computation_buffer, shift, mem_ptr->logical_scalar_shift_buffer,
      compute_bsks, ksks, num_blocks_intermediate);

  uint32_t num_blocks_output = radix_lwe_out->num_radix_blocks;
  uint32_t blocks_to_copy =
      std::min(num_blocks_output, num_blocks_intermediate);

  if (blocks_to_copy > 0) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), radix_lwe_out, 0,
        blocks_to_copy, computation_buffer, 0, blocks_to_copy);
  }

  if (num_blocks_output > blocks_to_copy) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), radix_lwe_out, blocks_to_copy,
        num_blocks_output);
  }
}

// Composes the plain custom-range OPRF scratch with a re-randomization scratch
// sized for the freshly generated random blocks.
template <typename Torus>
struct int_grouped_oprf_custom_range_with_rerand_memory {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_grouped_oprf_custom_range_memory<Torus> *oprf_memory;
  int_rerand_mem<Torus> *rerand_memory;

  int_grouped_oprf_custom_range_with_rerand_memory(
      CudaStreams streams, int_radix_params params,
      int_radix_params rerand_params, uint32_t num_blocks_intermediate,
      uint32_t message_bits_per_block, uint64_t num_input_random_bits,
      uint32_t num_scalar_bits, RERAND_MODE rerand_mode,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->oprf_memory = new int_grouped_oprf_custom_range_memory<Torus>(
        streams, params, num_blocks_intermediate, message_bits_per_block,
        num_input_random_bits, num_scalar_bits, allocate_gpu_memory,
        size_tracker);

    this->rerand_memory = new int_rerand_mem<Torus>(
        streams, rerand_params, this->oprf_memory->num_random_input_blocks,
        rerand_mode, allocate_gpu_memory, size_tracker);
  }

  void release(CudaStreams streams) {
    this->oprf_memory->release(streams);
    delete this->oprf_memory;
    this->oprf_memory = nullptr;

    this->rerand_memory->release(streams);
    delete this->rerand_memory;
    this->rerand_memory = nullptr;
  }
};

template <typename Torus>
uint64_t scratch_cuda_integer_grouped_oprf_custom_range_with_rerand(
    CudaStreams streams,
    int_grouped_oprf_custom_range_with_rerand_memory<Torus> **mem_ptr,
    int_radix_params params, int_radix_params rerand_params,
    uint32_t num_blocks_intermediate, uint32_t message_bits_per_block,
    uint64_t num_input_random_bits, uint32_t num_scalar_bits,
    RERAND_MODE rerand_mode, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;

  *mem_ptr = new int_grouped_oprf_custom_range_with_rerand_memory<Torus>(
      streams, params, rerand_params, num_blocks_intermediate,
      message_bits_per_block, num_input_random_bits, num_scalar_bits,
      rerand_mode, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

// Same pipeline as host_integer_grouped_oprf_custom_range, but re-randomizes
// the freshly generated random blocks after the grouped OPRF and before the
// range mapping, matching the CPU implementation so the result stays
// equivalent.
template <typename Torus, class params>
void host_integer_grouped_oprf_custom_range_with_rerand(
    CudaStreams streams, CudaRadixCiphertextFFI *radix_lwe_out,
    uint32_t num_blocks_intermediate, const Torus *seeded_lwe_input,
    const Torus *decomposed_scalar, const Torus *has_at_least_one_set,
    uint32_t num_scalars, uint32_t shift,
    const Torus *lwe_flattened_encryptions_of_zero_compact_array_in,
    int_grouped_oprf_custom_range_with_rerand_memory<Torus> *mem_ptr,
    void *const *bsks, void *const *compute_bsks, Torus *const *ksks,
    Torus *const *rerand_ksks) {

  auto oprf_mem = mem_ptr->oprf_memory;
  CudaRadixCiphertextFFI *computation_buffer = oprf_mem->tmp_oprf_output;
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), computation_buffer, 0,
      num_blocks_intermediate);

  host_integer_grouped_oprf<Torus>(
      streams, computation_buffer, seeded_lwe_input,
      oprf_mem->num_random_input_blocks, oprf_mem->grouped_oprf_memory, bsks);

  // Re-randomization requires NOMINAL input noise, which the grouped OPRF
  // provides, and only adds an encryption of zero so the value is preserved.
  // host_rerand_inplace does not refresh computation_buffer's noise metadata,
  // but that is safe because the following scalar multiply bootstraps the
  // blocks.
  host_rerand_inplace<Torus, params>(
      streams, (Torus *)computation_buffer->ptr,
      lwe_flattened_encryptions_of_zero_compact_array_in, rerand_ksks,
      mem_ptr->rerand_memory);

  host_integer_scalar_mul_radix<Torus>(
      streams, computation_buffer, decomposed_scalar, has_at_least_one_set,
      oprf_mem->scalar_mul_buffer, compute_bsks, ksks,
      oprf_mem->params.message_modulus, num_scalars);

  host_logical_scalar_shift_inplace<Torus>(
      streams, computation_buffer, shift, oprf_mem->logical_scalar_shift_buffer,
      compute_bsks, ksks, num_blocks_intermediate);

  uint32_t num_blocks_output = radix_lwe_out->num_radix_blocks;
  uint32_t blocks_to_copy =
      std::min(num_blocks_output, num_blocks_intermediate);

  if (blocks_to_copy > 0) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), radix_lwe_out, 0,
        blocks_to_copy, computation_buffer, 0, blocks_to_copy);
  }

  if (num_blocks_output > blocks_to_copy) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), radix_lwe_out, blocks_to_copy,
        num_blocks_output);
  }
}

#endif
