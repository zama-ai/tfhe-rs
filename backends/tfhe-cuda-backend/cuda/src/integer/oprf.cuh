#ifndef CUDA_INTEGER_OPRF_CUH
#define CUDA_INTEGER_OPRF_CUH

#include "integer/integer.cuh"
#include "integer/integer_utilities.h"

template <typename Torus>
uint64_t scratch_cuda_integer_grouped_oprf(
    CudaStreams streams, int_grouped_oprf_memory<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks_to_process,
    uint32_t num_blocks, uint32_t message_bits_per_block,
    uint64_t total_random_bits, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;

  *mem_ptr = new int_grouped_oprf_memory<Torus>(
      streams, params, num_blocks_to_process, num_blocks,
      message_bits_per_block, total_random_bits, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
void host_integer_grouped_oprf(
    CudaStreams streams, CudaRadixCiphertextFFI *radix_lwe_out,
    const Torus *seeded_lwe_input, uint32_t num_blocks_to_process,
    int_grouped_oprf_memory<Torus> *mem_ptr, void *const *bsks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  auto active_streams = streams.active_gpu_subset(num_blocks_to_process);
  auto lut = mem_ptr->luts;

  if (active_streams.count() == 1) {
    execute_pbs_async<Torus, Torus>(
        streams, (Torus *)(radix_lwe_out->ptr), lut->lwe_indexes_out,
        lut->lut_vec, lut->lut_indexes_vec,
        const_cast<Torus *>(seeded_lwe_input), lut->lwe_indexes_in, bsks,
        ms_noise_reduction_key, lut->buffer, mem_ptr->params.glwe_dimension,
        mem_ptr->params.small_lwe_dimension, mem_ptr->params.polynomial_size,
        mem_ptr->params.pbs_base_log, mem_ptr->params.pbs_level,
        mem_ptr->params.grouping_factor, num_blocks_to_process,
        mem_ptr->params.pbs_type, 1, 0);
  } else {
    std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
    std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
    std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

    cuda_event_record(lut->event_scatter_in, streams.stream(0),
                      streams.gpu_index(0));
    for (int j = 1; j < active_streams.count(); j++) {
      cuda_stream_wait_event(streams.stream(j), lut->event_scatter_in,
                             streams.gpu_index(j));
    }

    if (!lut->using_trivial_lwe_indexes) {
      PANIC("lut->using_trivial_lwe_indexes should be true");
    }

    multi_gpu_scatter_lwe_async<Torus>(
        active_streams, lwe_array_in_vec, seeded_lwe_input, lut->lwe_indexes_in,
        lut->using_trivial_lwe_indexes, lut->lwe_aligned_vec,
        active_streams.count(), num_blocks_to_process,
        mem_ptr->params.small_lwe_dimension + 1);

    execute_pbs_async<Torus, Torus>(
        active_streams, lwe_after_pbs_vec, lwe_trivial_indexes_vec,
        lut->lut_vec, lut->lut_indexes_vec, lwe_array_in_vec,
        lwe_trivial_indexes_vec, bsks, ms_noise_reduction_key, lut->buffer,
        mem_ptr->params.glwe_dimension, mem_ptr->params.small_lwe_dimension,
        mem_ptr->params.polynomial_size, mem_ptr->params.pbs_base_log,
        mem_ptr->params.pbs_level, mem_ptr->params.grouping_factor,
        num_blocks_to_process, mem_ptr->params.pbs_type, 1, 0);

    multi_gpu_gather_lwe_async<Torus>(
        active_streams, (Torus *)radix_lwe_out->ptr, lwe_after_pbs_vec,
        lut->lwe_indexes_out, lut->using_trivial_lwe_indexes,
        lut->lwe_aligned_vec, num_blocks_to_process,
        mem_ptr->params.big_lwe_dimension + 1);

    // other gpus record their events
    for (int j = 1; j < active_streams.count(); j++) {
      cuda_event_record(lut->event_scatter_out[j], streams.stream(j),
                        streams.gpu_index(j));
    }
    // GPU 0 waits for all
    for (int j = 1; j < active_streams.count(); j++) {
      cuda_stream_wait_event(streams.stream(0), lut->event_scatter_out[j],
                             streams.gpu_index(0));
    }
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

#endif
