#ifndef ZK_H
#define ZK_H

#include "../keyswitch/ks_enums.h"
#include "../pbs/pbs_enums.h"
#include <stdint.h>

extern "C" {

void cuda_lwe_expand_64(void *const stream, uint32_t gpu_index,
                        void *lwe_array_out, const void *lwe_compact_array_in,
                        uint32_t lwe_dimension, uint32_t num_lwe,
                        const uint32_t *compact_list_length_per_thread,
                        const void *lwe_compact_input_indexes);

void scratch_cuda_expand_without_verification_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, const uint32_t *num_samples_per_compact_list,
    const bool *is_boolean_array, uint32_t num_compact_lists,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array);

void cuda_expand_without_verification_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, const void *lwe_compact_array_in, int8_t *mem_ptr,
    KS_TYPE ks_type, void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key);

void cleanup_expand_without_verification_64(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count,
                                            int8_t **mem_ptr_void);
}
#endif // ZK_H
