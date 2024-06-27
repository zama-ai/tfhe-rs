#ifndef CNCRT_KS_H_
#define CNCRT_KS_H_

#include <cstdint>

extern "C" {

void cuda_keyswitch_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lwe_array_in, void *lwe_input_indexes,
    void *ksk, uint32_t lwe_dimension_in, uint32_t lwe_dimension_out,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples);

void cuda_keyswitch_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lwe_array_in, void *lwe_input_indexes,
    void *ksk, uint32_t lwe_dimension_in, uint32_t lwe_dimension_out,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples);
}

#endif // CNCRT_KS_H_
