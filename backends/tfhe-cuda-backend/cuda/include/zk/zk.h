#ifndef ZK_H
#define ZK_H

#include <stdint.h>

extern "C" {
void cuda_lwe_expand_64(void *stream, uint32_t gpu_index, void *lwe_array_out,
                        const void *lwe_compact_array_in,
                        uint32_t lwe_dimension, uint32_t num_lwe,
                       uint32_t max_ciphertext_per_bin);
}
#endif //ZK_H
