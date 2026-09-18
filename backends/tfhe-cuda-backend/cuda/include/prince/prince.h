#ifndef PRINCE_H
#define PRINCE_H
#include "../integer/integer.h"

extern "C" {
uint64_t scratch_cuda_integer_prince_key_prep_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

// k_first, k_second are the key halves in circuit order: (k0, k1) to encrypt,
// (k1, k0) to decrypt
void cuda_integer_prince_key_prep_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *key_bits_first,
    CudaRadixCiphertextFFI *key_bits_second,
    CudaRadixCiphertextFFI *kap_bw_first, CudaRadixCiphertextFFI *kap_bw_second,
    CudaRadixCiphertextFFI *kap_mid_first,
    CudaRadixCiphertextFFI const *k_first,
    CudaRadixCiphertextFFI const *k_second, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_integer_prince_key_prep_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_prince_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_prince_inputs,
    bool is_decrypt);

void cuda_integer_prince_64_async(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *output,
                                  CudaRadixCiphertextFFI const *input,
                                  CudaRadixCiphertextFFI const *k_first,
                                  CudaRadixCiphertextFFI const *k_second,
                                  CudaRadixCiphertextFFI const *key_bits_first,
                                  CudaRadixCiphertextFFI const *key_bits_second,
                                  CudaRadixCiphertextFFI const *kap_bw_first,
                                  CudaRadixCiphertextFFI const *kap_bw_second,
                                  CudaRadixCiphertextFFI const *kap_mid_first,
                                  int8_t *mem_ptr, void *const *bsks,
                                  void *const *ksks);

void cleanup_cuda_integer_prince_64(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void);
}

#endif
