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

/// @brief Prepares the key material of a PRINCEv2 key pair, once per pair
/// and direction, for any number of later cuda_integer_prince_64_async calls.
///
/// Spreads each 32-block key half into its 64 bits, then into the 3-bit
/// parities that let the linear layers absorb the key xor as a levelled sum.
/// All outputs carry no lane dimension, 64 blocks each, whatever the batch
/// size of the later calls. Asynchronous.
///
/// @param key_bits_first Output, the 64 bits of k_first, one per block.
/// @param key_bits_second Output, the 64 bits of k_second, one per block.
/// @param kap_bw_first Output, k_first pulled back through the backward
/// linear layer, M'(SR^-1(k_first)), one bit per block.
/// @param kap_bw_second Output, same for k_second.
/// @param kap_mid_first Output, k_first through the middle round's M' layer,
/// one bit per block.
/// @param k_first First key half in circuit order, k0 to encrypt, k1 to
/// decrypt. 32 blocks of 2 bits, most significant first, fresh encryptions.
/// @param k_second Second key half in circuit order, k1 to encrypt, k0 to
/// decrypt. Same layout as k_first.
/// @param mem_ptr Scratch allocated by
/// scratch_cuda_integer_prince_key_prep_64_async.
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

/// @brief Evaluates PRINCEv2 [BEK+20] on a batch of 64-bit blocks under an
/// encrypted key. k0 xor, 5 forward rounds, the reflective middle round, 5
/// backward rounds, k1 xor. Encrypts or decrypts according to the scratch's
/// is_decrypt flag and the key order given at key preparation. Asynchronous.
///
/// Fresh inputs only. The input xor packs 4 * m + k into one block, which
/// spends the full 2_2 noise budget.
///
/// @param output num_prince_inputs blocks of 64 bits, each as 32 blocks of 2
/// bits, most significant first, instance after instance.
/// @param input Same layout as output, fresh encryptions.
/// @param k_first First key half in circuit order (see
/// cuda_integer_prince_key_prep_64_async), 32 blocks.
/// @param k_second Second key half in circuit order, 32 blocks.
/// @param key_bits_first Prepared by cuda_integer_prince_key_prep_64_async.
/// @param key_bits_second Prepared by cuda_integer_prince_key_prep_64_async.
/// @param kap_bw_first Prepared by cuda_integer_prince_key_prep_64_async.
/// @param kap_bw_second Prepared by cuda_integer_prince_key_prep_64_async.
/// @param kap_mid_first Prepared by cuda_integer_prince_key_prep_64_async.
/// @param mem_ptr Scratch allocated by scratch_cuda_integer_prince_64_async
/// for the same batch size and direction.
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
