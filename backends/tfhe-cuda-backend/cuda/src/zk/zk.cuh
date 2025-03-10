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
    uint32_t gpu_count, Torus *lwe_array_out, const Torus *lwe_compact_array_in,
    const bool *is_boolean_array, zk_expand<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {
  printf("starting (%u blocks)\n", mem_ptr->num_lwes);
  // Expand
  auto expanded_lwes = mem_ptr->tmp_expanded_lwes;
  auto num_lwes = mem_ptr->num_lwes;
  auto lwe_dimension = mem_ptr->params.big_lwe_dimension;
  print_body<const Torus>("lwe_compact_array_in", lwe_compact_array_in,
                          num_lwes, lwe_dimension);
  if (sizeof(Torus) == 8) {
    // TODO: This must be the expansion PER compact ciphertext list.
    // We need to know how many lists we have and how many lwes we want to
    // expand per list.
    cuda_lwe_expand_64(streams[0], gpu_indexes[0], expanded_lwes,
                       lwe_compact_array_in, lwe_dimension, num_lwes / 2,
                       lwe_dimension);

    cuda_lwe_expand_64(streams[0], gpu_indexes[0],
                       expanded_lwes + (num_lwes / 2) * (lwe_dimension + 1),
                       lwe_compact_array_in +
                           (num_lwes / 2) * (mem_ptr->params.polynomial_size),
                       lwe_dimension, num_lwes / 2, lwe_dimension);
  } else
    PANIC("Cuda error: expand is only supported on 64 bits")

  // Keyswitch from small to big if needed
  auto ks_type = mem_ptr->params.ks_type;
  if (ks_type == SMALL_TO_BIG) {
    // apply keyswitch to BIG
  }

  // Apply LUT
  auto lut = mem_ptr->message_and_carry_extract_luts;
  cuda_memset_async(lwe_array_out, 0,
                    (lwe_dimension + 1) * num_lwes * 2 * sizeof(Torus),
                    streams[0], gpu_indexes[0]);
  auto output = new CudaRadixCiphertextFFI;
  into_radix_ciphertext(output, lwe_array_out, 2 * num_lwes, lwe_dimension);
  auto input = new CudaRadixCiphertextFFI;
  into_radix_ciphertext(input, expanded_lwes, 2 * num_lwes, lwe_dimension);

  print_body<Torus>("ks+pbs input", (Torus *)input->ptr, num_lwes,
                    lwe_dimension);

  auto message_and_carry_extract_luts = mem_ptr->message_and_carry_extract_luts;
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, output, input, bsks, ksks,
      message_and_carry_extract_luts, 2 * num_lwes);

  // print_body<Torus>("lwe_compact_array_in", lwe_compact_array_in, 8);
  auto output_message = new CudaRadixCiphertextFFI;
  auto output_carry = new CudaRadixCiphertextFFI;
  as_radix_ciphertext_slice<Torus>(output_message, output, 0, num_lwes);
  as_radix_ciphertext_slice<Torus>(output_carry, output, num_lwes,
                                   2 * num_lwes);

  print_body<Torus>("expanded_lwes ", expanded_lwes, num_lwes, lwe_dimension);
  print_body<Torus>("output message", static_cast<Torus *>(output_message->ptr),
                    num_lwes, lwe_dimension);
  print_body<Torus>("output carry", static_cast<Torus *>(output_carry->ptr),
                    num_lwes, lwe_dimension);
}

template <typename Torus>
__host__ void scratch_cuda_expand_without_verification(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, zk_expand<Torus> **mem_ptr, uint32_t num_radix_blocks,
    int_radix_params params, bool allocate_gpu_memory) {

  *mem_ptr = new zk_expand<Torus>(streams, gpu_indexes, gpu_count, params,
                                  num_radix_blocks, allocate_gpu_memory);
}

#endif // CUDA_ZK_CUH
