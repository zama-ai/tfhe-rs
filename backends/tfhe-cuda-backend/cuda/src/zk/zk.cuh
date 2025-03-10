#ifndef CUDA_ZK_CUH
#define CUDA_ZK_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "helper_multi_gpu.h"
#include "integer/integer_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/functions.cuh"
#include "utils/helper.cuh"
#include "utils/helper_multi_gpu.cuh"
#include "utils/kernel_dimensions.cuh"
#include "zk/zk_utilities.h"
#include <functional>
#include "expand.cuh"
#include "keyswitch/ks_enums.h"

template <typename Torus>
__host__ void host_expand_without_verification(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, const Torus *lwe_compact_array_in,
    const bool *is_boolean_array, zk_expand<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {
printf("starting\n");
  // Expand
  auto expanded_lwes = mem_ptr->tmp_expanded_lwes;
  auto num_lwes = mem_ptr->num_lwes;
  auto lwe_dimension = mem_ptr->params.big_lwe_dimension;
  if(sizeof(Torus) == 8)
      cuda_lwe_expand_64(streams[0], gpu_indexes[0], expanded_lwes, lwe_compact_array_in,
                       lwe_dimension, num_lwes, lwe_dimension);
  else
    PANIC("Cuda error: expand is only supported on 64 bits")

  // Keyswitch from small to big if needed
   auto ks_type = mem_ptr->params.ks_type;
   if(ks_type == SMALL_TO_BIG){
	// apply keyswitch to BIG
     }

  	// Apply LUT
    auto lut = mem_ptr->message_and_carry_extract_many_luts;
    CudaRadixCiphertextFFI output, input;
    output.ptr = lwe_array_out;
    output.num_radix_blocks = 2 * num_lwes;
    output.max_num_radix_blocks = 2 * num_lwes;
    output.lwe_dimension = lwe_dimension;
    input.ptr = expanded_lwes;
    input.num_radix_blocks = num_lwes;
    input.max_num_radix_blocks = num_lwes;
    input.lwe_dimension = lwe_dimension;
  integer_radix_apply_many_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, &output, &input, bsks,
      ksks, lut, 2, 1);

    print_debug<Torus>("lwe_compact_array_in", lwe_compact_array_in, 32);
    print_debug<Torus>("expanded_lwes", expanded_lwes, 32);
    print_debug<Torus>("output", lwe_array_out, 32);
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
