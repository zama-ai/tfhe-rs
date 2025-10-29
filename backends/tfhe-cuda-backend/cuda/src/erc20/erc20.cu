#include "erc20/erc20.cuh"

uint64_t scratch_cuda_erc20_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  PUSH_RANGE("scratch erc20")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  std::function<uint64_t(uint64_t)> predicate_lut_f =
      [](uint64_t x) -> uint64_t { return x == 1; };

  uint64_t ret = scratch_cuda_erc20<uint64_t>(
      CudaStreams(streams), (int_erc20_buffer<uint64_t> **)mem_ptr,
      lwe_ciphertext_count, params, allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

void cuda_erc20_assign_64(CudaStreamsFFI streams,
                          CudaRadixCiphertextFFI *from_amount,
                          CudaRadixCiphertextFFI *to_amount,
                          CudaRadixCiphertextFFI const *amount, int8_t *mem_ptr,
                          void *const *bsks, void *const *ksks) {
  PUSH_RANGE("erc20")
  auto mem = reinterpret_cast<int_erc20_buffer<uint64_t> *>(mem_ptr);
  switch (mem->params.polynomial_size) {
  case 256:
    host_erc20_assign<uint64_t, AmortizedDegree<256>>(
        CudaStreams(streams), from_amount, to_amount, amount, mem, bsks,
        (uint64_t **)(ksks));
    break;
  case 512:
    host_erc20_assign<uint64_t, AmortizedDegree<512>>(
        CudaStreams(streams), from_amount, to_amount, amount, mem, bsks,
        (uint64_t **)(ksks));
    break;
  case 1024:
    host_erc20_assign<uint64_t, AmortizedDegree<1024>>(
        CudaStreams(streams), from_amount, to_amount, amount, mem, bsks,
        (uint64_t **)(ksks));
    break;
  case 2048:
    host_erc20_assign<uint64_t, AmortizedDegree<2048>>(
        CudaStreams(streams), from_amount, to_amount, amount, mem, bsks,
        (uint64_t **)(ksks));
    break;
  case 4096:
    host_erc20_assign<uint64_t, AmortizedDegree<4096>>(
        CudaStreams(streams), from_amount, to_amount, amount, mem, bsks,
        (uint64_t **)(ksks));
    break;
  case 8192:
    host_erc20_assign<uint64_t, AmortizedDegree<8192>>(
        CudaStreams(streams), from_amount, to_amount, amount, mem, bsks,
        (uint64_t **)(ksks));
    break;
  case 16384:
    host_erc20_assign<uint64_t, AmortizedDegree<16384>>(
        CudaStreams(streams), from_amount, to_amount, amount, mem, bsks,
        (uint64_t **)(ksks));
    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Supported N's are powers of two in the interval [256..16384].")
  }
  POP_RANGE()
}

void cleanup_cuda_erc20(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup erc20")
  int_erc20_buffer<uint64_t> *mem_ptr =
      (int_erc20_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
