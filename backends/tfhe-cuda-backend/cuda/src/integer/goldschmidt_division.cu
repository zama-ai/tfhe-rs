#include "integer/goldschmidt_division.cuh"
#include "integer/goldschmidt_division.h"

uint64_t scratch_cuda_goldschmidt_division_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t num_radix_blocks, uint32_t lut_precision,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          PBS_MS_REDUCTION_T::NO_REDUCTION);

  return scratch_cuda_goldschmidt_division<uint64_t>(
      CudaStreams(streams),
      (int_goldschmidt_division_buffer<uint64_t> **)mem_ptr, num_radix_blocks,
      params, lut_precision, allocate_gpu_memory);
}

void cuda_goldschmidt_division_64(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *quotient,
                                  CudaRadixCiphertextFFI *remainder,
                                  const CudaRadixCiphertextFFI *numerator,
                                  const CudaRadixCiphertextFFI *denominator,
                                  uint32_t iterations, uint32_t lut_precision,
                                  int8_t *mem_ptr, void *const *bsks,
                                  void *const *ksks) {

  auto buffer = (int_goldschmidt_division_buffer<uint64_t> *)mem_ptr;
  uint32_t polynomial_size = buffer->params.polynomial_size;

  switch (polynomial_size) {
  case 256:
    host_goldschmidt_division<uint64_t, AmortizedDegree<256>>(
        CudaStreams(streams), quotient, remainder, numerator, denominator,
        buffer, iterations, lut_precision, bsks, (uint64_t *const *)ksks);
    break;
  case 512:
    host_goldschmidt_division<uint64_t, AmortizedDegree<512>>(
        CudaStreams(streams), quotient, remainder, numerator, denominator,
        buffer, iterations, lut_precision, bsks, (uint64_t *const *)ksks);
    break;
  case 1024:
    host_goldschmidt_division<uint64_t, AmortizedDegree<1024>>(
        CudaStreams(streams), quotient, remainder, numerator, denominator,
        buffer, iterations, lut_precision, bsks, (uint64_t *const *)ksks);
    break;
  case 2048:
    host_goldschmidt_division<uint64_t, AmortizedDegree<2048>>(
        CudaStreams(streams), quotient, remainder, numerator, denominator,
        buffer, iterations, lut_precision, bsks, (uint64_t *const *)ksks);
    break;
  case 4096:
    host_goldschmidt_division<uint64_t, AmortizedDegree<4096>>(
        CudaStreams(streams), quotient, remainder, numerator, denominator,
        buffer, iterations, lut_precision, bsks, (uint64_t *const *)ksks);
    break;
  case 8192:
    host_goldschmidt_division<uint64_t, AmortizedDegree<8192>>(
        CudaStreams(streams), quotient, remainder, numerator, denominator,
        buffer, iterations, lut_precision, bsks, (uint64_t *const *)ksks);
    break;
  case 16384:
    host_goldschmidt_division<uint64_t, AmortizedDegree<16384>>(
        CudaStreams(streams), quotient, remainder, numerator, denominator,
        buffer, iterations, lut_precision, bsks, (uint64_t *const *)ksks);
    break;
  default:
    PANIC("Cuda error (goldschmidt division): unsupported polynomial size.");
  }
}

void cleanup_cuda_goldschmidt_division(CudaStreamsFFI streams,
                                       int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup_cuda_goldschmidt_division")
  int_goldschmidt_division_buffer<uint64_t> *mem_ptr =
      (int_goldschmidt_division_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}

void cuda_mul_add_fixed_point_with_rescaling_64(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *result,
    const CudaRadixCiphertextFFI *lhs, const CudaRadixCiphertextFFI *rhs,
    const CudaRadixCiphertextFFI *added, int32_t rescaling, uint32_t precision,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks) {

  auto buffer = (int_goldschmidt_division_buffer<uint64_t> *)mem_ptr;
  uint32_t polynomial_size = buffer->params.polynomial_size;

  switch (polynomial_size) {
  case 256:
    host_mul_add_fixed_point_with_rescaling<uint64_t, AmortizedDegree<256>>(
        CudaStreams(streams), result, lhs, rhs, added, rescaling, precision,
        buffer, bsks, (uint64_t *const *)ksks);
    break;
  case 512:
    host_mul_add_fixed_point_with_rescaling<uint64_t, AmortizedDegree<512>>(
        CudaStreams(streams), result, lhs, rhs, added, rescaling, precision,
        buffer, bsks, (uint64_t *const *)ksks);
    break;
  case 1024:
    host_mul_add_fixed_point_with_rescaling<uint64_t, AmortizedDegree<1024>>(
        CudaStreams(streams), result, lhs, rhs, added, rescaling, precision,
        buffer, bsks, (uint64_t *const *)ksks);
    break;
  case 2048:
    host_mul_add_fixed_point_with_rescaling<uint64_t, AmortizedDegree<2048>>(
        CudaStreams(streams), result, lhs, rhs, added, rescaling, precision,
        buffer, bsks, (uint64_t *const *)ksks);
    break;
  case 4096:
    host_mul_add_fixed_point_with_rescaling<uint64_t, AmortizedDegree<4096>>(
        CudaStreams(streams), result, lhs, rhs, added, rescaling, precision,
        buffer, bsks, (uint64_t *const *)ksks);
    break;
  case 8192:
    host_mul_add_fixed_point_with_rescaling<uint64_t, AmortizedDegree<8192>>(
        CudaStreams(streams), result, lhs, rhs, added, rescaling, precision,
        buffer, bsks, (uint64_t *const *)ksks);
    break;
  case 16384:
    host_mul_add_fixed_point_with_rescaling<uint64_t, AmortizedDegree<16384>>(
        CudaStreams(streams), result, lhs, rhs, added, rescaling, precision,
        buffer, bsks, (uint64_t *const *)ksks);
    break;
  default:
    PANIC("Cuda error (mul_add_fixed_point_with_rescaling): unsupported "
          "polynomial size.");
  }
}
