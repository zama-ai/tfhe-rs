#include "integer/integer.cuh"
#include <linear_algebra.h>

void cuda_full_propagation_64_inplace(
    cuda_stream_t *stream, void *input_blocks, int8_t *mem_ptr, void *ksk,
    void *bsk, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t ks_base_log, uint32_t ks_level,
    uint32_t pbs_base_log, uint32_t pbs_level, uint32_t grouping_factor,
    uint32_t num_blocks) {

  switch (polynomial_size) {
  case 256:
    host_full_propagate_inplace<uint64_t, int64_t, AmortizedDegree<256>>(
        stream, static_cast<uint64_t *>(input_blocks),
        (int_fullprop_buffer<uint64_t> *)mem_ptr, static_cast<uint64_t *>(ksk),
        bsk, lwe_dimension, glwe_dimension, polynomial_size, ks_base_log,
        ks_level, pbs_base_log, pbs_level, grouping_factor, num_blocks);
    break;
  case 512:
    host_full_propagate_inplace<uint64_t, int64_t, AmortizedDegree<512>>(
        stream, static_cast<uint64_t *>(input_blocks),
        (int_fullprop_buffer<uint64_t> *)mem_ptr, static_cast<uint64_t *>(ksk),
        bsk, lwe_dimension, glwe_dimension, polynomial_size, ks_base_log,
        ks_level, pbs_base_log, pbs_level, grouping_factor, num_blocks);
    break;
  case 1024:
    host_full_propagate_inplace<uint64_t, int64_t, AmortizedDegree<1024>>(
        stream, static_cast<uint64_t *>(input_blocks),
        (int_fullprop_buffer<uint64_t> *)mem_ptr, static_cast<uint64_t *>(ksk),
        bsk, lwe_dimension, glwe_dimension, polynomial_size, ks_base_log,
        ks_level, pbs_base_log, pbs_level, grouping_factor, num_blocks);
    break;
  case 2048:
    host_full_propagate_inplace<uint64_t, int64_t, AmortizedDegree<2048>>(
        stream, static_cast<uint64_t *>(input_blocks),
        (int_fullprop_buffer<uint64_t> *)mem_ptr, static_cast<uint64_t *>(ksk),
        bsk, lwe_dimension, glwe_dimension, polynomial_size, ks_base_log,
        ks_level, pbs_base_log, pbs_level, grouping_factor, num_blocks);
    break;
  case 4096:
    host_full_propagate_inplace<uint64_t, int64_t, AmortizedDegree<4096>>(
        stream, static_cast<uint64_t *>(input_blocks),
        (int_fullprop_buffer<uint64_t> *)mem_ptr, static_cast<uint64_t *>(ksk),
        bsk, lwe_dimension, glwe_dimension, polynomial_size, ks_base_log,
        ks_level, pbs_base_log, pbs_level, grouping_factor, num_blocks);
    break;
  case 8192:
    host_full_propagate_inplace<uint64_t, int64_t, AmortizedDegree<8192>>(
        stream, static_cast<uint64_t *>(input_blocks),
        (int_fullprop_buffer<uint64_t> *)mem_ptr, static_cast<uint64_t *>(ksk),
        bsk, lwe_dimension, glwe_dimension, polynomial_size, ks_base_log,
        ks_level, pbs_base_log, pbs_level, grouping_factor, num_blocks);
    break;
  case 16384:
    host_full_propagate_inplace<uint64_t, int64_t, AmortizedDegree<16384>>(
        stream, static_cast<uint64_t *>(input_blocks),
        (int_fullprop_buffer<uint64_t> *)mem_ptr, static_cast<uint64_t *>(ksk),
        bsk, lwe_dimension, glwe_dimension, polynomial_size, ks_base_log,
        ks_level, pbs_base_log, pbs_level, grouping_factor, num_blocks);
    break;
  default:
    PANIC("Cuda error (full propagation inplace): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

void scratch_cuda_full_propagation_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  scratch_cuda_full_propagation<uint64_t>(
      stream, (int_fullprop_buffer<uint64_t> **)mem_ptr, lwe_dimension,
      glwe_dimension, polynomial_size, level_count, grouping_factor,
      input_lwe_ciphertext_count, message_modulus, carry_modulus, pbs_type,
      allocate_gpu_memory);
}

void cleanup_cuda_full_propagation(cuda_stream_t *stream,
                                   int8_t **mem_ptr_void) {

  int_fullprop_buffer<uint64_t> *mem_ptr =
      (int_fullprop_buffer<uint64_t> *)(*mem_ptr_void);

  cuda_drop_async(mem_ptr->lut_buffer, stream);
  cuda_drop_async(mem_ptr->lut_indexes, stream);

  cuda_drop_async(mem_ptr->lwe_indexes, stream);

  cuda_drop_async(mem_ptr->tmp_small_lwe_vector, stream);
  cuda_drop_async(mem_ptr->tmp_big_lwe_vector, stream);

  switch (mem_ptr->pbs_type) {
  case CLASSICAL: {
    auto x = (pbs_buffer<uint64_t, CLASSICAL> *)(mem_ptr->pbs_buffer);
    x->release(stream);
  } break;
  case MULTI_BIT: {
    auto x = (pbs_buffer<uint64_t, MULTI_BIT> *)(mem_ptr->pbs_buffer);
    x->release(stream);
  } break;
  default:
    PANIC("Cuda error (PBS): unsupported implementation variant.")
  }
}

void scratch_cuda_propagate_single_carry_kb_64_inplace(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_propagate_single_carry_kb_inplace(
      stream, (int_sc_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      allocate_gpu_memory);
}

void cuda_propagate_single_carry_kb_64_inplace(cuda_stream_t *stream,
                                               void *lwe_array, int8_t *mem_ptr,
                                               void *bsk, void *ksk,
                                               uint32_t num_blocks) {
  host_propagate_single_carry<uint64_t>(
      stream, static_cast<uint64_t *>(lwe_array),
      (int_sc_prop_memory<uint64_t> *)mem_ptr, bsk,
      static_cast<uint64_t *>(ksk), num_blocks);
}

void cleanup_cuda_propagate_single_carry(cuda_stream_t *stream,
                                         int8_t **mem_ptr_void) {
  int_sc_prop_memory<uint64_t> *mem_ptr =
      (int_sc_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(stream);
}
