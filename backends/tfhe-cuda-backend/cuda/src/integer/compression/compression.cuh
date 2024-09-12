#ifndef CUDA_INTEGER_COMPRESSION_CUH
#define CUDA_INTEGER_COMPRESSION_CUH

#include "ciphertext.h"
#include "compression.h"
#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer/integer.cuh"
#include "linearalgebra/multiplication.cuh"
#include "polynomial/functions.cuh"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__global__ void pack(Torus *array_out, Torus *array_in, uint32_t log_modulus,
                     uint32_t in_len, uint32_t len) {
  auto nbits = sizeof(Torus) * 8;

  auto i = threadIdx.x + blockIdx.x * blockDim.x;
  if (i < len) {
    auto k = nbits * i / log_modulus;
    auto j = k;

    auto start_shift = i * nbits - j * log_modulus;

    auto value = array_in[j] >> start_shift;
    j++;

    while (j * log_modulus < ((i + 1) * nbits) && j < in_len) {
      auto shift = j * log_modulus - i * nbits;
      value |= array_in[j] << shift;
      j++;
    }

    array_out[i] = value;
  }
}

template <typename Torus>
__host__ void host_pack(cudaStream_t stream, uint32_t gpu_index,
                        Torus *array_out, Torus *array_in, uint32_t body_count,
                        int_compression<Torus> *mem_ptr) {
  cudaSetDevice(gpu_index);
  auto params = mem_ptr->compression_params;

  auto log_modulus = mem_ptr->storage_log_modulus;
  auto in_len = params.glwe_dimension * params.polynomial_size + body_count;
  auto number_bits_to_pack = in_len * log_modulus;
  auto nbits = sizeof(Torus) * 8;
  // number_bits_to_pack.div_ceil(Scalar::BITS)
  auto len = (number_bits_to_pack + nbits - 1) / nbits;

  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(len, 128, num_blocks, num_threads);

  dim3 grid(num_blocks);
  dim3 threads(num_threads);
  pack<Torus><<<grid, threads, 0, stream>>>(array_out, array_in, log_modulus,
                                            in_len, len);
}

template <typename Torus>
__host__ void host_integer_compress(cudaStream_t *streams,
                                    uint32_t *gpu_indexes, uint32_t gpu_count,
                                    Torus *glwe_array_out, Torus *lwe_array_in,
                                    Torus **fp_ksk, uint32_t num_lwes,
                                    int_compression<Torus> *mem_ptr) {

  auto compression_params = mem_ptr->compression_params;
  auto input_lwe_dimension = compression_params.small_lwe_dimension;

  // Shift
  auto lwe_shifted = mem_ptr->tmp_lwe;
  host_cleartext_multiplication<Torus>(
      streams[0], gpu_indexes[0], lwe_shifted, lwe_array_in,
      (uint64_t)compression_params.message_modulus, input_lwe_dimension,
      num_lwes);

  uint32_t lwe_in_size = input_lwe_dimension + 1;
  uint32_t glwe_out_size = (compression_params.glwe_dimension + 1) *
                           compression_params.polynomial_size;
  uint32_t num_glwes = num_lwes / mem_ptr->lwe_per_glwe + 1;
  auto body_count = min(num_lwes, mem_ptr->lwe_per_glwe);

  // Keyswitch LWEs to GLWE
  auto tmp_glwe_array_out = mem_ptr->tmp_glwe_array_out;
  auto fp_ks_buffer = mem_ptr->fp_ks_buffer;
  for (int i = 0; i < num_glwes; i++) {
    auto lwe_subset = lwe_shifted + i * lwe_in_size;
    auto glwe_out = tmp_glwe_array_out + i * glwe_out_size;

    host_packing_keyswitch_lwe_list_to_glwe<Torus>(
        streams[0], gpu_indexes[0], glwe_out, lwe_subset, fp_ksk[0],
        fp_ks_buffer, input_lwe_dimension, compression_params.glwe_dimension,
        compression_params.polynomial_size, compression_params.ks_base_log,
        compression_params.ks_level, body_count);
  }

  // Modulus switch
  host_modulus_switch_inplace<Torus>(
      streams[0], gpu_indexes[0], tmp_glwe_array_out,
      num_glwes * (compression_params.glwe_dimension *
                       compression_params.polynomial_size +
                   body_count),
      mem_ptr->storage_log_modulus);
  check_cuda_error(cudaGetLastError());

  host_pack<Torus>(streams[0], gpu_indexes[0], glwe_array_out,
                   tmp_glwe_array_out, body_count, mem_ptr);
}

template <typename Torus>
__global__ void extract(Torus *glwe_array_out, Torus *array_in, uint32_t index,
                        uint32_t log_modulus, uint32_t initial_out_len) {
  auto nbits = sizeof(Torus) * 8;

  auto i = threadIdx.x + blockIdx.x * blockDim.x;

  if (i < initial_out_len) {
    // Unpack
    Torus mask = ((Torus)1 << log_modulus) - 1;
    auto start = i * log_modulus;
    auto end = (i + 1) * log_modulus;

    auto start_block = start / nbits;
    auto start_remainder = start % nbits;

    auto end_block_inclusive = (end - 1) / nbits;

    Torus unpacked_i;
    if (start_block == end_block_inclusive) {
      auto single_part = array_in[start_block] >> start_remainder;
      unpacked_i = single_part & mask;
    } else {
      auto first_part = array_in[start_block] >> start_remainder;
      auto second_part = array_in[start_block + 1] << (nbits - start_remainder);

      unpacked_i = (first_part | second_part) & mask;
    }

    // Extract
    glwe_array_out[i] = unpacked_i << (nbits - log_modulus);
  }
}

template <typename Torus>
__host__ void host_extract(cudaStream_t stream, uint32_t gpu_index,
                           Torus *glwe_array_out, Torus *array_in,
                           uint32_t glwe_index,
                           int_decompression<Torus> *mem_ptr) {
  cudaSetDevice(gpu_index);

  auto params = mem_ptr->compression_params;

  auto log_modulus = mem_ptr->storage_log_modulus;

  uint32_t body_count = mem_ptr->body_count;

  auto initial_out_len =
      params.glwe_dimension * params.polynomial_size + body_count;

  // We assure the tail of the glwe is zeroed
  auto zeroed_slice = glwe_array_out + initial_out_len;
  cuda_memset_async(zeroed_slice, 0,
                    (params.polynomial_size - body_count) * sizeof(Torus),
                    stream, gpu_index);
  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(initial_out_len, 128, num_blocks, num_threads);
  dim3 grid(num_blocks);
  dim3 threads(num_threads);
  extract<Torus><<<grid, threads, 0, stream>>>(
      glwe_array_out, array_in, glwe_index, log_modulus, initial_out_len);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ void
host_integer_decompress(cudaStream_t *streams, uint32_t *gpu_indexes,
                        uint32_t gpu_count, Torus *lwe_array_out,
                        Torus *packed_glwe_in, uint32_t *indexes_array,
                        uint32_t indexes_array_size, void **bsks,
                        int_decompression<Torus> *mem_ptr) {

  auto polynomial_size = mem_ptr->encryption_params.polynomial_size;
  if (indexes_array_size > polynomial_size)
    PANIC("Cuda error: too many LWEs to decompress. The number of LWEs should "
          "be smaller than "
          "polynomial_size.")

  auto extracted_glwe = mem_ptr->tmp_extracted_glwe;
  auto compression_params = mem_ptr->compression_params;
  host_extract<Torus>(streams[0], gpu_indexes[0], extracted_glwe,
                      packed_glwe_in, 0, mem_ptr);

  auto num_lwes = mem_ptr->num_lwes;

  // Sample extract
  auto extracted_lwe = mem_ptr->tmp_extracted_lwe;
  cuda_glwe_sample_extract_64(streams[0], gpu_indexes[0], extracted_lwe,
                              extracted_glwe, indexes_array, indexes_array_size,
                              compression_params.glwe_dimension,
                              compression_params.polynomial_size);

  // In the case of extracting a single LWE this parameters are dummy
  uint32_t lut_count = 1;
  uint32_t lut_stride = 0;
  /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
  /// dimension to a big LWE dimension
  auto encryption_params = mem_ptr->encryption_params;
  auto lut = mem_ptr->carry_extract_lut;
  auto active_gpu_count = get_active_gpu_count(num_lwes, gpu_count);
  if (active_gpu_count == 1) {

    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_out,
        lut->lwe_indexes_out, lut->lut_vec, lut->lut_indexes_vec, extracted_lwe,
        lut->lwe_indexes_in, bsks, lut->buffer,
        encryption_params.glwe_dimension,
        compression_params.small_lwe_dimension,
        encryption_params.polynomial_size, encryption_params.pbs_base_log,
        encryption_params.pbs_level, encryption_params.grouping_factor,
        num_lwes, encryption_params.pbs_type, lut_count, lut_stride);
  } else {
    /// For multi GPU execution we create vectors of pointers for inputs and
    /// outputs
    std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
    std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
    std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

    /// Make sure all data that should be on GPU 0 is indeed there
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    /// With multiple GPUs we push to the vectors on each GPU then when we
    /// gather data to GPU 0 we can copy back to the original indexing
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec, extracted_lwe,
        lut->h_lwe_indexes_in, lut->using_trivial_lwe_indexes, num_lwes,
        compression_params.small_lwe_dimension + 1);

    /// Apply PBS
    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_array_in_vec, lwe_trivial_indexes_vec, bsks, lut->buffer,
        encryption_params.glwe_dimension,
        compression_params.small_lwe_dimension,
        encryption_params.polynomial_size, encryption_params.pbs_base_log,
        encryption_params.pbs_level, encryption_params.grouping_factor,
        num_lwes, encryption_params.pbs_type, lut_count, lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_lwe_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                      lwe_array_out, lwe_after_pbs_vec,
                                      lut->h_lwe_indexes_out,
                                      lut->using_trivial_lwe_indexes, num_lwes,
                                      encryption_params.big_lwe_dimension + 1);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
}

template <typename Torus>
__host__ void scratch_cuda_compress_integer_radix_ciphertext(
    cudaStream_t *streams, uint32_t *gpu_indexes, uint32_t gpu_count,
    int_compression<Torus> **mem_ptr, uint32_t num_lwes,
    int_radix_params compression_params, uint32_t lwe_per_glwe,
    uint32_t storage_log_modulus, bool allocate_gpu_memory) {

  *mem_ptr = new int_compression<Torus>(
      streams, gpu_indexes, gpu_count, compression_params, num_lwes,
      lwe_per_glwe, storage_log_modulus, allocate_gpu_memory);
}

template <typename Torus>
__host__ void scratch_cuda_integer_decompress_radix_ciphertext(
    cudaStream_t *streams, uint32_t *gpu_indexes, uint32_t gpu_count,
    int_decompression<Torus> **mem_ptr, uint32_t num_lwes, uint32_t body_count,
    int_radix_params encryption_params, int_radix_params compression_params,
    uint32_t storage_log_modulus, bool allocate_gpu_memory) {

  *mem_ptr = new int_decompression<Torus>(
      streams, gpu_indexes, gpu_count, encryption_params, compression_params,
      num_lwes, body_count, storage_log_modulus, allocate_gpu_memory);
}
#endif
