#ifndef CUDA_INTEGER_COMPRESSION_CUH
#define CUDA_INTEGER_COMPRESSION_CUH

#include "ciphertext.h"
#include "crypto/keyswitch.cuh"
#include "crypto/packing_keyswitch.cuh"
#include "device.h"
#include "integer/compression/compression.h"
#include "integer/compression/compression_utilities.h"
#include "integer/integer.cuh"
#include "linearalgebra/multiplication.cuh"
#include "polynomial/functions.cuh"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__global__ void pack(Torus *array_out, Torus *array_in, uint32_t log_modulus,
                     uint32_t num_coeffs, uint32_t in_len, uint32_t out_len) {
  auto nbits = sizeof(Torus) * 8;
  auto tid = threadIdx.x + blockIdx.x * blockDim.x;

  auto glwe_index = tid / out_len;
  auto i = tid % out_len;
  auto chunk_array_in = array_in + glwe_index * in_len;
  auto chunk_array_out = array_out + glwe_index * out_len;

  if (tid < num_coeffs) {

    auto k = nbits * i / log_modulus;
    auto j = k;

    auto start_shift = i * nbits - j * log_modulus;

    auto value = chunk_array_in[j] >> start_shift;
    j++;

    while (j * log_modulus < ((i + 1) * nbits) && j < in_len) {
      auto shift = j * log_modulus - i * nbits;
      value |= chunk_array_in[j] << shift;
      j++;
    }

    chunk_array_out[i] = value;
  }
}

/// Packs `num_lwes` LWE-ciphertext contained in `num_glwes` GLWE-ciphertext in
/// a compressed array This function follows the naming used in the CPU
/// implementation
template <typename Torus>
__host__ void host_pack(cudaStream_t stream, uint32_t gpu_index,
                        Torus *array_out, Torus *array_in, uint32_t num_glwes,
                        uint32_t num_lwes, int_compression<Torus> *mem_ptr) {
  if (array_in == array_out)
    PANIC("Cuda error: Input and output must be different");

  cuda_set_device(gpu_index);
  auto compression_params = mem_ptr->compression_params;

  auto log_modulus = mem_ptr->storage_log_modulus;
  // [0..num_glwes-1) GLWEs
  auto in_len = num_glwes * compression_params.glwe_dimension *
                    compression_params.polynomial_size +
                num_lwes;

  auto number_bits_to_pack = in_len * log_modulus;

  // number_bits_to_pack.div_ceil(Scalar::BITS)
  auto nbits = sizeof(Torus) * 8;
  auto out_len = (number_bits_to_pack + nbits - 1) / nbits;

  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(out_len, 1024, num_blocks, num_threads);

  dim3 grid(num_blocks);
  dim3 threads(num_threads);
  pack<Torus><<<grid, threads, 0, stream>>>(array_out, array_in, log_modulus,
                                            out_len, in_len, out_len);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ void
host_integer_compress(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                      uint32_t gpu_count, Torus *glwe_array_out,
                      Torus const *lwe_array_in, Torus *const *fp_ksk,
                      uint32_t num_radix_blocks,
                      int_compression<Torus> *mem_ptr) {

  auto compression_params = mem_ptr->compression_params;
  auto input_lwe_dimension = compression_params.small_lwe_dimension;

  // Shift
  auto lwe_shifted = mem_ptr->tmp_lwe;
  host_cleartext_multiplication<Torus>(
      streams[0], gpu_indexes[0], lwe_shifted, lwe_array_in,
      (uint64_t)compression_params.message_modulus, input_lwe_dimension,
      num_radix_blocks);

  uint32_t lwe_in_size = input_lwe_dimension + 1;
  uint32_t glwe_out_size = (compression_params.glwe_dimension + 1) *
                           compression_params.polynomial_size;
  uint32_t num_glwes =
      (num_radix_blocks + mem_ptr->lwe_per_glwe - 1) / mem_ptr->lwe_per_glwe;

  // Keyswitch LWEs to GLWE
  auto tmp_glwe_array_out = mem_ptr->tmp_glwe_array_out;
  cuda_memset_async(tmp_glwe_array_out, 0,
                    num_glwes * (compression_params.glwe_dimension + 1) *
                        compression_params.polynomial_size * sizeof(Torus),
                    streams[0], gpu_indexes[0]);
  auto fp_ks_buffer = mem_ptr->fp_ks_buffer;
  auto rem_lwes = num_radix_blocks;

  auto lwe_subset = lwe_shifted;
  auto glwe_out = tmp_glwe_array_out;
  while (rem_lwes > 0) {
    auto chunk_size = min(rem_lwes, mem_ptr->lwe_per_glwe);

    host_packing_keyswitch_lwe_list_to_glwe<Torus>(
        streams[0], gpu_indexes[0], glwe_out, lwe_subset, fp_ksk[0],
        fp_ks_buffer, input_lwe_dimension, compression_params.glwe_dimension,
        compression_params.polynomial_size, compression_params.ks_base_log,
        compression_params.ks_level, chunk_size);

    rem_lwes -= chunk_size;
    lwe_subset += chunk_size * lwe_in_size;
    glwe_out += glwe_out_size;
  }

  // Modulus switch
  host_modulus_switch_inplace<Torus>(
      streams[0], gpu_indexes[0], tmp_glwe_array_out,
      num_glwes * compression_params.glwe_dimension *
              compression_params.polynomial_size +
          num_radix_blocks,
      mem_ptr->storage_log_modulus);

  host_pack<Torus>(streams[0], gpu_indexes[0], glwe_array_out,
                   tmp_glwe_array_out, num_glwes, num_radix_blocks, mem_ptr);
}

template <typename Torus>
__global__ void extract(Torus *glwe_array_out, Torus const *array_in,
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

/// Extracts the glwe_index-nth GLWE ciphertext
/// This function follows the naming used in the CPU implementation
template <typename Torus>
__host__ void host_extract(cudaStream_t stream, uint32_t gpu_index,
                           Torus *glwe_array_out, Torus const *array_in,
                           uint32_t glwe_index,
                           int_decompression<Torus> *mem_ptr) {
  if (array_in == glwe_array_out)
    PANIC("Cuda error: Input and output must be different");

  cuda_set_device(gpu_index);

  auto compression_params = mem_ptr->compression_params;
  auto log_modulus = mem_ptr->storage_log_modulus;
  auto glwe_ciphertext_size = (compression_params.glwe_dimension + 1) *
                              compression_params.polynomial_size;

  uint32_t body_count = mem_ptr->body_count;
  auto num_glwes = (body_count + compression_params.polynomial_size - 1) /
                   compression_params.polynomial_size;

  // Compressed length of the compressed GLWE we want to extract
  if (mem_ptr->body_count % compression_params.polynomial_size == 0)
    body_count = compression_params.polynomial_size;
  else if (glwe_index == num_glwes - 1)
    body_count = mem_ptr->body_count % compression_params.polynomial_size;
  else
    body_count = compression_params.polynomial_size;

  auto initial_out_len =
      compression_params.glwe_dimension * compression_params.polynomial_size +
      body_count;

  // Calculates how many bits this particular GLWE shall use
  auto number_bits_to_unpack = initial_out_len * log_modulus;
  auto nbits = sizeof(Torus) * 8;

  // Calculates how many bits a full-packed GLWE shall use
  number_bits_to_unpack = glwe_ciphertext_size * log_modulus;
  auto len = (number_bits_to_unpack + nbits - 1) / nbits;
  // Uses that length to set the input pointer
  auto chunk_array_in = array_in + glwe_index * len;

  // Ensure the tail of the GLWE is zeroed
  if (initial_out_len < glwe_ciphertext_size) {
    cuda_memset_async(glwe_array_out, 0,
                      (glwe_ciphertext_size - initial_out_len) * sizeof(Torus),
                      stream, gpu_index);
  }

  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(initial_out_len, 128, num_blocks, num_threads);
  dim3 grid(num_blocks);
  dim3 threads(num_threads);
  extract<Torus><<<grid, threads, 0, stream>>>(glwe_array_out, chunk_array_in,
                                               log_modulus, initial_out_len);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ void host_integer_decompress(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *d_lwe_array_out, Torus const *d_packed_glwe_in,
    uint32_t const *h_indexes_array, uint32_t indexes_array_size,
    void *const *d_bsks, int_decompression<Torus> *h_mem_ptr) {

  auto d_indexes_array = h_mem_ptr->tmp_indexes_array;
  cuda_memcpy_async_to_gpu(d_indexes_array, (void *)h_indexes_array,
                           indexes_array_size * sizeof(uint32_t), streams[0],
                           gpu_indexes[0]);

  auto compression_params = h_mem_ptr->compression_params;
  auto lwe_per_glwe = compression_params.polynomial_size;

  auto num_radix_blocks = h_mem_ptr->num_radix_blocks;
  if (num_radix_blocks != indexes_array_size)
    PANIC("Cuda error: wrong number of LWEs in decompress: the number of LWEs "
          "should be the same as indexes_array_size.")

  // the first element is the number of LWEs that lies in the related GLWE
  std::vector<std::pair<int, Torus *>> glwe_vec;

  // Extract all GLWEs
  Torus glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                compression_params.polynomial_size;

  auto current_glwe_index = h_indexes_array[0] / lwe_per_glwe;
  auto extracted_glwe = h_mem_ptr->tmp_extracted_glwe;
  host_extract<Torus>(streams[0], gpu_indexes[0], extracted_glwe,
                      d_packed_glwe_in, current_glwe_index, h_mem_ptr);
  glwe_vec.push_back(std::make_pair(1, extracted_glwe));
  for (int i = 1; i < indexes_array_size; i++) {
    auto glwe_index = h_indexes_array[i] / lwe_per_glwe;
    if (glwe_index != current_glwe_index) {
      extracted_glwe += glwe_accumulator_size;
      current_glwe_index = glwe_index;
      // Extracts a new GLWE
      host_extract<Torus>(streams[0], gpu_indexes[0], extracted_glwe,
                          d_packed_glwe_in, glwe_index, h_mem_ptr);
      glwe_vec.push_back(std::make_pair(1, extracted_glwe));
    } else {
      // Updates the quantity
      ++glwe_vec.back().first;
    }
  }
  // Sample extract all LWEs
  Torus lwe_accumulator_size = compression_params.small_lwe_dimension + 1;

  auto extracted_lwe = h_mem_ptr->tmp_extracted_lwe;
  uint32_t current_idx = 0;
  auto d_indexes_array_chunk = d_indexes_array;
  for (const auto &max_idx_and_glwe : glwe_vec) {
    const auto num_lwes = max_idx_and_glwe.first;
    extracted_glwe = max_idx_and_glwe.second;

    cuda_glwe_sample_extract_64(
        streams[0], gpu_indexes[0], extracted_lwe, extracted_glwe,
        d_indexes_array_chunk, num_lwes, compression_params.polynomial_size,
        compression_params.glwe_dimension, compression_params.polynomial_size);
    d_indexes_array_chunk += num_lwes;
    extracted_lwe += num_lwes * lwe_accumulator_size;
    current_idx += num_lwes;
  }

  // Reset
  extracted_lwe = h_mem_ptr->tmp_extracted_lwe;

  // In the case of extracting a single LWE these parameters are dummy
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
  /// dimension to a big LWE dimension
  auto encryption_params = h_mem_ptr->encryption_params;
  auto lut = h_mem_ptr->decompression_rescale_lut;
  auto active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
  if (active_gpu_count == 1) {
    execute_pbs_async<Torus, Torus>(
        streams, gpu_indexes, active_gpu_count, d_lwe_array_out,
        lut->lwe_indexes_out, lut->lut_vec, lut->lut_indexes_vec, extracted_lwe,
        lut->lwe_indexes_in, d_bsks, nullptr, lut->buffer,
        encryption_params.glwe_dimension,
        compression_params.small_lwe_dimension,
        encryption_params.polynomial_size, encryption_params.pbs_base_log,
        encryption_params.pbs_level, encryption_params.grouping_factor,
        num_radix_blocks, encryption_params.pbs_type, num_many_lut, lut_stride);
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
        lut->h_lwe_indexes_in, lut->using_trivial_lwe_indexes, num_radix_blocks,
        compression_params.small_lwe_dimension + 1);

    /// Apply PBS
    execute_pbs_async<Torus, Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_array_in_vec, lwe_trivial_indexes_vec, d_bsks, nullptr, lut->buffer,
        encryption_params.glwe_dimension,
        compression_params.small_lwe_dimension,
        encryption_params.polynomial_size, encryption_params.pbs_base_log,
        encryption_params.pbs_level, encryption_params.grouping_factor,
        num_radix_blocks, encryption_params.pbs_type, num_many_lut, lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, d_lwe_array_out,
        lwe_after_pbs_vec, lut->h_lwe_indexes_out,
        lut->using_trivial_lwe_indexes, num_radix_blocks,
        encryption_params.big_lwe_dimension + 1);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
}

template <>
__host__ void host_integer_decompress<__uint128_t>(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, __uint128_t *d_lwe_array_out,
    __uint128_t const *d_packed_glwe_in, uint32_t const *h_indexes_array,
    uint32_t indexes_array_size, void *const *d_bsks,
    int_decompression<__uint128_t> *h_mem_ptr) {

  auto d_indexes_array = h_mem_ptr->tmp_indexes_array;
  cuda_memcpy_async_to_gpu(d_indexes_array, (void *)h_indexes_array,
                           indexes_array_size * sizeof(uint32_t), streams[0],
                           gpu_indexes[0]);

  auto compression_params = h_mem_ptr->compression_params;
  auto lwe_per_glwe = compression_params.polynomial_size;

  auto num_radix_blocks = h_mem_ptr->num_radix_blocks;
  if (num_radix_blocks != indexes_array_size)
    PANIC("Cuda error: wrong number of LWEs in decompress: the number of LWEs "
          "should be the same as indexes_array_size.")

  // the first element is the number of LWEs that lies in the related GLWE
  std::vector<std::pair<int, __uint128_t *>> glwe_vec;

  // Extract all GLWEs
  uint64_t glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                   compression_params.polynomial_size;

  auto current_glwe_index = h_indexes_array[0] / lwe_per_glwe;
  auto extracted_glwe = h_mem_ptr->tmp_extracted_glwe;
  host_extract<__uint128_t>(streams[0], gpu_indexes[0], extracted_glwe,
                            d_packed_glwe_in, current_glwe_index, h_mem_ptr);
  glwe_vec.push_back(std::make_pair(1, extracted_glwe));
  for (int i = 1; i < indexes_array_size; i++) {
    auto glwe_index = h_indexes_array[i] / lwe_per_glwe;
    if (glwe_index != current_glwe_index) {
      extracted_glwe += glwe_accumulator_size;
      current_glwe_index = glwe_index;
      // Extracts a new GLWE
      host_extract<__uint128_t>(streams[0], gpu_indexes[0], extracted_glwe,
                                d_packed_glwe_in, glwe_index, h_mem_ptr);
      glwe_vec.push_back(std::make_pair(1, extracted_glwe));
    } else {
      // Updates the quantity
      ++glwe_vec.back().first;
    }
  }
  // Sample extract all LWEs
  uint32_t lwe_accumulator_size = compression_params.small_lwe_dimension + 1;

  auto extracted_lwe = d_lwe_array_out;
  uint32_t current_idx = 0;
  auto d_indexes_array_chunk = d_indexes_array;
  for (const auto &max_idx_and_glwe : glwe_vec) {
    const auto num_lwes = max_idx_and_glwe.first;
    extracted_glwe = max_idx_and_glwe.second;

    cuda_glwe_sample_extract_64(
        streams[0], gpu_indexes[0], extracted_lwe, extracted_glwe,
        d_indexes_array_chunk, num_lwes, compression_params.polynomial_size,
        compression_params.glwe_dimension, compression_params.polynomial_size);
    d_indexes_array_chunk += num_lwes;
    extracted_lwe += num_lwes * lwe_accumulator_size;
    current_idx += num_lwes;
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_compress_integer_radix_ciphertext(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_compression<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params compression_params,
    uint32_t lwe_per_glwe, uint32_t storage_log_modulus,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_compression<Torus>(
      streams, gpu_indexes, gpu_count, compression_params, num_radix_blocks,
      lwe_per_glwe, storage_log_modulus, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_decompress_radix_ciphertext(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_decompression<Torus> **mem_ptr,
    uint32_t num_radix_blocks, uint32_t body_count,
    int_radix_params encryption_params, int_radix_params compression_params,
    uint32_t storage_log_modulus, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_decompression<Torus>(
      streams, gpu_indexes, gpu_count, encryption_params, compression_params,
      num_radix_blocks, body_count, storage_log_modulus, allocate_gpu_memory,
      size_tracker);
  return size_tracker;
}
#endif
