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
  constexpr auto nbits = sizeof(Torus) * 8;
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
                        CudaPackedGlweCiphertextListFFI *array_out,
                        Torus *array_in, uint32_t num_glwes,
                        int_radix_params compression_params) {
  if (array_in == (Torus *)array_out->ptr)
    PANIC("Cuda error: Input and output must be different");

  cuda_set_device(gpu_index);

  auto log_modulus = array_out->storage_log_modulus;
  // [0..num_glwes-1) GLWEs
  auto in_len = num_glwes * compression_params.glwe_dimension *
                    compression_params.polynomial_size +
                array_out->total_lwe_bodies_count;

  auto number_bits_to_pack = in_len * log_modulus;

  // number_bits_to_pack.div_ceil(Scalar::BITS)
  auto nbits = sizeof(Torus) * 8;
  auto out_len = (number_bits_to_pack + nbits - 1) / nbits;

  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(out_len, 1024, num_blocks, num_threads);

  dim3 grid(num_blocks);
  dim3 threads(num_threads);
  pack<Torus><<<grid, threads, 0, stream>>>(
      (Torus *)array_out->ptr, array_in, log_modulus, out_len, in_len, out_len);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ void
host_integer_compress(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                      uint32_t gpu_count,
                      CudaPackedGlweCiphertextListFFI *glwe_array_out,
                      CudaLweCiphertextListFFI const *lwe_array_in,
                      Torus *const *fp_ksk, int_compression<Torus> *mem_ptr) {

  static_assert(std::is_same_v<Torus, uint64_t> ||
                    std::is_same_v<Torus, __uint128_t>,
                "Torus must be either uint64_t or __uint128_t");

  auto compression_params = mem_ptr->compression_params;

  // Shift
  auto lwe_pksk_input = (Torus *)lwe_array_in->ptr;

  if constexpr (std::is_same_v<Torus, uint64_t>) {
    lwe_pksk_input = mem_ptr->tmp_lwe;
    host_cleartext_multiplication<Torus>(
        streams[0], gpu_indexes[0], lwe_pksk_input, lwe_array_in,
        (uint64_t)compression_params.message_modulus);
  }

  uint32_t lwe_in_size = compression_params.small_lwe_dimension + 1;
  uint32_t glwe_out_size = (compression_params.glwe_dimension + 1) *
                           compression_params.polynomial_size;
  // div_ceil
  uint32_t num_glwes = (glwe_array_out->total_lwe_bodies_count +
                        glwe_array_out->lwe_per_glwe - 1) /
                       glwe_array_out->lwe_per_glwe;

  // Keyswitch LWEs to GLWE
  auto tmp_glwe_array_out = mem_ptr->tmp_glwe_array_out;
  cuda_memset_async(tmp_glwe_array_out, 0,
                    num_glwes * (compression_params.glwe_dimension + 1) *
                        compression_params.polynomial_size * sizeof(Torus),
                    streams[0], gpu_indexes[0]);
  auto fp_ks_buffer = mem_ptr->fp_ks_buffer;
  auto rem_lwes = glwe_array_out->total_lwe_bodies_count;

  auto glwe_out = tmp_glwe_array_out;

  while (rem_lwes > 0) {
    auto chunk_size = min(rem_lwes, glwe_array_out->lwe_per_glwe);

    host_packing_keyswitch_lwe_list_to_glwe<Torus>(
        streams[0], gpu_indexes[0], glwe_out, lwe_pksk_input, fp_ksk[0],
        fp_ks_buffer, compression_params.small_lwe_dimension,
        compression_params.glwe_dimension, compression_params.polynomial_size,
        compression_params.ks_base_log, compression_params.ks_level,
        chunk_size);

    rem_lwes -= chunk_size;
    lwe_pksk_input += chunk_size * lwe_in_size;
    glwe_out += glwe_out_size;
  }

  // Modulus switch
  int size = num_glwes * compression_params.glwe_dimension *
                 compression_params.polynomial_size +
             glwe_array_out->total_lwe_bodies_count;

  host_modulus_switch_inplace<Torus>(streams[0], gpu_indexes[0],
                                     tmp_glwe_array_out, size,
                                     glwe_array_out->storage_log_modulus);

  host_pack<Torus>(streams[0], gpu_indexes[0], glwe_array_out,
                   tmp_glwe_array_out, num_glwes, compression_params);
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
                           Torus *glwe_array_out,
                           CudaPackedGlweCiphertextListFFI const *array_in,
                           uint32_t glwe_index) {
  if ((Torus *)array_in->ptr == glwe_array_out)
    PANIC("Cuda error: Input and output must be different");

  cuda_set_device(gpu_index);

  auto log_modulus = array_in->storage_log_modulus;
  auto total_lwe_bodies_count = array_in->total_lwe_bodies_count;
  auto polynomial_size = array_in->polynomial_size;
  auto glwe_dimension = array_in->glwe_dimension;

  auto glwe_ciphertext_size = (glwe_dimension + 1) * polynomial_size;

  uint32_t num_glwes =
      (total_lwe_bodies_count + polynomial_size - 1) / polynomial_size;

  // Compressed length of the compressed GLWE we want to extract
  uint32_t body_count = 0;
  if (glwe_index == num_glwes - 1) {
    auto remainder = total_lwe_bodies_count % polynomial_size;
    if (remainder == 0) {
      body_count = polynomial_size;
    } else {
      body_count = remainder;
    }
  } else {
    body_count = polynomial_size;
  }

  uint32_t initial_out_len = glwe_dimension * polynomial_size + body_count;

  // Calculates how many bits this particular GLWE shall use
  auto number_bits_to_unpack = initial_out_len * log_modulus;
  auto nbits = sizeof(Torus) * 8;

  // Calculates how many bits a full-packed GLWE shall use
  number_bits_to_unpack = glwe_ciphertext_size * log_modulus;
  auto len = (number_bits_to_unpack + nbits - 1) / nbits;
  // Uses that length to set the input pointer
  auto chunk_array_in = (Torus *)array_in->ptr + glwe_index * len;

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
__host__ void
host_integer_decompress(cudaStream_t const *streams,
                        uint32_t const *gpu_indexes, uint32_t gpu_count,
                        CudaLweCiphertextListFFI *d_lwe_array_out,
                        CudaPackedGlweCiphertextListFFI const *d_packed_glwe_in,
                        uint32_t const *h_indexes_array, void *const *d_bsks,
                        int_decompression<Torus> *h_mem_ptr) {

  static_assert(std::is_same_v<Torus, uint64_t> ||
                    std::is_same_v<Torus, __uint128_t>,
                "Torus must be either uint64_t or __uint128_t");
  auto num_blocks_to_decompress = h_mem_ptr->num_blocks_to_decompress;

  auto d_indexes_array = h_mem_ptr->tmp_indexes_array;
  cuda_memcpy_async_to_gpu(d_indexes_array, (void *)h_indexes_array,
                           num_blocks_to_decompress * sizeof(uint32_t),
                           streams[0], gpu_indexes[0]);

  auto compression_params = h_mem_ptr->compression_params;
  auto lwe_per_glwe = compression_params.polynomial_size;

  // the first element is the number of LWEs that lies in the related GLWE
  std::vector<std::pair<int, Torus *>> glwe_vec;

  // Extract all GLWEs
  Torus glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                compression_params.polynomial_size;

  auto current_glwe_index = h_indexes_array[0] / lwe_per_glwe;
  auto extracted_glwe = h_mem_ptr->tmp_extracted_glwe;
  host_extract<Torus>(streams[0], gpu_indexes[0], extracted_glwe,
                      d_packed_glwe_in, current_glwe_index);
  glwe_vec.push_back(std::make_pair(1, extracted_glwe));
  for (int i = 1; i < num_blocks_to_decompress; i++) {
    auto glwe_index = h_indexes_array[i] / lwe_per_glwe;
    if (glwe_index != current_glwe_index) {
      extracted_glwe += glwe_accumulator_size;
      current_glwe_index = glwe_index;
      // Extracts a new GLWE
      host_extract<Torus>(streams[0], gpu_indexes[0], extracted_glwe,
                          d_packed_glwe_in, glwe_index);
      glwe_vec.push_back(std::make_pair(1, extracted_glwe));
    } else {
      // Updates the quantity
      ++glwe_vec.back().first;
    }
  }
  // Sample extract all LWEs
  auto lwe_size = compression_params.small_lwe_dimension + 1;

  Torus *extracted_lwe;
  if constexpr (std::is_same_v<Torus, uint64_t>) {
    // 64 bits
    extracted_lwe = h_mem_ptr->tmp_extracted_lwe;
  } else {
    // 128 bits
    // We skip the PBS at the end
    extracted_lwe = static_cast<Torus *>(d_lwe_array_out->ptr);
  }
  uint32_t current_idx = 0;
  auto d_indexes_array_chunk = d_indexes_array;
  for (const auto &max_idx_and_glwe : glwe_vec) {
    const auto num_lwes = max_idx_and_glwe.first;
    extracted_glwe = max_idx_and_glwe.second;

    if constexpr (std::is_same_v<Torus, uint64_t>)
      cuda_glwe_sample_extract_64(streams[0], gpu_indexes[0], extracted_lwe,
                                  extracted_glwe, d_indexes_array_chunk,
                                  num_lwes, compression_params.polynomial_size,
                                  compression_params.glwe_dimension,
                                  compression_params.polynomial_size);
    else
      // 128 bits
      cuda_glwe_sample_extract_128(streams[0], gpu_indexes[0], extracted_lwe,
                                   extracted_glwe, d_indexes_array_chunk,
                                   num_lwes, compression_params.polynomial_size,
                                   compression_params.glwe_dimension,
                                   compression_params.polynomial_size);

    d_indexes_array_chunk += num_lwes;
    extracted_lwe += num_lwes * lwe_size;
    current_idx += num_lwes;
  }

  if constexpr (std::is_same_v<Torus, uint64_t>) {
    // Reset
    extracted_lwe = h_mem_ptr->tmp_extracted_lwe;

    // In the case of extracting a single LWE these parameters are dummy
    uint32_t num_many_lut = 1;
    uint32_t lut_stride = 0;
    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    auto encryption_params = h_mem_ptr->encryption_params;
    auto lut = h_mem_ptr->decompression_rescale_lut;
    auto active_gpu_count =
        get_active_gpu_count(num_blocks_to_decompress, gpu_count);
    if (active_gpu_count == 1) {
      execute_pbs_async<Torus, Torus>(
          streams, gpu_indexes, active_gpu_count, (Torus *)d_lwe_array_out->ptr,
          lut->lwe_indexes_out, lut->lut_vec, lut->lut_indexes_vec,
          extracted_lwe, lut->lwe_indexes_in, d_bsks, nullptr, lut->buffer,
          encryption_params.glwe_dimension,
          compression_params.small_lwe_dimension,
          encryption_params.polynomial_size, encryption_params.pbs_base_log,
          encryption_params.pbs_level, encryption_params.grouping_factor,
          num_blocks_to_decompress, encryption_params.pbs_type, num_many_lut,
          lut_stride);
    } else {
      /// For multi GPU execution we create vectors of pointers for inputs and
      /// outputs
      std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
      std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
      std::vector<Torus *> lwe_trivial_indexes_vec =
          lut->lwe_trivial_indexes_vec;

      /// Make sure all data that should be on GPU 0 is indeed there
      cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    /// With multiple GPUs we push to the vectors on each GPU then when we
    /// gather data to GPU 0 we can copy back to the original indexing
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec, extracted_lwe,
        lut->lwe_indexes_in, lut->using_trivial_lwe_indexes,
        lut->active_gpu_count, num_blocks_to_decompress,
        compression_params.small_lwe_dimension + 1);

      /// Apply PBS
      execute_pbs_async<Torus, Torus>(
          streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
          lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
          lwe_array_in_vec, lwe_trivial_indexes_vec, d_bsks, nullptr,
          lut->buffer, encryption_params.glwe_dimension,
          compression_params.small_lwe_dimension,
          encryption_params.polynomial_size, encryption_params.pbs_base_log,
          encryption_params.pbs_level, encryption_params.grouping_factor,
          num_blocks_to_decompress, encryption_params.pbs_type, num_many_lut,
          lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, (Torus *)d_lwe_array_out->ptr,
        lwe_after_pbs_vec, lut->lwe_indexes_out, lut->using_trivial_lwe_indexes,
        num_blocks_to_decompress, encryption_params.big_lwe_dimension + 1);

      /// Synchronize all GPUs
      for (uint i = 0; i < active_gpu_count; i++) {
        cuda_synchronize_stream(streams[i], gpu_indexes[i]);
      }
    }
  } else {
    static_assert(std::is_same_v<Torus, __uint128_t>,
                  "Torus must be either uint64_t or __uint128_t");
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_compress_integer_radix_ciphertext(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_compression<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params compression_params,
    uint32_t lwe_per_glwe, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_compression<Torus>(
      streams, gpu_indexes, gpu_count, compression_params, num_radix_blocks,
      lwe_per_glwe, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_decompress_radix_ciphertext(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_decompression<Torus> **mem_ptr,
    uint32_t num_blocks_to_decompress, int_radix_params encryption_params,
    int_radix_params compression_params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_decompression<Torus>(
      streams, gpu_indexes, gpu_count, encryption_params, compression_params,
      num_blocks_to_decompress, allocate_gpu_memory, size_tracker);
  return size_tracker;
}
#endif
