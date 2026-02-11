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
#include "utils/helper.cuh"

/*
 * =============================================================================
 * GPU Compression/Decompression Algorithm: Overview
 * =============================================================================
 *
 * The compression algorithm transforms standard LWE ciphertexts into a compact
 * packed format. Decompression reverses this process.
 *
 * -----------------------------------------------------------------------------
 * COMPRESSION INPUT (lwe_array_in)
 * -----------------------------------------------------------------------------
 *
 *  +-------------------------------------------------------------------------+
 *  |                    lwe_array_in (GPU memory)                            |
 *  +-------------------------------------------------------------------------+
 *  +---------------------------+---------------------------+-----------------+
 *  |          LWE 0            |          LWE 1            |      ...        |
 *  |      [mask, body]         |      [mask, body]         |                 |
 *  +---------------------------+---------------------------+-----------------+
 *  |<-- lwe_dimension + 1 -->|
 *
 *  Total LWEs: total_lwe_bodies_count (num_radix_blocks)
 *
 * -----------------------------------------------------------------------------
 * COMPRESSION PROCESS
 * -----------------------------------------------------------------------------
 *
 * 1. Message Shift (64-bit only):
 *    Each LWE is multiplied by message_modulus to shift the message to MSB
 *
 * 2. Packing Keyswitch (LWE -> GLWE):
 *    Groups of up to num_lwes_stored_per_glwe LWEs are packed into a single
 * GLWE:
 *
 *    +--------------------------------------------------------------+
 *    |   num_lwes_stored_per_glwe LWEs (input batch) | |   LWE[0], LWE[1], ...,
 * LWE[num_lwes_stored_per_glwe-1]                   |
 *    +--------------------------------------------------------------+
 *                              |
 *                    Packing Keyswitch
 *                              v
 *    +--------------------------------------------------------------+
 *    |            Single GLWE Ciphertext                            |
 *    |   [A_0, A_1, ..., A_{k-1}, B]                                |
 *    |   |<-- k * polynomial_size -->| |<-- polynomial_size -->|   |
 *    +--------------------------------------------------------------+
 *
 *    Number of output GLWEs: num_glwes = ceil(total_lwe_bodies_count /
 *                                             num_lwes_stored_per_glwe)
 *
 * 3. Modulus Switch:
 *    Reduce precision from 64-bit torus to storage_log_modulus bits
 *
 * 4. Bit Packing:
 *    Pack multiple reduced-precision elements into dense bit representation
 *
 * -----------------------------------------------------------------------------
 * COMPRESSION MEMORY LAYOUT (tmp_glwe_array_out)
 * -----------------------------------------------------------------------------
 *
 *  +-------------------------------------------------------------------------+
 *  |                 tmp_glwe_array_out (intermediate buffer)                |
 *  +-------------------------------------------------------------------------+
 *  +----------------------------+----------------------------+---------------+
 *  |         GLWE 0             |         GLWE 1             |    ...        |
 *  |  [A_0..A_{k-1}, B_0..B_N]  |  [A_0..A_{k-1}, B_0..B_N]  |               |
 *  +----------------------------+----------------------------+---------------+
 *       |<-- glwe_accumulator_size = (k+1)*N -->|
 *
 *  Total size needed: num_glwes * glwe_accumulator_size elements
 *  Where: num_glwes = ceil(total_lwe_bodies_count / num_lwes_stored_per_glwe)
 *
 * -----------------------------------------------------------------------------
 * PACKED OUTPUT (glwe_array_out)
 * -----------------------------------------------------------------------------
 *
 *  +-------------------------------------------------------------------------+
 *  |              Packed GLWE Ciphertext List (bit-packed)                   |
 *  +-------------------------------------------------------------------------+
 *  +-------------------------------------------------------------------------+
 *  |  Elements packed with storage_log_modulus bits per original element    |
 *  |  Total packed size: ceil(in_len * storage_log_modulus / 64) elements   |
 *  +-------------------------------------------------------------------------+
 *
 * =============================================================================
 * DECOMPRESSION (Extract) Algorithm
 * =============================================================================
 *
 * Decompression receives an array of LWE indexes. For each index, it identifies
 * the corresponding GLWE, extracts that GLWE from the packed representation,
 * and then sample-extracts the requested LWE from the GLWE.
 *
 * -----------------------------------------------------------------------------
 * EXTRACT OUTPUT LAYOUT (glwe_array_out in host_extract)
 * -----------------------------------------------------------------------------
 *
 *  +-------------------------------------------------------------------------+
 *  |               Extracted GLWE Ciphertext                                 |
 *  +-------------------------------------------------------------------------+
 *  +---------------------------------------+-----------------+---------------+
 *  |    Mask (A polynomials)               |   Body (B)      |    Tail       |
 *  |    [A_0, ..., A_{k-1}]                |   (body_count)  |   (zeroed)    |
 *  |    k * polynomial_size elements       |   elements      |   elements    |
 *  +---------------------------------------+-----------------+---------------+
 *  |<------------------- initial_out_len ------------------->|               |
 *  |<------------------------ glwe_ciphertext_size ------------------------->|
 *
 *  For the last GLWE, body_count may be less than polynomial_size (partial).
 *  The tail region must be zeroed to ensure defined behavior.
 *
 *  tail_size = glwe_ciphertext_size - initial_out_len
 *  tail_offset = initial_out_len  (NOT 0!)
 *
 * =============================================================================
 */

template <typename Torus>
__global__ void pack(Torus *array_out, Torus const *array_in,
                     uint32_t log_modulus, uint32_t num_coeffs, uint32_t in_len,
                     uint32_t in_stride, uint32_t out_len) {
  constexpr auto nbits = sizeof(Torus) * 8;
  auto tid = threadIdx.x + blockIdx.x * blockDim.x;

  auto glwe_index = tid / out_len;
  auto i = tid % out_len;
  // in_stride is the distance between consecutive GLWEs in the input buffer.
  // in_len is the number of meaningful elements to pack per GLWE.
  // When num_lwes_stored_per_glwe == polynomial_size, in_stride == in_len (flat
  // layout).
  auto chunk_array_in = array_in + glwe_index * in_stride;
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

/// Packs GLWE ciphertexts from a (possibly strided) input buffer into a
/// per-GLWE packed output. Each GLWE's in_len elements are bit-packed at
/// log_modulus bits each, producing out_len output elements per GLWE.
///
/// in_stride: distance between consecutive GLWEs in array_in (in elements).
///            For compact layout, in_stride == in_len.
///            For strided layout (packing keyswitch output), in_stride ==
///            (k+1)*N.
template <typename Torus>
__host__ void host_pack(cudaStream_t stream, uint32_t gpu_index,
                        Torus *packed_out, Torus const *array_in,
                        uint32_t log_modulus, uint32_t num_glwes,
                        uint32_t in_len, uint32_t in_stride) {
  if (array_in == packed_out)
    PANIC("Cuda error: Input and output must be different");

  cuda_set_device(gpu_index);

  constexpr auto nbits = sizeof(Torus) * 8;
  auto number_bits_to_pack = in_len * log_modulus;
  auto out_len = (uint32_t)CEIL_DIV(number_bits_to_pack, nbits);
  auto total_coeffs = num_glwes * out_len;

  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(total_coeffs, 1024, num_blocks, num_threads);

  pack<Torus><<<dim3(num_blocks), dim3(num_threads), 0, stream>>>(
      packed_out, array_in, log_modulus, total_coeffs, in_len, in_stride,
      out_len);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ void
host_integer_compress(CudaStreams streams,
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
        streams.stream(0), streams.gpu_index(0), lwe_pksk_input, lwe_array_in,
        (uint64_t)compression_params.message_modulus);
  }

  uint32_t lwe_in_size = compression_params.small_lwe_dimension + 1;
  uint32_t glwe_out_size = (compression_params.glwe_dimension + 1) *
                           compression_params.polynomial_size;
  // div_ceil
  uint32_t num_glwes = (glwe_array_out->total_lwe_bodies_count +
                        glwe_array_out->num_lwes_stored_per_glwe - 1) /
                       glwe_array_out->num_lwes_stored_per_glwe;
  PANIC_IF_FALSE(num_glwes <= mem_ptr->max_num_glwes,
                 "Invalid number of GLWEs");
  PANIC_IF_FALSE(glwe_array_out->num_lwes_stored_per_glwe ==
                     mem_ptr->num_lwes_stored_per_glwe,
                 "num_lwes_stored_per_glwe mismatch: scratch allocated with %u "
                 "but compress "
                 "called with %u",
                 mem_ptr->num_lwes_stored_per_glwe,
                 glwe_array_out->num_lwes_stored_per_glwe);
  PANIC_IF_FALSE(
      glwe_array_out->num_lwes_stored_per_glwe <=
          compression_params.polynomial_size,
      "num_lwes_stored_per_glwe (%u) must be <= polynomial_size (%u)",
      glwe_array_out->num_lwes_stored_per_glwe,
      compression_params.polynomial_size);

  // Keyswitch LWEs to GLWE
  auto tmp_glwe_array_out = mem_ptr->tmp_glwe_array_out;
  cuda_memset_async(
      tmp_glwe_array_out, 0,
      safe_mul_sizeof<Torus>((size_t)num_glwes,
                             (size_t)(compression_params.glwe_dimension + 1),
                             (size_t)compression_params.polynomial_size),
      streams.stream(0), streams.gpu_index(0));
  auto fp_ks_buffer = mem_ptr->fp_ks_buffer;
  auto rem_lwes = glwe_array_out->total_lwe_bodies_count;

  auto glwe_out = tmp_glwe_array_out;

  while (rem_lwes > 0) {
    auto chunk_size = min(rem_lwes, glwe_array_out->num_lwes_stored_per_glwe);

    host_packing_keyswitch_lwe_list_to_glwe<Torus>(
        streams.stream(0), streams.gpu_index(0), glwe_out, lwe_pksk_input,
        fp_ksk[0], fp_ks_buffer, compression_params.small_lwe_dimension,
        compression_params.glwe_dimension, compression_params.polynomial_size,
        compression_params.ks_base_log, compression_params.ks_level,
        chunk_size);

    rem_lwes -= chunk_size;
    lwe_pksk_input += chunk_size * lwe_in_size;
    glwe_out += glwe_out_size;
  }

  // Per-GLWE in_len: mask (k*N) + meaningful body (num_lwes_stored_per_glwe)
  uint32_t per_glwe_in_len =
      compression_params.glwe_dimension * compression_params.polynomial_size +
      glwe_array_out->num_lwes_stored_per_glwe;

  // Strided modswitch: process only the meaningful elements of each GLWE,
  // skipping garbage body positions [num_lwes_stored_per_glwe,
  // polynomial_size).
  host_modulus_switch_strided_inplace<Torus>(
      streams.stream(0), streams.gpu_index(0), tmp_glwe_array_out, num_glwes,
      per_glwe_in_len, glwe_out_size, glwe_array_out->storage_log_modulus);

  // Pack per-GLWE: read per_glwe_in_len elements from each GLWE in the
  // strided buffer (stride = glwe_out_size), pack into per-GLWE chunks.
  host_pack<Torus>(streams.stream(0), streams.gpu_index(0),
                   (Torus *)glwe_array_out->ptr, tmp_glwe_array_out,
                   glwe_array_out->storage_log_modulus, num_glwes,
                   per_glwe_in_len, glwe_out_size);
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
  auto num_lwes_stored_per_glwe = array_in->num_lwes_stored_per_glwe;

  auto glwe_ciphertext_size = (glwe_dimension + 1) * polynomial_size;

  uint32_t num_glwes =
      CEIL_DIV(total_lwe_bodies_count, num_lwes_stored_per_glwe);

  // Determine how many body elements this GLWE carries. Non-last GLWEs have
  // num_lwes_stored_per_glwe bodies; the last may have fewer if
  // total_lwe_bodies_count is not a multiple of num_lwes_stored_per_glwe.
  uint32_t body_count = 0;
  if (glwe_index == num_glwes - 1) {
    auto remainder = total_lwe_bodies_count % num_lwes_stored_per_glwe;
    body_count = (remainder == 0) ? num_lwes_stored_per_glwe : remainder;
  } else {
    body_count = num_lwes_stored_per_glwe;
  }

  // initial_out_len: number of elements to unpack (mask + meaningful body).
  // The output GLWE polynomial is still of size polynomial_size, but only
  // body_count body coefficients are populated from packed data.
  uint32_t initial_out_len = glwe_dimension * polynomial_size + body_count;

  auto nbits = sizeof(Torus) * 8;

  // All GLWEs are packed at uniform stride = ceil((k*N +
  // num_lwes_stored_per_glwe) * log_modulus / nbits). The last GLWE has fewer
  // meaningful body elements but the same packed stride (extra bits are
  // zero-padded).
  auto per_glwe_uncompressed =
      glwe_dimension * polynomial_size + num_lwes_stored_per_glwe;
  auto per_glwe_packed_len =
      CEIL_DIV(per_glwe_uncompressed * log_modulus, nbits);
  auto chunk_array_in =
      (Torus *)array_in->ptr + glwe_index * per_glwe_packed_len;

  // Ensure the tail of the GLWE is zeroed
  // The extract kernel writes initial_out_len elements starting at offset 0.
  // We must zero the tail region (from initial_out_len to
  // glwe_ciphertext_size)
  if (initial_out_len < glwe_ciphertext_size) {
    cuda_memset_async(glwe_array_out + initial_out_len, 0,
                      safe_mul_sizeof<Torus>(
                          (size_t)(glwe_ciphertext_size - initial_out_len)),
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
host_integer_decompress(CudaStreams streams,
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
                           safe_mul_sizeof<uint32_t>(num_blocks_to_decompress),
                           streams.stream(0), streams.gpu_index(0));

  auto compression_params = h_mem_ptr->compression_params;
  auto num_lwes_stored_per_glwe = d_packed_glwe_in->num_lwes_stored_per_glwe;

  // the first element is the number of LWEs that lies in the related GLWE
  std::vector<std::pair<int, Torus *>> glwe_vec;

  // Extract all GLWEs
  Torus glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                compression_params.polynomial_size;

  auto current_glwe_index = h_indexes_array[0] / num_lwes_stored_per_glwe;
  auto extracted_glwe = h_mem_ptr->tmp_extracted_glwe;
  host_extract<Torus>(streams.stream(0), streams.gpu_index(0), extracted_glwe,
                      d_packed_glwe_in, current_glwe_index);
  glwe_vec.push_back(std::make_pair(1, extracted_glwe));
  for (int i = 1; i < num_blocks_to_decompress; i++) {
    auto glwe_index = h_indexes_array[i] / num_lwes_stored_per_glwe;
    if (glwe_index != current_glwe_index) {
      extracted_glwe += glwe_accumulator_size;
      current_glwe_index = glwe_index;
      // Extracts a new GLWE
      host_extract<Torus>(streams.stream(0), streams.gpu_index(0),
                          extracted_glwe, d_packed_glwe_in, glwe_index);
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
      cuda_glwe_sample_extract_64_async(
          streams.stream(0), streams.gpu_index(0), extracted_lwe,
          extracted_glwe, d_indexes_array_chunk, num_lwes, num_lwes,
          num_lwes_stored_per_glwe, compression_params.glwe_dimension,
          compression_params.polynomial_size);
    else
      // 128 bits
      cuda_glwe_sample_extract_128_async(
          streams.stream(0), streams.gpu_index(0), extracted_lwe,
          extracted_glwe, d_indexes_array_chunk, num_lwes, num_lwes,
          num_lwes_stored_per_glwe, compression_params.glwe_dimension,
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
    auto active_streams = streams.active_gpu_subset(
        num_blocks_to_decompress,
        h_mem_ptr->decompression_rescale_lut->params.pbs_type);
    if (active_streams.count() == 1) {
      execute_pbs_async<Torus, Torus>(
          active_streams, (Torus *)d_lwe_array_out->ptr, lut->lwe_indexes_out,
          lut->lut_vec, lut->lut_indexes_vec, extracted_lwe,
          lut->lwe_indexes_in, d_bsks, lut->buffer,
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

      lut->multi_gpu_scatter_barrier.local_streams_wait_for_stream_0(
          active_streams);

      /// With multiple GPUs we push to the vectors on each GPU then when we
      /// gather data to GPU 0 we can copy back to the original indexing
      multi_gpu_scatter_lwe_async<Torus>(
          active_streams, lwe_array_in_vec, extracted_lwe, lut->lwe_indexes_in,
          lut->using_trivial_lwe_indexes, lut->lwe_aligned_vec, lut->event_pool,
          lut->active_streams.count(), num_blocks_to_decompress,
          compression_params.small_lwe_dimension + 1);

      /// Apply PBS
      execute_pbs_async<Torus, Torus>(
          active_streams, lwe_after_pbs_vec, lwe_trivial_indexes_vec,
          lut->lut_vec, lut->lut_indexes_vec, lwe_array_in_vec,
          lwe_trivial_indexes_vec, d_bsks, lut->buffer,
          encryption_params.glwe_dimension,
          compression_params.small_lwe_dimension,
          encryption_params.polynomial_size, encryption_params.pbs_base_log,
          encryption_params.pbs_level, encryption_params.grouping_factor,
          num_blocks_to_decompress, encryption_params.pbs_type, num_many_lut,
          lut_stride);

      /// Copy data back to GPU 0 and release vecs
      multi_gpu_gather_lwe_async<Torus>(
          active_streams, (Torus *)d_lwe_array_out->ptr, lwe_after_pbs_vec,
          lut->lwe_indexes_out, lut->using_trivial_lwe_indexes,
          lut->lwe_aligned_vec, lut->event_pool, num_blocks_to_decompress,
          encryption_params.big_lwe_dimension + 1);

      /// Synchronize all GPUs
      // other gpus record their events
      lut->multi_gpu_gather_barrier.stream_0_wait_for_local_streams(
          active_streams);
    }
  } else {
    static_assert(std::is_same_v<Torus, __uint128_t>,
                  "Torus must be either uint64_t or __uint128_t");
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_compress_ciphertext(
    CudaStreams streams, int_compression<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params compression_params,
    uint32_t num_lwes_stored_per_glwe, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_compression<Torus>(
      streams, compression_params, num_radix_blocks, num_lwes_stored_per_glwe,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_decompress_radix_ciphertext(
    CudaStreams streams, int_decompression<Torus> **mem_ptr,
    uint32_t num_blocks_to_decompress, int_radix_params encryption_params,
    int_radix_params compression_params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_decompression<Torus>(
      streams, encryption_params, compression_params, num_blocks_to_decompress,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}
#endif
