#ifndef AES_CUH
#define AES_CUH

#include "../../include/aes/aes_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../linearalgebra/addition.cuh"

template <typename Torus>
uint64_t scratch_cuda_integer_aes_encrypt(
    CudaStreams streams, int_aes_encrypt_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_aes_encrypt_buffer<Torus>(
      streams, params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism,
      size_tracker);
  return size_tracker;
}

/**
 * Transposes a collection of AES states from a block-oriented layout to a
 * bit-sliced layout. This is a crucial data restructuring step for efficient
 * homomorphic bitwise operations.
 *
 * Source (Block-oriented)                   Destination (Bitsliced)
 * Block 0: [B0b0, B0b1, B0b2, ...]          Slice 0: [B0b0, B1b0, B2b0, ...]
 * Block 1: [B1b0, B1b1, B1b2, ...]  ----->  Slice 1: [B0b1, B1b1, B2b1, ...]
 * Block 2: [B2b0, B2b1, B2b2, ...]          Slice 2: [B0b2, B1b2, B2b2, ...]
 * ...                                       ...
 *
 */
template <typename Torus>
__host__ void
transpose_blocks_to_bitsliced(cudaStream_t stream, uint32_t gpu_index,
                              CudaRadixCiphertextFFI *dest_bitsliced,
                              const CudaRadixCiphertextFFI *source_blocks,
                              uint32_t num_aes_inputs,
                              uint32_t block_size_bits) {

  PANIC_IF_FALSE(dest_bitsliced != source_blocks,
                 "transpose_blocks_to_bitsliced is not an in-place function.");

  for (uint32_t i = 0; i < block_size_bits; ++i) {
    for (uint32_t j = 0; j < num_aes_inputs; ++j) {
      uint32_t src_idx = j * block_size_bits + i;
      uint32_t dest_idx = i * num_aes_inputs + j;
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, dest_bitsliced, dest_idx, dest_idx + 1,
          source_blocks, src_idx, src_idx + 1);
    }
  }
}

/**
 * Transposes a collection of AES states from a bit-sliced layout back to a
 * block-oriented layout. This is the inverse of
 * 'transpose_blocks_to_bitsliced'.
 *
 */
template <typename Torus>
__host__ void
transpose_bitsliced_to_blocks(cudaStream_t stream, uint32_t gpu_index,
                              CudaRadixCiphertextFFI *dest_blocks,
                              const CudaRadixCiphertextFFI *source_bitsliced,
                              uint32_t num_aes_inputs,
                              uint32_t block_size_bits) {

  PANIC_IF_FALSE(dest_blocks != source_bitsliced,
                 "transpose_bitsliced_to_blocks is not an in-place function.");

  for (uint32_t i = 0; i < block_size_bits; ++i) {
    for (uint32_t j = 0; j < num_aes_inputs; ++j) {
      uint32_t src_idx = i * num_aes_inputs + j;
      uint32_t dest_idx = j * block_size_bits + i;
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, dest_blocks, dest_idx, dest_idx + 1,
          source_bitsliced, src_idx, src_idx + 1);
    }
  }
}

/**
 * Performs a vectorized homomorphic XOR operation on two sets of ciphertexts.
 *
 */
template <typename Torus>
__host__ __forceinline__ void
aes_xor(CudaStreams streams, int_aes_encrypt_buffer<Torus> *mem,
        CudaRadixCiphertextFFI *out, const CudaRadixCiphertextFFI *lhs,
        const CudaRadixCiphertextFFI *rhs) {

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), out, lhs, rhs,
                       out->num_radix_blocks, mem->params.message_modulus,
                       mem->params.carry_modulus);
}

/**
 * Applies a "flush" Look-Up Table (LUT) to a vector of ciphertexts.
 * This operation isolates the first message bit (the LSB) by applying the
 * identity function to it, while discarding any higher-order bits
 * that may have resulted from previous additions. This effectively cleans the
 * result.
 *
 */
template <typename Torus, typename KSTorus>
__host__ __forceinline__ void
aes_flush_inplace(CudaStreams streams, CudaRadixCiphertextFFI *data,
                  int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
                  KSTorus *const *ksks) {

  integer_radix_apply_univariate_lookup_table<Torus>(streams, data, data, bsks,
                                                     ksks, mem->luts->flush_lut,
                                                     data->num_radix_blocks);
}

/**
 * Performs an operation: homomorphically adds a plaintext 1 to a
 * ciphertext, then flushes the result to ensure it's a valid bit.
 *
 */
template <typename Torus, typename KSTorus>
__host__ __forceinline__ void
aes_scalar_add_one_flush_inplace(CudaStreams streams,
                                 CudaRadixCiphertextFFI *data,
                                 int_aes_encrypt_buffer<Torus> *mem,
                                 void *const *bsks, KSTorus *const *ksks) {

  host_add_scalar_one_inplace<Torus>(streams, data, mem->params.message_modulus,
                                     mem->params.carry_modulus);

  aes_flush_inplace(streams, data, mem, bsks, ksks);
}

/**
 * Batches multiple "flush" operations into a single operation.
 * This is done in three steps:
 * 1. GATHER: All target ciphertexts are copied into one large, contiguous
 * buffer.
 * 2. PROCESS: A single flush operation is executed on the entire buffer.
 * 3. SCATTER: The results are copied from the buffer back to the original
 * ciphertext locations.
 *
 */
template <typename Torus, typename KSTorus>
__host__ void
batch_vec_flush_inplace(CudaStreams streams, CudaRadixCiphertextFFI **targets,
                        size_t count, int_aes_encrypt_buffer<Torus> *mem,
                        void *const *bsks, KSTorus *const *ksks) {

  uint32_t num_radix_blocks = targets[0]->num_radix_blocks;

  CudaRadixCiphertextFFI batch_in, batch_out;
  as_radix_ciphertext_slice<Torus>(
      &batch_in, mem->main_workspaces->batch_processing_buffer, 0,
      count * num_radix_blocks);
  as_radix_ciphertext_slice<Torus>(
      &batch_out, mem->main_workspaces->batch_processing_buffer,
      count * num_radix_blocks, (2 * count) * num_radix_blocks);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI dest_slice;
    as_radix_ciphertext_slice<Torus>(&dest_slice, &batch_in,
                                     i * num_radix_blocks,
                                     (i + 1) * num_radix_blocks);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_slice, targets[i]);
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &batch_out, &batch_in, bsks, ksks, mem->luts->flush_lut,
      batch_out.num_radix_blocks);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI src_slice;
    as_radix_ciphertext_slice<Torus>(&src_slice, &batch_out,
                                     i * num_radix_blocks,
                                     (i + 1) * num_radix_blocks);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       targets[i], &src_slice);
  }
}

/**
 * Batches multiple "and" operations into a single, large launch.
 *
 */
template <typename Torus, typename KSTorus>
__host__ void batch_vec_and_inplace(CudaStreams streams,
                                    CudaRadixCiphertextFFI **outs,
                                    CudaRadixCiphertextFFI **lhs,
                                    CudaRadixCiphertextFFI **rhs, size_t count,
                                    int_aes_encrypt_buffer<Torus> *mem,
                                    void *const *bsks, KSTorus *const *ksks) {

  uint32_t num_aes_inputs = outs[0]->num_radix_blocks;

  CudaRadixCiphertextFFI batch_lhs, batch_rhs, batch_out;
  as_radix_ciphertext_slice<Torus>(
      &batch_lhs, mem->main_workspaces->batch_processing_buffer, 0,
      count * num_aes_inputs);
  as_radix_ciphertext_slice<Torus>(
      &batch_rhs, mem->main_workspaces->batch_processing_buffer,
      count * num_aes_inputs, (2 * count) * num_aes_inputs);
  as_radix_ciphertext_slice<Torus>(
      &batch_out, mem->main_workspaces->batch_processing_buffer,
      (2 * count) * num_aes_inputs, (3 * count) * num_aes_inputs);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI dest_lhs_slice, dest_rhs_slice;
    as_radix_ciphertext_slice<Torus>(&dest_lhs_slice, &batch_lhs,
                                     i * num_aes_inputs,
                                     (i + 1) * num_aes_inputs);
    as_radix_ciphertext_slice<Torus>(&dest_rhs_slice, &batch_rhs,
                                     i * num_aes_inputs,
                                     (i + 1) * num_aes_inputs);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_lhs_slice, lhs[i]);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_rhs_slice, rhs[i]);
  }

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, &batch_out, &batch_lhs, &batch_rhs, bsks, ksks,
      mem->luts->and_lut, batch_out.num_radix_blocks,
      mem->params.message_modulus);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI src_slice;
    as_radix_ciphertext_slice<Torus>(&src_slice, &batch_out, i * num_aes_inputs,
                                     (i + 1) * num_aes_inputs);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       outs[i], &src_slice);
  }
}

/**
 * Implements the AES S-Box substitution for two bytes in parallel using a
 * bitsliced circuit design.
 *
 * Boyar-Peralta circuit: https://eprint.iacr.org/2011/332.pdf
 *
 * sbox_io_bytes (Input: Array of pointers to separate bytes)
 * [ptr] -> [B0b0, B0b1, B0b2, B0b3, B0b4, B0b5, B0b6, B0b7]
 * [ptr] -> [B1b0, B1b1, B1b2, B1b3, B1b4, B1b5, B1b6, B1b7]
 * [ptr] -> [B2b0, B2b1, B2b2, B2b3, B2b4, B2b5, B2b6, B2b7]
 * ...
 * |
 * | GATHER
 * V
 * Internal Bitsliced Buffer (input_bits)
 * Slice 0: [B0b0, B1b0, B2b0, ...] (All the 0th bits)
 * Slice 1: [B0b1, B1b1, B2b1, ...] (All the 1st bits)
 * Slice 2: [B0b2, B1b2, B2b2, ...] (All the 2nd bits)
 * ...
 * |
 * V
 * +----------------------------------+
 * |   Homomorphic S-Box Evaluation   |
 * +----------------------------------+
 * |
 * V
 * Internal Bitsliced Buffer (output_bits)
 * Result Slice 0: [R0b0, R1b0, R2b0, ...]
 * Result Slice 1: [R0b1, R1b1, R2b1, ...]
 * Result Slice 2: [R0b2, R1b2, R2b2, ...]
 * ...
 * |
 * | SCATTER
 * V
 * sbox_io_bytes (Output: Results written back in-place)
 * [ptr] -> [R0b0, R0b1, R0b2, R0b3, R0b4, R0b5, R0b6, R0b7]
 * [ptr] -> [R1b0, R1b1, R1b2, R1b3, R1b4, R1b5, R1b6, R1b7]
 * [ptr] -> [R2b0, R2b1, R2b2, R2b3, R2b4, R2b5, R2b6, R2b7]
 * ...
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_sbox_n_bytes(CudaStreams streams,
                                      CudaRadixCiphertextFFI **sbox_io_bytes,
                                      uint32_t num_bytes_parallel,
                                      uint32_t num_aes_inputs,
                                      int_aes_encrypt_buffer<Torus> *mem,
                                      void *const *bsks, KSTorus *const *ksks) {

  uint32_t num_sbox_blocks = num_bytes_parallel * num_aes_inputs;

  constexpr uint32_t INPUT_BITS_LEN = 8;
  constexpr uint32_t OUTPUT_BITS_LEN = 8;
  constexpr uint32_t WIRES_A_LEN = 22;
  constexpr uint32_t WIRES_B_LEN = 68;
  constexpr uint32_t WIRES_C_LEN = 18;

  CudaRadixCiphertextFFI wires_a[WIRES_A_LEN], wires_b[WIRES_B_LEN],
      wires_c[WIRES_C_LEN];

  for (uint32_t i = 0; i < WIRES_A_LEN; ++i)
    as_radix_ciphertext_slice<Torus>(
        &wires_a[i], mem->main_workspaces->sbox_internal_workspace,
        i * num_sbox_blocks, (i + 1) * num_sbox_blocks);
  for (uint32_t i = 0; i < WIRES_B_LEN; ++i)
    as_radix_ciphertext_slice<Torus>(
        &wires_b[i], mem->main_workspaces->sbox_internal_workspace,
        (WIRES_A_LEN + i) * num_sbox_blocks,
        (WIRES_A_LEN + i + 1) * num_sbox_blocks);
  for (uint32_t i = 0; i < WIRES_C_LEN; ++i)
    as_radix_ciphertext_slice<Torus>(
        &wires_c[i], mem->main_workspaces->sbox_internal_workspace,
        (WIRES_A_LEN + WIRES_B_LEN + i) * num_sbox_blocks,
        (WIRES_A_LEN + WIRES_B_LEN + i + 1) * num_sbox_blocks);

  // Input Reordering (Gather)
  //

  CudaRadixCiphertextFFI input_bits[INPUT_BITS_LEN];
  CudaRadixCiphertextFFI *reordered_input_buffer =
      mem->main_workspaces->tmp_tiled_key_buffer;

  for (uint32_t bit = 0; bit < INPUT_BITS_LEN; ++bit) {
    as_radix_ciphertext_slice<Torus>(&input_bits[bit], reordered_input_buffer,
                                     bit * num_sbox_blocks,
                                     (bit + 1) * num_sbox_blocks);

    for (uint32_t byte_idx = 0; byte_idx < num_bytes_parallel; ++byte_idx) {
      CudaRadixCiphertextFFI *current_source_byte = sbox_io_bytes[byte_idx];
      CudaRadixCiphertextFFI dest_slice;
      as_radix_ciphertext_slice<Torus>(&dest_slice, &input_bits[bit],
                                       byte_idx * num_aes_inputs,
                                       (byte_idx + 1) * num_aes_inputs);
      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0), &dest_slice,
                                         &current_source_byte[bit]);
    }
  }

#define XOR(out, a, b)                                                         \
  do {                                                                         \
    aes_xor<Torus>(streams, mem, out, a, b);                                   \
  } while (0)

#define FLUSH(...)                                                             \
  do {                                                                         \
    CudaRadixCiphertextFFI *targets[] = {__VA_ARGS__};                         \
    batch_vec_flush_inplace(streams, targets,                                  \
                            sizeof(targets) / sizeof(targets[0]), mem, bsks,   \
                            ksks);                                             \
  } while (0)

#define AND(outs, lhs, rhs)                                                    \
  do {                                                                         \
    batch_vec_and_inplace(streams, outs, lhs, rhs,                             \
                          sizeof(outs) / sizeof(outs[0]), mem, bsks, ksks);    \
  } while (0)

#define ADD_ONE_FLUSH(target)                                                  \
  do {                                                                         \
    aes_scalar_add_one_flush_inplace<Torus>(streams, target, mem, bsks, ksks); \
  } while (0)

#define ADD_ONE(target)                                                        \
  do {                                                                         \
    host_add_scalar_one_inplace<Torus>(streams, target,                        \
                                       mem->params.message_modulus,            \
                                       mem->params.carry_modulus);             \
  } while (0)

  // Homomorphic S-Box Circuit Evaluation
  //

  XOR(&wires_a[14], &input_bits[3], &input_bits[5]);
  XOR(&wires_a[13], &input_bits[0], &input_bits[6]);
  XOR(&wires_a[9], &input_bits[0], &input_bits[3]);
  XOR(&wires_a[8], &input_bits[0], &input_bits[5]);
  XOR(&wires_b[0], &input_bits[1], &input_bits[2]);
  FLUSH(&wires_a[14], &wires_a[13], &wires_a[9], &wires_a[8]);
  XOR(&wires_a[1], &wires_b[0], &input_bits[7]);
  FLUSH(&wires_a[1]);
  XOR(&wires_a[12], &wires_a[13], &wires_a[14]);
  XOR(&wires_a[4], &wires_a[1], &input_bits[3]);
  XOR(&wires_a[2], &wires_a[1], &input_bits[0]);
  XOR(&wires_a[5], &wires_a[1], &input_bits[6]);
  FLUSH(&wires_a[12], &wires_a[4], &wires_a[2], &wires_a[5]);
  XOR(&wires_a[3], &wires_a[5], &wires_a[8]);
  XOR(&wires_b[1], &input_bits[4], &wires_a[12]);
  FLUSH(&wires_a[3]);
  XOR(&wires_a[15], &wires_b[1], &input_bits[5]);
  XOR(&wires_a[20], &wires_b[1], &input_bits[1]);
  FLUSH(&wires_a[15], &wires_a[20]);
  XOR(&wires_a[6], &wires_a[15], &input_bits[7]);
  XOR(&wires_a[10], &wires_a[15], &wires_b[0]);
  XOR(&wires_a[11], &wires_a[20], &wires_a[9]);
  FLUSH(&wires_a[6], &wires_a[10]);
  XOR(&wires_a[7], &input_bits[7], &wires_a[11]);
  FLUSH(&wires_a[7]);
  XOR(&wires_a[17], &wires_a[10], &wires_a[11]);
  XOR(&wires_a[19], &wires_a[10], &wires_a[8]);
  XOR(&wires_a[16], &wires_b[0], &wires_a[11]);
  FLUSH(&wires_a[17], &wires_a[19], &wires_a[16]);
  XOR(&wires_a[21], &wires_a[13], &wires_a[16]);
  XOR(&wires_a[18], &input_bits[0], &wires_a[16]);

  CudaRadixCiphertextFFI *and_outs_1[] = {
      &wires_b[2],  &wires_b[3],  &wires_b[5],  &wires_b[7], &wires_b[8],
      &wires_b[10], &wires_b[12], &wires_b[13], &wires_b[15]};
  CudaRadixCiphertextFFI *and_lhs_1[] = {
      &wires_a[15], &wires_a[3], &input_bits[7], &wires_a[13], &wires_a[1],
      &wires_a[2],  &wires_a[9], &wires_a[14],   &wires_a[8]};
  CudaRadixCiphertextFFI *and_rhs_1[] = {
      &wires_a[12], &wires_a[6],  &wires_a[4],  &wires_a[16], &wires_a[5],
      &wires_a[7],  &wires_a[11], &wires_a[17], &wires_a[10]};
  AND(and_outs_1, and_lhs_1, and_rhs_1);

  FLUSH(&wires_a[21], &wires_a[18]);
  XOR(&wires_b[4], &wires_b[3], &wires_b[2]);
  XOR(&wires_b[6], &wires_b[5], &wires_b[2]);
  XOR(&wires_b[9], &wires_b[8], &wires_b[7]);
  XOR(&wires_b[11], &wires_b[10], &wires_b[7]);
  XOR(&wires_b[14], &wires_b[13], &wires_b[12]);
  XOR(&wires_b[16], &wires_b[15], &wires_b[12]);
  XOR(&wires_b[17], &wires_b[4], &wires_b[14]);
  XOR(&wires_b[18], &wires_b[6], &wires_b[16]);
  XOR(&wires_b[19], &wires_b[9], &wires_b[14]);
  XOR(&wires_b[20], &wires_b[11], &wires_b[16]);
  XOR(&wires_b[21], &wires_b[17], &wires_a[20]);
  XOR(&wires_b[22], &wires_b[18], &wires_a[19]);
  XOR(&wires_b[23], &wires_b[19], &wires_a[21]);
  XOR(&wires_b[24], &wires_b[20], &wires_a[18]);
  FLUSH(&wires_b[21], &wires_b[23], &wires_b[24]);
  XOR(&wires_b[25], &wires_b[21], &wires_b[22]);
  FLUSH(&wires_b[25]);

  CudaRadixCiphertextFFI *and_outs_2[] = {&wires_b[26]};
  CudaRadixCiphertextFFI *and_lhs_2[] = {&wires_b[21]};
  CudaRadixCiphertextFFI *and_rhs_2[] = {&wires_b[23]};
  AND(and_outs_2, and_lhs_2, and_rhs_2);

  XOR(&wires_b[27], &wires_b[24], &wires_b[26]);
  XOR(&wires_b[30], &wires_b[23], &wires_b[24]);
  XOR(&wires_b[31], &wires_b[22], &wires_b[26]);
  FLUSH(&wires_b[27], &wires_b[30], &wires_b[31]);

  CudaRadixCiphertextFFI *and_outs_3[] = {&wires_b[28]};
  CudaRadixCiphertextFFI *and_lhs_3[] = {&wires_b[25]};
  CudaRadixCiphertextFFI *and_rhs_3[] = {&wires_b[27]};
  AND(and_outs_3, and_lhs_3, and_rhs_3);

  XOR(&wires_b[29], &wires_b[28], &wires_b[22]);

  CudaRadixCiphertextFFI *and_outs_4[] = {&wires_b[32]};
  CudaRadixCiphertextFFI *and_lhs_4[] = {&wires_b[30]};
  CudaRadixCiphertextFFI *and_rhs_4[] = {&wires_b[31]};
  AND(and_outs_4, and_lhs_4, and_rhs_4);

  FLUSH(&wires_b[29]);
  XOR(&wires_b[33], &wires_b[32], &wires_b[24]);
  FLUSH(&wires_b[33]);
  XOR(&wires_b[42], &wires_b[29], &wires_b[33]);
  FLUSH(&wires_b[42]);
  XOR(&wires_b[34], &wires_b[23], &wires_b[33]);
  XOR(&wires_b[35], &wires_b[27], &wires_b[33]);
  FLUSH(&wires_b[34], &wires_b[35]);

  CudaRadixCiphertextFFI *and_outs_5[] = {&wires_b[36]};
  CudaRadixCiphertextFFI *and_lhs_5[] = {&wires_b[24]};
  CudaRadixCiphertextFFI *and_rhs_5[] = {&wires_b[35]};
  AND(and_outs_5, and_lhs_5, and_rhs_5);

  XOR(&wires_b[37], &wires_b[36], &wires_b[34]);
  XOR(&wires_b[38], &wires_b[27], &wires_b[36]);
  FLUSH(&wires_b[38]);
  XOR(&wires_b[44], &wires_b[33], &wires_b[37]);

  CudaRadixCiphertextFFI *and_outs_6[] = {&wires_b[39]};
  CudaRadixCiphertextFFI *and_lhs_6[] = {&wires_b[38]};
  CudaRadixCiphertextFFI *and_rhs_6[] = {&wires_b[29]};
  AND(and_outs_6, and_lhs_6, and_rhs_6);

  XOR(&wires_b[40], &wires_b[25], &wires_b[39]);
  XOR(&wires_b[41], &wires_b[40], &wires_b[37]);
  XOR(&wires_b[43], &wires_b[29], &wires_b[40]);
  FLUSH(&wires_b[41]);
  XOR(&wires_b[45], &wires_b[42], &wires_b[41]);
  FLUSH(&wires_b[45]);

  CudaRadixCiphertextFFI *and_outs_7[] = {
      &wires_c[0],  &wires_c[1],  &wires_c[2],  &wires_c[3],  &wires_c[4],
      &wires_c[5],  &wires_c[6],  &wires_c[7],  &wires_c[8],  &wires_c[9],
      &wires_c[10], &wires_c[11], &wires_c[12], &wires_c[13], &wires_c[14],
      &wires_c[15], &wires_c[16], &wires_c[17]};
  CudaRadixCiphertextFFI *and_lhs_7[] = {
      &wires_a[15], &wires_a[6],  &wires_b[33], &wires_a[16], &wires_a[1],
      &wires_b[29], &wires_b[42], &wires_a[17], &wires_a[10], &wires_a[12],
      &wires_a[3],  &wires_b[33], &wires_a[13], &wires_a[5],  &wires_b[29],
      &wires_b[42], &wires_b[45], &wires_b[41]};
  CudaRadixCiphertextFFI *and_rhs_7[] = {
      &wires_b[44], &wires_b[37], &input_bits[7], &wires_b[43], &wires_b[40],
      &wires_a[7],  &wires_a[11], &wires_b[45],   &wires_b[41], &wires_b[44],
      &wires_b[37], &wires_a[4],  &wires_b[43],   &wires_b[40], &wires_a[2],
      &wires_a[9],  &wires_a[14], &wires_a[8]};
  AND(and_outs_7, and_lhs_7, and_rhs_7);

  XOR(&wires_b[46], &wires_c[15], &wires_c[16]);
  XOR(&wires_b[47], &wires_c[10], &wires_c[11]);
  XOR(&wires_b[48], &wires_c[5], &wires_c[13]);
  XOR(&wires_b[49], &wires_c[9], &wires_c[10]);
  XOR(&wires_b[50], &wires_c[2], &wires_c[12]);
  XOR(&wires_b[51], &wires_c[2], &wires_c[5]);
  XOR(&wires_b[52], &wires_c[7], &wires_c[8]);
  XOR(&wires_b[53], &wires_c[0], &wires_c[3]);
  XOR(&wires_b[54], &wires_c[6], &wires_c[7]);
  XOR(&wires_b[55], &wires_c[16], &wires_c[17]);
  XOR(&wires_b[56], &wires_c[12], &wires_b[48]);
  XOR(&wires_b[57], &wires_b[50], &wires_b[53]);
  XOR(&wires_b[58], &wires_c[4], &wires_b[46]);
  XOR(&wires_b[59], &wires_c[3], &wires_b[54]);
  XOR(&wires_b[60], &wires_b[46], &wires_b[57]);
  XOR(&wires_b[61], &wires_c[14], &wires_b[57]);
  XOR(&wires_b[62], &wires_b[52], &wires_b[58]);
  XOR(&wires_b[63], &wires_b[49], &wires_b[58]);
  XOR(&wires_b[64], &wires_c[4], &wires_b[59]);
  FLUSH(&wires_b[61], &wires_b[63], &wires_b[64]);
  XOR(&wires_b[65], &wires_b[61], &wires_b[62]);
  FLUSH(&wires_b[65]);
  XOR(&wires_b[66], &wires_c[1], &wires_b[63]);
  FLUSH(&wires_b[66]);

  // Final Output Combination
  //

  CudaRadixCiphertextFFI output_bits[OUTPUT_BITS_LEN];
  for (uint32_t i = 0; i < OUTPUT_BITS_LEN; i++)
    as_radix_ciphertext_slice<Torus>(
        &output_bits[i], mem->main_workspaces->sbox_internal_workspace,
        i * num_sbox_blocks, (i + 1) * num_sbox_blocks);

  CudaRadixCiphertextFFI single_bit_buffer;
  as_radix_ciphertext_slice<Torus>(
      &single_bit_buffer, mem->main_workspaces->sbox_internal_workspace,
      (OUTPUT_BITS_LEN * num_sbox_blocks),
      (OUTPUT_BITS_LEN * num_sbox_blocks) + num_sbox_blocks);

  XOR(&output_bits[0], &wires_b[59], &wires_b[63]);
  XOR(&wires_b[67], &wires_b[64], &wires_b[65]);
  XOR(&output_bits[3], &wires_b[53], &wires_b[66]);
  XOR(&output_bits[4], &wires_b[51], &wires_b[66]);
  XOR(&output_bits[5], &wires_b[47], &wires_b[65]);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &single_bit_buffer, &wires_b[62]);

  ADD_ONE_FLUSH(&single_bit_buffer);
  XOR(&output_bits[6], &wires_b[56], &single_bit_buffer);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &single_bit_buffer, &wires_b[60]);

  ADD_ONE_FLUSH(&single_bit_buffer);
  XOR(&output_bits[7], &wires_b[48], &single_bit_buffer);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &single_bit_buffer, &output_bits[3]);

  ADD_ONE(&single_bit_buffer);
  XOR(&output_bits[1], &wires_b[64], &single_bit_buffer);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &single_bit_buffer, &wires_b[67]);

  ADD_ONE_FLUSH(&single_bit_buffer);
  XOR(&output_bits[2], &wires_b[55], &single_bit_buffer);

  FLUSH(&output_bits[0], &output_bits[1], &output_bits[2], &output_bits[3],
        &output_bits[4], &output_bits[5], &output_bits[6], &output_bits[7]);

  // Output Reordering (Scatter)
  //

  for (uint32_t bit = 0; bit < OUTPUT_BITS_LEN; ++bit) {
    for (uint32_t byte_idx = 0; byte_idx < num_bytes_parallel; ++byte_idx) {
      CudaRadixCiphertextFFI *current_dest_byte = sbox_io_bytes[byte_idx];
      CudaRadixCiphertextFFI src_slice;
      as_radix_ciphertext_slice<Torus>(&src_slice, &output_bits[bit],
                                       byte_idx * num_aes_inputs,
                                       (byte_idx + 1) * num_aes_inputs);
      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0),
                                         &current_dest_byte[bit], &src_slice);
    }
  }

#undef XOR
#undef FLUSH
#undef AND
#undef ADD_ONE_FLUSH
}

/**
 * Implements the ShiftRows step of AES on bitsliced data.
 *
 * Before ShiftRows (Input State):
 * +----+----+----+----+
 * | A  | B  | C  | D  |
 * +----+----+----+----+
 * | E  | F  | G  | H  |
 * +----+----+----+----+
 * | I  | J  | K  | L  |
 * +----+----+----+----+
 * | M  | N  | O  | P  |
 * +----+----+----+----+
 *
 * After ShiftRows (Output State):
 * +----+----+----+----+
 * | A  | B  | C  | D  |  <- No shift
 * +----+----+----+----+
 * | F  | G  | H  | E  |  <- 1 byte left shift
 * +----+----+----+----+
 * | K  | L  | I  | J  |  <- 2 bytes left shift
 * +----+----+----+----+
 * | P  | M  | N  | O  |  <- 3 bytes left shift
 * +----+----+----+----+
 *
 *
 */
template <typename Torus>
__host__ void vectorized_shift_rows(CudaStreams streams,
                                    CudaRadixCiphertextFFI *state_bitsliced,
                                    uint32_t num_aes_inputs,
                                    int_aes_encrypt_buffer<Torus> *mem) {
  constexpr uint32_t NUM_BYTES = 16;
  constexpr uint32_t LEN_BYTE = 8;
  constexpr uint32_t NUM_BITS = NUM_BYTES * LEN_BYTE;

  CudaRadixCiphertextFFI tmp_full_state_bitsliced_slice;
  as_radix_ciphertext_slice<Torus>(
      &tmp_full_state_bitsliced_slice,
      mem->main_workspaces->sbox_internal_workspace, 0,
      state_bitsliced->num_radix_blocks);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &tmp_full_state_bitsliced_slice,
                                     state_bitsliced);

  CudaRadixCiphertextFFI s_bits[NUM_BITS];
  for (int i = 0; i < NUM_BITS; i++) {
    as_radix_ciphertext_slice<Torus>(&s_bits[i], state_bitsliced,
                                     i * num_aes_inputs,
                                     (i + 1) * num_aes_inputs);
  }

  CudaRadixCiphertextFFI tmp_s_bits_slices[NUM_BITS];
  for (int i = 0; i < NUM_BITS; i++) {
    as_radix_ciphertext_slice<Torus>(
        &tmp_s_bits_slices[i], &tmp_full_state_bitsliced_slice,
        i * num_aes_inputs, (i + 1) * num_aes_inputs);
  }

  const int shift_rows_map[] = {0, 5,  10, 15, 4,  9, 14, 3,
                                8, 13, 2,  7,  12, 1, 6,  11};

  for (int i = 0; i < NUM_BYTES; i++) {
    for (int bit = 0; bit < LEN_BYTE; bit++) {
      CudaRadixCiphertextFFI *dest_slice = &s_bits[i * LEN_BYTE + bit];
      CudaRadixCiphertextFFI *src_slice =
          &tmp_s_bits_slices[shift_rows_map[i] * LEN_BYTE + bit];
      copy_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), dest_slice, src_slice);
    }
  }
}

/**
 * Helper for MixColumns. Homomorphically multiplies an 8-bit byte by 2.
 *
 */
template <typename Torus>
__host__ void vectorized_mul_by_2(CudaStreams streams,
                                  CudaRadixCiphertextFFI *res_byte,
                                  CudaRadixCiphertextFFI *in_byte,
                                  int_aes_encrypt_buffer<Torus> *mem) {

  constexpr uint32_t LEN_BYTE = 8;

  CudaRadixCiphertextFFI *msb = &in_byte[0];

  for (int i = 0; i < LEN_BYTE - 1; ++i) {
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &res_byte[i], &in_byte[i + 1]);
  }

  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &res_byte[LEN_BYTE - 1], 0,
      res_byte[LEN_BYTE - 1].num_radix_blocks);

  const int indices_to_xor[] = {3, 4, 6, 7};
  for (int index : indices_to_xor) {
    aes_xor<Torus>(streams, mem, &res_byte[index], &res_byte[index], msb);
  }
}

/**
 * Implements the MixColumns step of AES. It performs a matrix multiplication
 * on each column of the AES state.
 *
 * [ s'_0 ]   [ 02 03 01 01 ]   [ s_0 ]
 * [ s'_1 ] = [ 01 02 03 01 ] * [ s_1 ]
 * [ s'_2 ]   [ 01 01 02 03 ]   [ s_2 ]
 * [ s'_3 ]   [ 03 01 01 02 ]   [ s_3 ]
 *
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_mix_columns(CudaStreams streams,
                                     CudaRadixCiphertextFFI *s_bits,
                                     uint32_t num_aes_inputs,
                                     int_aes_encrypt_buffer<Torus> *mem,
                                     void *const *bsks, KSTorus *const *ksks) {

  constexpr uint32_t BITS_PER_BYTE = 8;
  constexpr uint32_t BYTES_PER_COLUMN = 4;
  constexpr uint32_t NUM_COLUMNS = 4;
  constexpr uint32_t BITS_PER_COLUMN = BYTES_PER_COLUMN * BITS_PER_BYTE;

  for (uint32_t col = 0; col < NUM_COLUMNS; ++col) {
    CudaRadixCiphertextFFI *col_copy_buffer =
        mem->round_workspaces->mix_columns_col_copy_buffer;
    for (uint32_t i = 0; i < BITS_PER_COLUMN; ++i) {
      CudaRadixCiphertextFFI dest_slice, src_slice;
      as_radix_ciphertext_slice<Torus>(&dest_slice, col_copy_buffer,
                                       i * num_aes_inputs,
                                       (i + 1) * num_aes_inputs);
      as_radix_ciphertext_slice<Torus>(
          &src_slice, s_bits, (col * BITS_PER_COLUMN + i) * num_aes_inputs,
          (col * BITS_PER_COLUMN + i + 1) * num_aes_inputs);
      copy_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &dest_slice, &src_slice);
    }

    CudaRadixCiphertextFFI b_orig[BYTES_PER_COLUMN][BITS_PER_BYTE];
    for (uint32_t i = 0; i < BYTES_PER_COLUMN; ++i) {
      for (uint32_t j = 0; j < BITS_PER_BYTE; j++) {
        as_radix_ciphertext_slice<Torus>(
            &b_orig[i][j], col_copy_buffer,
            (i * BITS_PER_BYTE + j) * num_aes_inputs,
            (i * BITS_PER_BYTE + j + 1) * num_aes_inputs);
      }
    }

    CudaRadixCiphertextFFI *mul_workspace =
        mem->round_workspaces->mix_columns_mul_workspace_buffer;
    CudaRadixCiphertextFFI b_mul2[BYTES_PER_COLUMN][BITS_PER_BYTE];
    CudaRadixCiphertextFFI b_mul2_tmp_buffers[BYTES_PER_COLUMN];
    for (uint32_t i = 0; i < BYTES_PER_COLUMN; i++) {
      as_radix_ciphertext_slice<Torus>(&b_mul2_tmp_buffers[i], mul_workspace,
                                       (i * BITS_PER_BYTE) * num_aes_inputs,
                                       (i * BITS_PER_BYTE + BITS_PER_BYTE) *
                                           num_aes_inputs);
      for (uint32_t j = 0; j < BITS_PER_BYTE; j++) {
        as_radix_ciphertext_slice<Torus>(&b_mul2[i][j], &b_mul2_tmp_buffers[i],
                                         j * num_aes_inputs,
                                         (j + 1) * num_aes_inputs);
      }
    }

    for (uint32_t i = 0; i < BYTES_PER_COLUMN; ++i) {
      vectorized_mul_by_2<Torus>(streams, b_mul2[i], b_orig[i], mem);
    }
    aes_flush_inplace<Torus>(streams, mul_workspace, mem, bsks, ksks);

    CudaRadixCiphertextFFI b0_mul2_copy_buffer;
    as_radix_ciphertext_slice<Torus>(
        &b0_mul2_copy_buffer, mul_workspace,
        (BYTES_PER_COLUMN * BITS_PER_BYTE) * num_aes_inputs,
        ((BYTES_PER_COLUMN * BITS_PER_BYTE) + BITS_PER_BYTE) * num_aes_inputs);
    CudaRadixCiphertextFFI b0_mul2_copy[BITS_PER_BYTE];
    for (uint32_t j = 0; j < BITS_PER_BYTE; j++) {
      as_radix_ciphertext_slice<Torus>(&b0_mul2_copy[j], &b0_mul2_copy_buffer,
                                       j * num_aes_inputs,
                                       (j + 1) * num_aes_inputs);
      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0), &b0_mul2_copy[j],
                                         &b_mul2[0][j]);
    }

    for (uint32_t bit = 0; bit < BITS_PER_BYTE; bit++) {
      CudaRadixCiphertextFFI *dest_bit_0 =
          &s_bits[(col * BYTES_PER_COLUMN + 0) * BITS_PER_BYTE + bit];
      CudaRadixCiphertextFFI *dest_bit_1 =
          &s_bits[(col * BYTES_PER_COLUMN + 1) * BITS_PER_BYTE + bit];
      CudaRadixCiphertextFFI *dest_bit_2 =
          &s_bits[(col * BYTES_PER_COLUMN + 2) * BITS_PER_BYTE + bit];
      CudaRadixCiphertextFFI *dest_bit_3 =
          &s_bits[(col * BYTES_PER_COLUMN + 3) * BITS_PER_BYTE + bit];

#define VEC_XOR_INPLACE(DEST, SRC) aes_xor<Torus>(streams, mem, DEST, DEST, SRC)

      copy_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), dest_bit_0, &b_mul2[0][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_mul2[1][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_orig[1][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_orig[2][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_orig[3][bit]);

      copy_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), dest_bit_1, &b_orig[0][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_mul2[1][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_mul2[2][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_orig[2][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_orig[3][bit]);

      copy_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), dest_bit_2, &b_orig[0][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_orig[1][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_mul2[2][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_orig[3][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_mul2[3][bit]);

      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0), dest_bit_3,
                                         &b0_mul2_copy[bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_orig[0][bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_orig[1][bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_orig[2][bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_mul2[3][bit]);
#undef VEC_XOR_INPLACE
    }
  }
}

/**
 * The main AES encryption function. It orchestrates the full 10-round AES-128
 * encryption process on the bitsliced state.
 *
 * The process is broken down into three phases:
 *
 * 1. Initial Round (Round 0):
 * - AddRoundKey, which is a XOR
 *
 * 2. Main Rounds (Rounds 1-9):
 * This sequence is repeated 9 times.
 * - SubBytes
 * - ShiftRows
 * - MixColumns
 * - AddRoundKey
 *
 * 3. Final Round (Round 10):
 * - SubBytes
 * - ShiftRows
 * - AddRoundKey
 *
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_aes_encrypt_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *all_states_bitsliced,
    CudaRadixCiphertextFFI const *round_keys, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {

  constexpr uint32_t BITS_PER_BYTE = 8;
  constexpr uint32_t STATE_BYTES = 16;
  constexpr uint32_t STATE_BITS = STATE_BYTES * BITS_PER_BYTE;
  constexpr uint32_t ROUNDS = 10;

  CudaRadixCiphertextFFI *jit_transposed_key =
      mem->main_workspaces->initial_states_and_jit_key_workspace;

  CudaRadixCiphertextFFI round_0_key_slice;
  as_radix_ciphertext_slice<Torus>(
      &round_0_key_slice, (CudaRadixCiphertextFFI *)round_keys, 0, STATE_BITS);
  for (uint32_t block = 0; block < num_aes_inputs; ++block) {
    CudaRadixCiphertextFFI tile_slice;
    as_radix_ciphertext_slice<Torus>(
        &tile_slice, mem->main_workspaces->tmp_tiled_key_buffer,
        block * STATE_BITS, (block + 1) * STATE_BITS);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &tile_slice, &round_0_key_slice);
  }
  transpose_blocks_to_bitsliced<Torus>(
      streams.stream(0), streams.gpu_index(0), jit_transposed_key,
      mem->main_workspaces->tmp_tiled_key_buffer, num_aes_inputs, STATE_BITS);

  aes_xor<Torus>(streams, mem, all_states_bitsliced, all_states_bitsliced,
                 jit_transposed_key);

  aes_flush_inplace<Torus>(streams, all_states_bitsliced, mem, bsks, ksks);

  for (uint32_t round = 1; round <= ROUNDS; ++round) {
    CudaRadixCiphertextFFI s_bits[STATE_BITS];
    for (uint32_t i = 0; i < STATE_BITS; i++) {
      as_radix_ciphertext_slice<Torus>(&s_bits[i], all_states_bitsliced,
                                       i * num_aes_inputs,
                                       (i + 1) * num_aes_inputs);
    }

    uint32_t sbox_parallelism = mem->sbox_parallel_instances;
    switch (sbox_parallelism) {
    case 1:
      for (uint32_t i = 0; i < STATE_BYTES; ++i) {
        CudaRadixCiphertextFFI *sbox_inputs[] = {&s_bits[i * BITS_PER_BYTE]};
        vectorized_sbox_n_bytes<Torus>(streams, sbox_inputs, 1, num_aes_inputs,
                                       mem, bsks, ksks);
      }
      break;
    case 2:
      for (uint32_t i = 0; i < STATE_BYTES; i += 2) {
        CudaRadixCiphertextFFI *sbox_inputs[] = {
            &s_bits[i * BITS_PER_BYTE], &s_bits[(i + 1) * BITS_PER_BYTE]};
        vectorized_sbox_n_bytes<Torus>(streams, sbox_inputs, 2, num_aes_inputs,
                                       mem, bsks, ksks);
      }
      break;
    case 4:
      for (uint32_t i = 0; i < STATE_BYTES; i += 4) {
        CudaRadixCiphertextFFI *sbox_inputs[] = {
            &s_bits[i * BITS_PER_BYTE], &s_bits[(i + 1) * BITS_PER_BYTE],
            &s_bits[(i + 2) * BITS_PER_BYTE], &s_bits[(i + 3) * BITS_PER_BYTE]};
        vectorized_sbox_n_bytes<Torus>(streams, sbox_inputs, 4, num_aes_inputs,
                                       mem, bsks, ksks);
      }
      break;
    case 8:
      for (uint32_t i = 0; i < STATE_BYTES; i += 8) {
        CudaRadixCiphertextFFI *sbox_inputs[] = {
            &s_bits[i * BITS_PER_BYTE],       &s_bits[(i + 1) * BITS_PER_BYTE],
            &s_bits[(i + 2) * BITS_PER_BYTE], &s_bits[(i + 3) * BITS_PER_BYTE],
            &s_bits[(i + 4) * BITS_PER_BYTE], &s_bits[(i + 5) * BITS_PER_BYTE],
            &s_bits[(i + 6) * BITS_PER_BYTE], &s_bits[(i + 7) * BITS_PER_BYTE]};
        vectorized_sbox_n_bytes<Torus>(streams, sbox_inputs, 8, num_aes_inputs,
                                       mem, bsks, ksks);
      }
      break;
    case 16: {
      CudaRadixCiphertextFFI *sbox_inputs[] = {
          &s_bits[0 * BITS_PER_BYTE],  &s_bits[1 * BITS_PER_BYTE],
          &s_bits[2 * BITS_PER_BYTE],  &s_bits[3 * BITS_PER_BYTE],
          &s_bits[4 * BITS_PER_BYTE],  &s_bits[5 * BITS_PER_BYTE],
          &s_bits[6 * BITS_PER_BYTE],  &s_bits[7 * BITS_PER_BYTE],
          &s_bits[8 * BITS_PER_BYTE],  &s_bits[9 * BITS_PER_BYTE],
          &s_bits[10 * BITS_PER_BYTE], &s_bits[11 * BITS_PER_BYTE],
          &s_bits[12 * BITS_PER_BYTE], &s_bits[13 * BITS_PER_BYTE],
          &s_bits[14 * BITS_PER_BYTE], &s_bits[15 * BITS_PER_BYTE]};
      vectorized_sbox_n_bytes<Torus>(streams, sbox_inputs, 16, num_aes_inputs,
                                     mem, bsks, ksks);
    } break;
    default:
      PANIC("Unsupported S-Box parallelism level selected: %u",
            sbox_parallelism);
    }

    vectorized_shift_rows<Torus>(streams, all_states_bitsliced, num_aes_inputs,
                                 mem);

    if (round != ROUNDS) {
      vectorized_mix_columns<Torus>(streams, s_bits, num_aes_inputs, mem, bsks,
                                    ksks);
      aes_flush_inplace<Torus>(streams, all_states_bitsliced, mem, bsks, ksks);
    }

    CudaRadixCiphertextFFI round_key_slice;
    as_radix_ciphertext_slice<Torus>(
        &round_key_slice, (CudaRadixCiphertextFFI *)round_keys,
        round * STATE_BITS, (round + 1) * STATE_BITS);
    for (uint32_t block = 0; block < num_aes_inputs; ++block) {
      CudaRadixCiphertextFFI tile_slice;
      as_radix_ciphertext_slice<Torus>(
          &tile_slice, mem->main_workspaces->tmp_tiled_key_buffer,
          block * STATE_BITS, (block + 1) * STATE_BITS);
      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0), &tile_slice,
                                         &round_key_slice);
    }
    transpose_blocks_to_bitsliced<Torus>(
        streams.stream(0), streams.gpu_index(0), jit_transposed_key,
        mem->main_workspaces->tmp_tiled_key_buffer, num_aes_inputs, STATE_BITS);

    aes_xor<Torus>(streams, mem, all_states_bitsliced, all_states_bitsliced,
                   jit_transposed_key);

    aes_flush_inplace<Torus>(streams, all_states_bitsliced, mem, bsks, ksks);
  }
}

/**
 * Performs the homomorphic addition of the plaintext counter to the encrypted
 * IV.
 *
 * It functions as a 128-bit ripple-carry adder. For each bit $i$ from LSB to
 * MSB, it computes the sum $S_i$ and the output carry $C_i$ based on the state
 * bit ($IV_i$), the counter bit ($Counter_i$), and the incoming carry
 * ($C_{i-1}$). The logical formulas are:
 *
 * $S_i = IV_i + Counter_i + C_{i-1}$
 * $C_i = (IV_i * Counter_i) + (IV_i * C_{i-1}) + (Counter_i * C_{i-1})$
 *
 * The "transposed_states" buffer is updated in-place with the sum bits $S_i$.
 *
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_aes_full_adder_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *transposed_states,
    const Torus *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {

  constexpr uint32_t NUM_BITS = 128;

  // --- Initialization ---
  CudaRadixCiphertextFFI *carry_vec =
      mem->counter_workspaces->vec_tmp_carry_buffer;
  CudaRadixCiphertextFFI *trivial_b_bits_vec =
      mem->counter_workspaces->vec_trivial_b_bits_buffer;
  CudaRadixCiphertextFFI *sum_plus_carry_vec =
      mem->counter_workspaces->vec_tmp_sum_buffer;

  // Initialize the carry vector to 0.
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), carry_vec, 0, num_aes_inputs);

  // Main loop iterating over the 128 bits, from LSB (i=0) to MSB (i=127).
  // Each iteration implements one stage of the full adder.
  for (uint32_t i = 0; i < NUM_BITS; ++i) {
    // The index in the state buffer is reversed (127-i),
    // because of the LSB -> MSB logic.
    const uint32_t state_bit_index = NUM_BITS - 1 - i;

    // --- Step 1: Prepare the adder inputs ---

    // a_i_vec: The first operand (ciphertext). This is the i-th bit of the IV.
    CudaRadixCiphertextFFI a_i_vec;
    as_radix_ciphertext_slice<Torus>(&a_i_vec, transposed_states,
                                     state_bit_index * num_aes_inputs,
                                     (state_bit_index + 1) * num_aes_inputs);

    // Prepare the second operand (plaintext, then trivially encrypted).
    // This is the i-th bit of the counter.
    for (uint32_t block = 0; block < num_aes_inputs; ++block) {
      mem->counter_workspaces->h_counter_bits_buffer[block] =
          counter_bits_le_all_blocks[block * NUM_BITS + i];
    }
    cuda_memcpy_async_to_gpu(mem->counter_workspaces->d_counter_bits_buffer,
                             mem->counter_workspaces->h_counter_bits_buffer,
                             safe_mul_sizeof<Torus>(num_aes_inputs),
                             streams.stream(0), streams.gpu_index(0));
    set_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), trivial_b_bits_vec,
        mem->counter_workspaces->d_counter_bits_buffer,
        mem->counter_workspaces->h_counter_bits_buffer, num_aes_inputs,
        mem->params.message_modulus, mem->params.carry_modulus);

    // carry_vec: The third operand (ciphertext).
    // This is the carry from the previous stage (C_{i-1}).

    // --- Step 2: Compute the sum and carry ---

    // Compute the temporary sum of the first two operands: IV_i + Counter_i
    CudaRadixCiphertextFFI tmp_sum_vec;
    as_radix_ciphertext_slice<Torus>(&tmp_sum_vec,
                                     mem->round_workspaces->vec_tmp_bit_buffer,
                                     0, num_aes_inputs);
    aes_xor<Torus>(streams, mem, &tmp_sum_vec, &a_i_vec, trivial_b_bits_vec);

    // Compute the sum of all three operands: (IV_i + Counter_i) + C_{i-1}
    aes_xor<Torus>(streams, mem, sum_plus_carry_vec, &tmp_sum_vec, carry_vec);

    // Compute the new carry (C_i) for the next iteration.
    // The carry_lut applies the function f(x) = (x >> 1) & 1, which
    // extracts the carry bit from the previous sum. The result is stored
    // in carry_vec for the next iteration (i+1).
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, carry_vec, sum_plus_carry_vec, bsks, ksks,
        mem->luts->carry_lut, num_aes_inputs);

    // Compute the final sum bit (S_i).
    // The flush_lut applies the function f(x) = x & 1, which extracts
    // the least significant bit of the sum. The result is written
    // directly into the state buffer, updating the IV in-place.
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &a_i_vec, sum_plus_carry_vec, bsks, ksks, mem->luts->flush_lut,
        num_aes_inputs);
  }
}

/**
 * Top-level function to perform a full AES-128-CTR encryption homomorphically.
 *
 * +----------+     +-------------------+
 * |   IV_CT  |     | Plaintext Counter |
 * +----------+     +-------------------+
 * |                  |
 * V                  V
 * +---------------------------------+
 * |   Homomorphic Full Adder        |
 * |   (IV_CT + Counter)             |
 * +---------------------------------+
 * |
 * V
 * +---------------------------------+
 * |   Homomorphic AES Encryption    | -> Final Output Ciphertext
 * |   (10 Rounds)                   |
 * +---------------------------------+
 *
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_aes_ctr_encrypt(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const Torus *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {

  constexpr uint32_t NUM_BITS = 128;

  CudaRadixCiphertextFFI *initial_states =
      mem->main_workspaces->initial_states_and_jit_key_workspace;

  for (uint32_t block = 0; block < num_aes_inputs; ++block) {
    CudaRadixCiphertextFFI output_slice;
    as_radix_ciphertext_slice<Torus>(&output_slice, initial_states,
                                     block * NUM_BITS, (block + 1) * NUM_BITS);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &output_slice, iv);
  }

  CudaRadixCiphertextFFI *transposed_states =
      mem->main_workspaces->main_bitsliced_states_buffer;
  transpose_blocks_to_bitsliced<Torus>(streams.stream(0), streams.gpu_index(0),
                                       transposed_states, initial_states,
                                       num_aes_inputs, NUM_BITS);

  vectorized_aes_full_adder_inplace<Torus>(streams, transposed_states,
                                           counter_bits_le_all_blocks,
                                           num_aes_inputs, mem, bsks, ksks);

  vectorized_aes_encrypt_inplace<Torus>(streams, transposed_states, round_keys,
                                        num_aes_inputs, mem, bsks, ksks);

  transpose_bitsliced_to_blocks<Torus>(streams.stream(0), streams.gpu_index(0),
                                       output, transposed_states,
                                       num_aes_inputs, NUM_BITS);
}

template <typename Torus>
uint64_t scratch_cuda_integer_key_expansion(
    CudaStreams streams, int_key_expansion_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_key_expansion_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/**
 * Homomorphically performs the AES-128 key expansion schedule on the GPU.
 *
 * This function expands an encrypted 128-bit key into 44 words (11 round keys).
 * The generation logic for a new word `w_i` depends on its position:
 * - If (i % 4 == 0): w_i = w_{i-4} + SubWord(RotWord(w_{i-1})) + Rcon[i/4]
 * - If (i % 4 != 0): w_i = w_{i-4} + w_{i-1}
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_key_expansion(CudaStreams streams,
                                         CudaRadixCiphertextFFI *expanded_keys,
                                         CudaRadixCiphertextFFI const *key,
                                         int_key_expansion_buffer<Torus> *mem,
                                         void *const *bsks,
                                         KSTorus *const *ksks) {

  constexpr uint32_t BITS_PER_WORD = 32;
  constexpr uint32_t BITS_PER_BYTE = 8;
  constexpr uint32_t BYTES_PER_WORD = 4;
  constexpr uint32_t TOTAL_WORDS = 44;
  constexpr uint32_t KEY_WORDS = 4;

  const Torus rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10,
                        0x20, 0x40, 0x80, 0x1b, 0x36};

  CudaRadixCiphertextFFI *words = mem->words_buffer;

  CudaRadixCiphertextFFI initial_key_dest_slice;
  as_radix_ciphertext_slice<Torus>(&initial_key_dest_slice, words, 0,
                                   KEY_WORDS * BITS_PER_WORD);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &initial_key_dest_slice, key);

  for (uint32_t w = KEY_WORDS; w < TOTAL_WORDS; ++w) {
    CudaRadixCiphertextFFI tmp_word_buffer, tmp_far, tmp_near;

    as_radix_ciphertext_slice<Torus>(&tmp_word_buffer, mem->tmp_word_buffer, 0,
                                     BITS_PER_WORD);
    as_radix_ciphertext_slice<Torus>(&tmp_far, words, (w - 4) * BITS_PER_WORD,
                                     (w - 3) * BITS_PER_WORD);
    as_radix_ciphertext_slice<Torus>(&tmp_near, words, (w - 1) * BITS_PER_WORD,
                                     w * BITS_PER_WORD);

    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &tmp_word_buffer, &tmp_near);

    if (w % KEY_WORDS == 0) {
      CudaRadixCiphertextFFI rotated_word_buffer;
      as_radix_ciphertext_slice<Torus>(
          &rotated_word_buffer, mem->tmp_rotated_word_buffer, 0, BITS_PER_WORD);

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &rotated_word_buffer, 0,
          BITS_PER_WORD - BITS_PER_BYTE, &tmp_word_buffer, BITS_PER_BYTE,
          BITS_PER_WORD);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &rotated_word_buffer,
          BITS_PER_WORD - BITS_PER_BYTE, BITS_PER_WORD, &tmp_word_buffer, 0,
          BITS_PER_BYTE);

      CudaRadixCiphertextFFI bit_slices[BITS_PER_WORD];
      for (uint32_t i = 0; i < BITS_PER_WORD; ++i) {
        as_radix_ciphertext_slice<Torus>(&bit_slices[i], &rotated_word_buffer,
                                         i, i + 1);
      }

      CudaRadixCiphertextFFI *sbox_byte_pointers[BYTES_PER_WORD];
      for (uint32_t i = 0; i < BYTES_PER_WORD; ++i) {
        sbox_byte_pointers[i] = &bit_slices[i * BITS_PER_BYTE];
      }

      vectorized_sbox_n_bytes<Torus>(streams, sbox_byte_pointers,
                                     BYTES_PER_WORD, 1, mem->aes_encrypt_buffer,
                                     bsks, ksks);

      Torus rcon_val = rcon[w / KEY_WORDS - 1];
      for (uint32_t bit = 0; bit < BITS_PER_BYTE; ++bit) {
        if ((rcon_val >> (7 - bit)) & 1) {
          CudaRadixCiphertextFFI first_byte_bit_slice;
          as_radix_ciphertext_slice<Torus>(&first_byte_bit_slice,
                                           &rotated_word_buffer, bit, bit + 1);
          host_add_scalar_one_inplace<Torus>(streams, &first_byte_bit_slice,
                                             mem->params.message_modulus,
                                             mem->params.carry_modulus);
        }
      }

      aes_flush_inplace(streams, &rotated_word_buffer, mem->aes_encrypt_buffer,
                        bsks, ksks);

      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0), &tmp_word_buffer,
                                         &rotated_word_buffer);
    }

    aes_xor(streams, mem->aes_encrypt_buffer, &tmp_word_buffer, &tmp_far,
            &tmp_word_buffer);
    aes_flush_inplace(streams, &tmp_word_buffer, mem->aes_encrypt_buffer, bsks,
                      ksks);

    CudaRadixCiphertextFFI dest_word;
    as_radix_ciphertext_slice<Torus>(&dest_word, words, w * BITS_PER_WORD,
                                     (w + 1) * BITS_PER_WORD);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_word, &tmp_word_buffer);
  }

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     expanded_keys, words);
}

#endif
