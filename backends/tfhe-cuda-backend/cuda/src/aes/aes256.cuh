#pragma once

#include "../../include/aes/aes_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../linearalgebra/addition.cuh"
#include "aes.cuh"

/**
 * The main AES encryption function. It orchestrates the full 14-round AES-256
 * encryption process on the bitsliced state.
 *
 * The process is broken down into three phases:
 *
 * 1. Initial Round (Round 0):
 * - AddRoundKey, which is a XOR
 *
 * 2. Main Rounds (Rounds 1-13):
 * This sequence is repeated 13 times.
 * - SubBytes
 * - ShiftRows
 * - MixColumns
 * - AddRoundKey
 *
 * 3. Final Round (Round 14):
 * - SubBytes
 * - ShiftRows
 * - AddRoundKey
 *
 */
template <typename Torus>
__host__ void vectorized_aes_256_encrypt_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *all_states_bitsliced,
    CudaRadixCiphertextFFI const *round_keys, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks) {

  constexpr uint32_t BITS_PER_BYTE = 8;
  constexpr uint32_t STATE_BYTES = 16;
  constexpr uint32_t STATE_BITS = STATE_BYTES * BITS_PER_BYTE;
  constexpr uint32_t ROUNDS = 14;

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
 * Top-level function to perform a full AES-256-CTR encryption homomorphically.
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
 * |   (14 Rounds)                   |
 * +---------------------------------+
 *
 */
template <typename Torus>
__host__ void host_integer_aes_ctr_256_encrypt(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const Torus *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks) {

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

  vectorized_aes_256_encrypt_inplace<Torus>(
      streams, transposed_states, round_keys, num_aes_inputs, mem, bsks, ksks);

  transpose_bitsliced_to_blocks<Torus>(streams.stream(0), streams.gpu_index(0),
                                       output, transposed_states,
                                       num_aes_inputs, NUM_BITS);
}

template <typename Torus>
uint64_t scratch_cuda_integer_key_expansion_256(
    CudaStreams streams, int_key_expansion_256_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_key_expansion_256_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/**
 * Homomorphically performs the AES-256 key expansion schedule on the GPU.
 *
 * This function expands an encrypted 256-bit key into 60 words (15 round keys).
 * The generation logic for a new word `w_i` depends on its position (with
 * KEY_WORDS = 8):
 * - If (i % 8 == 0): w_i = w_{i-8} + SubWord(RotWord(w_{i-1})) + Rcon[i/8]
 * - If (i % 8 == 4): w_i = w_{i-8} + SubWord(w_{i-1})
 * - Otherwise:       w_i = w_{i-8} + w_{i-1}
 */
template <typename Torus>
__host__ void host_integer_key_expansion_256(
    CudaStreams streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key, int_key_expansion_256_buffer<Torus> *mem,
    void *const *bsks, Torus *const *ksks) {

  constexpr uint32_t BITS_PER_WORD = 32;
  constexpr uint32_t BITS_PER_BYTE = 8;
  constexpr uint32_t BYTES_PER_WORD = 4;
  constexpr uint32_t TOTAL_WORDS = 60;
  constexpr uint32_t KEY_WORDS = 8;

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
    as_radix_ciphertext_slice<Torus>(&tmp_far, words, (w - 8) * BITS_PER_WORD,
                                     (w - 7) * BITS_PER_WORD);
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
    } else if (w % KEY_WORDS == 4) {
      CudaRadixCiphertextFFI bit_slices[BITS_PER_WORD];
      for (uint32_t i = 0; i < BITS_PER_WORD; ++i) {
        as_radix_ciphertext_slice<Torus>(&bit_slices[i], &tmp_word_buffer, i,
                                         i + 1);
      }

      CudaRadixCiphertextFFI *sbox_byte_pointers[BYTES_PER_WORD];
      for (uint32_t i = 0; i < BYTES_PER_WORD; ++i) {
        sbox_byte_pointers[i] = &bit_slices[i * BITS_PER_BYTE];
      }

      vectorized_sbox_n_bytes<Torus>(streams, sbox_byte_pointers,
                                     BYTES_PER_WORD, 1, mem->aes_encrypt_buffer,
                                     bsks, ksks);
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
