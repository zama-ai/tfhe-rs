#ifndef FAST_KREYVIUM_CUH
#define FAST_KREYVIUM_CUH

#include "../../include/kreyvium/fast_kreyvium_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../integer/scalar_mul.cuh"
#include "../linearalgebra/addition.cuh"
#include "kreyvium_common.cuh"

template <typename Torus>
__global__ void
device_fast_kreyvium_add_body_constant(Torus *__restrict__ lwe_array,
                                       uint32_t lwe_dimension,
                                       uint32_t num_blocks, Torus constant) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    lwe_array[tid * (lwe_dimension + 1) + lwe_dimension] += constant;
  }
}

// Adds a raw constant to the body of every block of a ZZ_4-encoded buffer.
// Used for the BitExt pre-rotation (+q/8) and post-rotation (+q/8 = +Delta/2),
// and for encoding the constant 1 at the ZZ_4 scale during init.
template <typename Torus>
__host__ void fast_kreyvium_add_body_constant_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *ct, Torus constant) {
  cuda_set_device(streams.gpu_index(0));
  uint32_t num_blocks = ct->num_radix_blocks;
  int num_cuda_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(num_blocks, 512, num_cuda_blocks, num_threads);
  dim3 grid(num_cuda_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);
  device_fast_kreyvium_add_body_constant<Torus>
      <<<grid, thds, 0, streams.stream(0)>>>(static_cast<Torus *>(ct->ptr),
                                             ct->lwe_dimension, num_blocks,
                                             constant);
  check_cuda_error(cudaGetLastError());
}

// Builds one round boolean as a ZZ_4 linear combination directly into a slice
// of the packed accumulator, following Algorithm 2:
//   acc <- 2 * (XOR-terms) + (AND-pair operands)   (mod 4)
// The doubling pushes the XOR parity into the padding bit; the AND-pair sum
// reaches 2 (padding bit set) exactly when both operands are 1, so the padding
// bit of acc equals XOR-of-terms XOR (AND-of-pair). No bivariate PBS is used.
//
// xor_terms : taps that are XORed (each doubled by the scalar mul by 2).
// and_terms : the two operands of the single AND gate (added in, not doubled).
//             Empty for the keystream path, which has no AND term.
template <typename Torus>
__host__ void fast_kreyvium_build_accumulator(
    CudaStreams streams, const int_radix_params &params,
    CudaRadixCiphertextFFI *acc_slice,
    const std::vector<CudaRadixCiphertextFFI *> &xor_terms,
    const std::vector<CudaRadixCiphertextFFI *> &and_terms) {

  uint32_t num_blocks = acc_slice->num_radix_blocks;

  // acc <- sum of XOR terms
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), acc_slice, 0, num_blocks,
      xor_terms[0], 0, num_blocks);
  for (size_t i = 1; i < xor_terms.size(); i++)
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), acc_slice,
                         acc_slice, xor_terms[i], num_blocks,
                         params.message_modulus, params.carry_modulus);

  // acc <- 2 * acc : the parity of the XOR terms moves into the padding bit.
  host_integer_small_scalar_mul_radix<Torus>(streams, acc_slice, acc_slice, 2,
                                             params.message_modulus,
                                             params.carry_modulus);

  // acc <- acc + AND-pair operands : their sum hits 2 (padding bit) iff both 1.
  for (size_t i = 0; i < and_terms.size(); i++)
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), acc_slice,
                         acc_slice, and_terms[i], num_blocks,
                         params.message_modulus, params.carry_modulus);
}

// Core evaluation function that advances the Kreyvium state by exactly 64
// steps. Each of the four round booleans is built as a single ZZ_4 linear
// combination and reduced to its padding bit by one univariate bit-extraction
// PBS (BitExt). During warm-up (output_dest == nullptr) only the three feedback
// booleans are extracted; the keystream boolean is added as a fourth path.
//
template <typename Torus>
__host__ void fast_kreyvium_compute_64_steps(
    CudaStreams streams, int_fast_kreyvium_buffer<Torus> *mem,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    CudaRadixCiphertextFFI *output_dest, void *const *bsks,
    uint64_t *const *ksks) {

  uint32_t N = mem->num_inputs;
  constexpr uint32_t BATCH = FAST_KREYVIUM_BATCH_SIZE;
  uint32_t batch_size_blocks = BATCH * N;
  auto ws = mem->ws;
  auto luts = mem->luts;
  auto params = mem->params;
  bool emit_keystream = (output_dest != nullptr);
  uint32_t num_paths = emit_keystream ? FAST_KREYVIUM_NUM_OUTPUT_PATHS
                                      : FAST_KREYVIUM_NUM_FEEDBACK_PATHS;

  // Delta = q/4 and the BitExt rotations of +q/8 = +Delta/2.
  Torus delta = luts->delta;
  Torus half_delta = delta / 2;

  // Extract register taps for A (93-bit register)
  CudaRadixCiphertextFFI a65, a92, a91, a90, a68;
  slice_reg_batch_impl<Torus>(&a65, a_reg, 27, BATCH, N);
  slice_reg_batch_impl<Torus>(&a92, a_reg, 0, BATCH, N);
  slice_reg_batch_impl<Torus>(&a91, a_reg, 1, BATCH, N);
  slice_reg_batch_impl<Torus>(&a90, a_reg, 2, BATCH, N);
  slice_reg_batch_impl<Torus>(&a68, a_reg, 24, BATCH, N);

  // Extract register taps for B (84-bit register)
  CudaRadixCiphertextFFI b68, b83, b82, b81, b77;
  slice_reg_batch_impl<Torus>(&b68, b_reg, 15, BATCH, N);
  slice_reg_batch_impl<Torus>(&b83, b_reg, 0, BATCH, N);
  slice_reg_batch_impl<Torus>(&b82, b_reg, 1, BATCH, N);
  slice_reg_batch_impl<Torus>(&b81, b_reg, 2, BATCH, N);
  slice_reg_batch_impl<Torus>(&b77, b_reg, 6, BATCH, N);

  // Extract register taps for C (111-bit register)
  CudaRadixCiphertextFFI c65, c110, c109, c108, c86;
  slice_reg_batch_impl<Torus>(&c65, c_reg, 45, BATCH, N);
  slice_reg_batch_impl<Torus>(&c110, c_reg, 0, BATCH, N);
  slice_reg_batch_impl<Torus>(&c109, c_reg, 1, BATCH, N);
  slice_reg_batch_impl<Torus>(&c108, c_reg, 2, BATCH, N);
  slice_reg_batch_impl<Torus>(&c86, c_reg, 24, BATCH, N);

  // Extract Key/IV bits using the virtual rotation offset and advance offsets
  CudaRadixCiphertextFFI k127, iv127;
  slice_reg_batch_impl<Torus>(&k127, k_reg, *k_offset, FAST_KREYVIUM_BATCH_SIZE,
                              N);
  slice_reg_batch_impl<Torus>(&iv127, iv_reg, *iv_offset,
                              FAST_KREYVIUM_BATCH_SIZE, N);
  *k_offset = (*k_offset + FAST_KREYVIUM_BATCH_SIZE) % FAST_KREYVIUM_KEY_BITS;
  *iv_offset = (*iv_offset + FAST_KREYVIUM_BATCH_SIZE) % FAST_KREYVIUM_IV_BITS;

  // The packed accumulator holds the round booleans in the order
  // [t3 (-> A), t1 (-> B), t2 (-> C), r (keystream)] so the first three slices
  // feed shift-and-insert directly and the fourth is the optional keystream.
  CudaRadixCiphertextFFI acc_a, acc_b, acc_c, acc_out;
  as_radix_ciphertext_slice<Torus>(&acc_a, ws->packed_acc, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&acc_b, ws->packed_acc, batch_size_blocks,
                                   2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(
      &acc_c, ws->packed_acc, 2 * batch_size_blocks, 3 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(
      &acc_out, ws->packed_acc, 3 * batch_size_blocks, 4 * batch_size_blocks);

  // t3 -> A : 2*(c65 + c110 + k127 + a68) + c109 + c108
  fast_kreyvium_build_accumulator<Torus>(
      streams, params, &acc_a, {&c65, &c110, &k127, &a68}, {&c109, &c108});
  // t1 -> B : 2*(a65 + a92 + iv127 + b77) + a91 + a90
  fast_kreyvium_build_accumulator<Torus>(
      streams, params, &acc_b, {&a65, &a92, &iv127, &b77}, {&a91, &a90});
  // t2 -> C : 2*(b68 + b83 + c86) + b82 + b81
  fast_kreyvium_build_accumulator<Torus>(streams, params, &acc_c,
                                         {&b68, &b83, &c86}, {&b82, &b81});
  // r (keystream) : 2*(a65 + a92 + b68 + b83 + c65 + c110 + k127), no AND term.
  // The transciphering XOR with a cleartext message bit alpha folds in here as
  // a trivial body offset (2*alpha mod 4)*Delta on acc_out (noise-free) before
  // the BitExt; the current FFI exposes no alpha, so the raw keystream bit is
  // built.
  if (emit_keystream)
    fast_kreyvium_build_accumulator<Torus>(
        streams, params, &acc_out, {&a65, &a92, &b68, &b83, &c65, &c110, &k127},
        {});

  // BitExt over the active paths (Algorithm 1):
  //   1. pre-rotation  : + q/8 to center the four ZZ_4 values
  //   2. PBS           : raw padding-bit test polynomial (built in the LUT)
  //   3. post-rotation : + q/8 (= +Delta/2) to normalize to a clean {0,Delta}
  CudaRadixCiphertextFFI acc_active, out_active;
  as_radix_ciphertext_slice<Torus>(&acc_active, ws->packed_acc, 0,
                                   num_paths * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&out_active, ws->packed_out, 0,
                                   num_paths * batch_size_blocks);

  fast_kreyvium_add_body_constant_inplace<Torus>(streams, &acc_active,
                                                 half_delta);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &out_active, &acc_active, bsks, ksks, luts->bitext_lut,
      num_paths * batch_size_blocks);
  fast_kreyvium_add_body_constant_inplace<Torus>(streams, &out_active,
                                                 half_delta);

  // Route extracted booleans back into the registers.
  CudaRadixCiphertextFFI new_a, new_b, new_c;
  as_radix_ciphertext_slice<Torus>(&new_a, ws->packed_out, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&new_b, ws->packed_out, batch_size_blocks,
                                   2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(
      &new_c, ws->packed_out, 2 * batch_size_blocks, 3 * batch_size_blocks);

  shift_and_insert_batch_impl<Torus>(streams, ws->shift_workspace, a_reg,
                                     &new_a, FAST_KREYVIUM_REGISTER_A_BITS, N,
                                     FAST_KREYVIUM_BATCH_SIZE);
  shift_and_insert_batch_impl<Torus>(streams, ws->shift_workspace, b_reg,
                                     &new_b, FAST_KREYVIUM_REGISTER_B_BITS, N,
                                     FAST_KREYVIUM_BATCH_SIZE);
  shift_and_insert_batch_impl<Torus>(streams, ws->shift_workspace, c_reg,
                                     &new_c, FAST_KREYVIUM_REGISTER_C_BITS, N,
                                     FAST_KREYVIUM_BATCH_SIZE);

  if (emit_keystream) {
    CudaRadixCiphertextFFI new_out;
    as_radix_ciphertext_slice<Torus>(
        &new_out, ws->packed_out, 3 * batch_size_blocks, 4 * batch_size_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output_dest, 0,
        batch_size_blocks, &new_out, 0, batch_size_blocks);
  }
}

// Initializes the Kreyvium state by loading the Key and IV into the registers
// and executing the standard 1152-cycle warmup phase. All loaded bits and the
// 66 constant ones in register C are encoded at the ZZ_4 scale (body 0 or
// Delta = q/4), matching the loop invariant; no flush is needed afterwards.
//
template <typename Torus>
__host__ void host_fast_kreyvium_init(
    CudaStreams streams, int_fast_kreyvium_buffer<Torus> *mem,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    CudaRadixCiphertextFFI const *key_bitsliced,
    CudaRadixCiphertextFFI const *iv_bitsliced, void *const *bsks,
    uint64_t *const *ksks) {

  uint32_t N = mem->num_inputs;
  *k_offset = 0;
  *iv_offset = 0;

  // k = key_bits.to_vec();
  CudaRadixCiphertextFFI src_key_slice;
  slice_reg_batch_impl<Torus>(&src_key_slice, key_bitsliced, 0,
                              FAST_KREYVIUM_KEY_BITS, N);
  CudaRadixCiphertextFFI dest_k_reg_slice;
  slice_reg_batch_impl<Torus>(&dest_k_reg_slice, k_reg, 0,
                              FAST_KREYVIUM_KEY_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_k_reg_slice, &src_key_slice);

  // a[0..93] = key[35..128]
  CudaRadixCiphertextFFI k_source_for_a;
  slice_reg_batch_impl<Torus>(&k_source_for_a, k_reg,
                              FAST_KREYVIUM_KEY_BITS -
                                  FAST_KREYVIUM_REGISTER_A_BITS,
                              FAST_KREYVIUM_REGISTER_A_BITS, N);
  CudaRadixCiphertextFFI dest_a_slice;
  slice_reg_batch_impl<Torus>(&dest_a_slice, a_reg, 0,
                              FAST_KREYVIUM_REGISTER_A_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_a_slice, &k_source_for_a);

  // k.reverse();
  reverse_bitsliced_radix_inplace_impl<Torus>(streams, mem->ws->shift_workspace,
                                              k_reg, FAST_KREYVIUM_KEY_BITS, N);

  // iv = iv_bits.to_vec();
  CudaRadixCiphertextFFI src_iv_slice;
  slice_reg_batch_impl<Torus>(&src_iv_slice, iv_bitsliced, 0,
                              FAST_KREYVIUM_IV_BITS, N);
  CudaRadixCiphertextFFI dest_iv_reg_slice;
  slice_reg_batch_impl<Torus>(&dest_iv_reg_slice, iv_reg, 0,
                              FAST_KREYVIUM_IV_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_iv_reg_slice, &src_iv_slice);

  // b[0..84] = iv[44..128]
  CudaRadixCiphertextFFI iv_source_for_b;
  slice_reg_batch_impl<Torus>(&iv_source_for_b, iv_reg,
                              FAST_KREYVIUM_IV_BITS -
                                  FAST_KREYVIUM_REGISTER_B_BITS,
                              FAST_KREYVIUM_REGISTER_B_BITS, N);
  CudaRadixCiphertextFFI dest_b_slice;
  slice_reg_batch_impl<Torus>(&dest_b_slice, b_reg, 0,
                              FAST_KREYVIUM_REGISTER_B_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_b_slice, &iv_source_for_b);

  // c[67..111] = iv[0..44]
  CudaRadixCiphertextFFI iv_source_for_c;
  slice_reg_batch_impl<Torus>(
      &iv_source_for_c, iv_reg, 0,
      FAST_KREYVIUM_IV_BITS - FAST_KREYVIUM_REGISTER_B_BITS, N);
  CudaRadixCiphertextFFI dest_c_iv_part;
  slice_reg_batch_impl<Torus>(
      &dest_c_iv_part, c_reg,
      FAST_KREYVIUM_REGISTER_C_BITS -
          (FAST_KREYVIUM_IV_BITS - FAST_KREYVIUM_REGISTER_B_BITS),
      FAST_KREYVIUM_IV_BITS - FAST_KREYVIUM_REGISTER_B_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_c_iv_part, &iv_source_for_c);

  // iv.reverse();
  reverse_bitsliced_radix_inplace_impl<Torus>(streams, mem->ws->shift_workspace,
                                              iv_reg, FAST_KREYVIUM_IV_BITS, N);

  // for i in 0..66 { c[i + 1] = 1; }
  // Encode the constant 1 directly at the ZZ_4 scale by adding Delta to the
  // body. The source slice is a trivial zero ciphertext, so this yields a clean
  // {Delta} ciphertext and needs no flush PBS, unlike the old message-space
  // path which added 1 then flushed.
  CudaRadixCiphertextFFI dest_c_ones;
  slice_reg_batch_impl<Torus>(&dest_c_ones, c_reg, FAST_KREYVIUM_C_ONES_OFFSET,
                              FAST_KREYVIUM_C_ONES_COUNT, N);
  fast_kreyvium_add_body_constant_inplace<Torus>(streams, &dest_c_ones,
                                                 mem->luts->delta);

  // Standard Kreyvium warm-up: FAST_KREYVIUM_WARMUP_CYCLES (1152) cycles,
  // processed in batches of FAST_KREYVIUM_BATCH_SIZE (64). No keystream is
  // emitted, so each batch issues only the three feedback bit-extraction PBS.
  for (uint32_t i = 0; i < FAST_KREYVIUM_WARMUP_BATCHES; i++)
    fast_kreyvium_compute_64_steps(streams, mem, a_reg, b_reg, c_reg, k_reg,
                                   iv_reg, k_offset, iv_offset, nullptr, bsks,
                                   ksks);
}

// Generates the requested number of keystream bits (in batches of 64) from an
// existing state and updates the internal registers in place.
//
template <typename Torus>
__host__ void host_fast_kreyvium_step(
    CudaStreams streams, CudaRadixCiphertextFFI *keystream_output,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    uint32_t num_inputs, uint32_t num_steps,
    int_fast_kreyvium_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {

  PANIC_IF_FALSE(num_steps % FAST_KREYVIUM_BATCH_SIZE == 0,
                 "FastKreyvium Error: num_steps must be a multiple of 64.\n");
  uint32_t num_batches = num_steps / FAST_KREYVIUM_BATCH_SIZE;
  for (uint32_t i = 0; i < num_batches; i++) {
    CudaRadixCiphertextFFI batch_out_slice;
    slice_reg_batch_impl<Torus>(&batch_out_slice, keystream_output,
                                i * FAST_KREYVIUM_BATCH_SIZE,
                                FAST_KREYVIUM_BATCH_SIZE, num_inputs);
    fast_kreyvium_compute_64_steps(streams, mem, a_reg, b_reg, c_reg, k_reg,
                                   iv_reg, k_offset, iv_offset,
                                   &batch_out_slice, bsks, ksks);
  }
}

template <typename Torus>
uint64_t scratch_cuda_fast_kreyvium_encrypt(
    CudaStreams streams, int_fast_kreyvium_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_inputs) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_fast_kreyvium_buffer<Torus>(
      streams, params, allocate_gpu_memory, num_inputs, size_tracker);
  return size_tracker;
}

#endif
