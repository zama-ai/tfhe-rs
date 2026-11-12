#ifndef CUDA_VERIFICATION_TRACE_H
#define CUDA_VERIFICATION_TRACE_H

// ---------------------------------------------------------------------------
// Verification trace (test builds only: cargo feature
// `gpu-verification-trace`, CMake define VERIFICATION_TRACE)
// ---------------------------------------------------------------------------
//
// Every leaf host function of the integer layer launches one GPU kernel (or a
// memcpy/memset) and then updates the host-side degrees / noise levels. With
// VERIFICATION_TRACE defined, each leaf also appends a TraceRecord naming the
// kernel and its arguments. Replaying the records with the plaintext kernels
// of verification/plain_kernels.h runs the exact same algorithm on cleartext
// blocks, so it can be checked on many inputs without keys or a GPU.
//
//   leaf host function                    TraceRecord
//   ┌──────────────────────────────┐      ┌────────────────────────────────┐
//   │ kernel<<<>>>(out, in1, in2)  │ ───► │ kernel  = ADDITION             │
//   │ out->degrees[i] = ...        │      │ origin  = "host_addition"      │
//   │ VERIFICATION_TRACE_HOOK(...) │      │ buffers = [out, in1, in2]      │
//   └──────────────────────────────┘      │ meta_out= degrees/noise set    │
//                                         └────────────────────────────────┘
//
// Blocks are identified by their device address, so slices, aliasing and
// in-place kernels need no special treatment: a slice's block i simply has
// the address of the parent's block (start + i).
//
//   radix ct (ptr)      slice(ct, 2, 4)
//   ┌────┬────┬────┬────┬────┐
//   │ b0 │ b1 │ b2 │ b3 │ b4 │   address(b_i) = ptr + i * (lwe_dim + 1) * 8
//   └────┴────┴────┴────┴────┘
//             ^slice.ptr
//
// Semantics shared by every kernel record:
// - Values live in Z_{2p}, p = message_modulus * carry_modulus: the message
//   and carry bits plus the padding bit, exactly what a ciphertext encodes.
//   For 2_2 parameters a block is a 5-bit value [pad | c1 c0 | m1 m0].
// - A record is a parallel assignment: all reads happen before all writes,
//   which is how the GPU kernels behave on non-overlapping blocks.
// - buffers[k] is the k-th pointer argument of the kernel, expressed as the
//   device addresses of the blocks the kernel may touch through it.
// - meta_out is the degree / noise the leaf host function wrote on its output
//   ciphertext(s) after the kernel, snapshotted on every block of them.
// - meta_in is the degree / noise claimed on blocks whose metadata matters at
//   that point: PBS inputs (degree < p, noise <= max) and op outputs (END).
//
// The trace is process-global. A test clears it, allocates the op inputs
// (ALLOC), calls begin() to seed them, runs scratch + op (so LUT generation and
// zero-initialised scratch buffers are recorded), calls end() and releases.
//
// Lifetime of a block address, as tracked by the interpreter:
//
//   (absent) --ALLOC--> trivial 0 --write--> value --FREE--> dead
//   reading an absent or dead block is an error (missing hook, use after
//   free); FREE then ALLOC of the same address starts a fresh buffer.

// Hooks are written as VERIFICATION_TRACE_HOOK(verification::record_x<T>(...))
// and compile to nothing without VERIFICATION_TRACE. Variadic so that template
// argument lists containing commas pass through unchanged.
#ifdef VERIFICATION_TRACE
#define VERIFICATION_TRACE_HOOK(...) __VA_ARGS__
#else
#define VERIFICATION_TRACE_HOOK(...)                                           \
  do {                                                                         \
  } while (0)
#endif

#ifdef VERIFICATION_TRACE

#include "checked_arithmetic.h"
#include "device.h"
#include "integer/integer.h"
#include "verification/trace_format.h"
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace verification {

/// Process-global, mutex-protected list of records.
class Trace {
public:
  static Trace &get() {
    static Trace instance;
    return instance;
  }

  void push(TraceRecord &&record) {
    std::lock_guard<std::mutex> guard(lock);
    record.seq = records.size();
    records.push_back(std::move(record));
  }

  void clear() {
    std::lock_guard<std::mutex> guard(lock);
    records.clear();
  }

  /// @brief Copy of the records, for an in-process interpreter.
  std::vector<TraceRecord> snapshot() {
    std::lock_guard<std::mutex> guard(lock);
    return records;
  }

  /// @brief Human-readable dump, one record per line.
  void dump_text(const char *path) {
    std::lock_guard<std::mutex> guard(lock);
    FILE *file = std::fopen(path, "w");
    PANIC_IF_FALSE(file != nullptr,
                   "Cuda error (verification trace): cannot open %s", path);
    for (auto const &r : records)
      write_record(file, r);
    std::fclose(file);
  }

private:
  Trace() = default;

  std::mutex lock;
  std::vector<TraceRecord> records;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// @brief Device address of block `index` of a radix ciphertext.
template <typename Torus>
uint64_t block_address(CudaRadixCiphertextFFI const *ct, uint64_t index) {
  PANIC_IF_FALSE(ct->ptr != nullptr,
                 "Cuda error (verification trace): unallocated ciphertext");
  return reinterpret_cast<uint64_t>(ct->ptr) +
         index * ((uint64_t)ct->lwe_dimension + 1) * sizeof(Torus);
}

/// @brief Addresses of blocks [start, end) of a radix ciphertext.
template <typename Torus>
BlockArray blocks(CudaRadixCiphertextFFI const *ct, uint32_t start,
                  uint32_t end) {
  BlockArray out;
  out.reserve(end - start);
  for (uint32_t i = start; i < end; i++)
    out.push_back(block_address<Torus>(ct, i));
  return out;
}

/// @brief Addresses of all num_radix_blocks blocks of a radix ciphertext.
template <typename Torus>
BlockArray all_blocks(CudaRadixCiphertextFFI const *ct) {
  return blocks<Torus>(ct, 0, ct->num_radix_blocks);
}

/// @brief Claimed degree / noise of blocks [start, end).
template <typename Torus>
std::vector<MetaEntry> meta(CudaRadixCiphertextFFI const *ct, uint32_t start,
                            uint32_t end) {
  std::vector<MetaEntry> out;
  out.reserve(end - start);
  for (uint32_t i = start; i < end; i++)
    out.push_back(
        {block_address<Torus>(ct, i), ct->degrees[i], ct->noise_levels[i]});
  return out;
}

/// @brief Claimed degree / noise of every block of a ciphertext.
template <typename Torus>
std::vector<MetaEntry> all_meta(CudaRadixCiphertextFFI const *ct) {
  return meta<Torus>(ct, 0, ct->num_radix_blocks);
}

/// @brief Appends `extra` at the end of `dst`.
inline void append_meta(std::vector<MetaEntry> &dst,
                        std::vector<MetaEntry> const &extra) {
  dst.insert(dst.end(), extra.begin(), extra.end());
}

/// @brief Blocking copy of a device array, widened to uint64_t. Traces record
/// what the kernel read on the GPU, not a host mirror that could disagree.
template <typename T>
std::vector<uint64_t> read_device_array(cudaStream_t stream, uint32_t gpu_index,
                                        T const *d_array, uint32_t count) {
  if (count == 0)
    return {};
  std::vector<T> h_array(count);
  cuda_memcpy_async_to_cpu(h_array.data(), d_array, safe_mul_sizeof<T>(count),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  return std::vector<uint64_t>(h_array.begin(), h_array.end());
}

/// @brief Identity index array 0..count-1, for LUTs using trivial indexes.
inline std::vector<uint64_t> identity_indexes(uint32_t count) {
  std::vector<uint64_t> out(count);
  for (uint32_t i = 0; i < count; i++)
    out[i] = i;
  return out;
}

inline TraceRecord make_record(Kernel kernel, const char *origin) {
  TraceRecord r;
  r.kernel = kernel;
  r.origin = origin;
  return r;
}

// ---------------------------------------------------------------------------
// Op boundaries
// ---------------------------------------------------------------------------

/// @brief Declares the op inputs, whose blocks the interpreter seeds. Call
/// before scratch so LUTs and buffers created there are part of the trace.
/// `op_args` are the public op parameters (flags, ...), kept for the
/// interpreter to pick the reference result.
template <typename Torus>
void begin(const char *label,
           std::vector<CudaRadixCiphertextFFI const *> const &inputs,
           uint32_t message_modulus, uint32_t carry_modulus,
           std::vector<uint64_t> const &op_args = {}) {
  auto r = make_record(Kernel::BEGIN, "begin");
  r.label = label;
  r.args = {message_modulus, carry_modulus};
  r.args.insert(r.args.end(), op_args.begin(), op_args.end());
  for (auto const *ct : inputs) {
    r.buffers.push_back(all_blocks<Torus>(ct));
    append_meta(r.meta_in, all_meta<Torus>(ct));
  }
  Trace::get().push(std::move(r));
}

/// @brief Declares the op outputs; the interpreter reads them back here.
template <typename Torus>
void end(const char *label,
         std::vector<CudaRadixCiphertextFFI const *> const &outputs) {
  auto r = make_record(Kernel::END, "end");
  r.label = label;
  for (auto const *ct : outputs) {
    r.buffers.push_back(all_blocks<Torus>(ct));
    append_meta(r.meta_in, all_meta<Torus>(ct));
  }
  Trace::get().push(std::move(r));
}

// ---------------------------------------------------------------------------
// Memory lifetime recorders
// ---------------------------------------------------------------------------

/// create_zero_radix_ciphertext_async. Nothing is recorded for the size-only
/// scratch pass, which allocates nothing.
template <typename Torus>
void record_alloc(const char *origin, CudaRadixCiphertextFFI const *ct,
                  bool allocate_gpu_memory) {
  if (!allocate_gpu_memory || ct->ptr == nullptr)
    return;
  auto r = make_record(Kernel::ALLOC, origin);
  r.buffers = {all_blocks<Torus>(ct)};
  r.args = {reinterpret_cast<uint64_t>(ct->ptr),
            ((uint64_t)ct->lwe_dimension + 1) * sizeof(Torus),
            ct->num_radix_blocks};
  r.meta_out = all_meta<Torus>(ct);
  Trace::get().push(std::move(r));
}

/// release_radix_ciphertext_async. Only the base address is needed: the
/// interpreter frees the whole allocation registered by ALLOC.
inline void record_free(const char *origin, void const *ptr,
                        bool gpu_memory_allocated) {
  if (!gpu_memory_allocated || ptr == nullptr)
    return;
  auto r = make_record(Kernel::FREE, origin);
  r.args = {reinterpret_cast<uint64_t>(ptr)};
  Trace::get().push(std::move(r));
}

// ---------------------------------------------------------------------------
// Data movement recorders
// ---------------------------------------------------------------------------

/// copy_radix_ciphertext_slice_async (also reached by copy_radix_ciphertext,
/// pop / insert / push block) and the memcpy of host_addition_plaintext*.
template <typename Torus>
void record_memcpy_blocks(const char *origin, CudaRadixCiphertextFFI const *dst,
                          uint32_t dst_start, uint32_t dst_end,
                          CudaRadixCiphertextFFI const *src, uint32_t src_start,
                          uint32_t src_end) {
  auto r = make_record(Kernel::MEMCPY_BLOCKS, origin);
  r.buffers = {blocks<Torus>(dst, dst_start, dst_end),
               blocks<Torus>(src, src_start, src_end)};
  r.meta_out = all_meta<Torus>(dst);
  Trace::get().push(std::move(r));
}

/// set_zero_radix_ciphertext_slice_async.
template <typename Torus>
void record_memset_zero(const char *origin, CudaRadixCiphertextFFI const *dst,
                        uint32_t start, uint32_t end) {
  auto r = make_record(Kernel::MEMSET_ZERO, origin);
  r.buffers = {blocks<Torus>(dst, start, end)};
  r.meta_out = all_meta<Torus>(dst);
  Trace::get().push(std::move(r));
}

/// set_trivial_radix_ciphertext_async (scalars read from the GPU) and
/// set_single_scalar_trivial_radix_ciphertext_async (one host scalar).
template <typename Torus>
void record_create_trivial_radix(const char *origin,
                                 CudaRadixCiphertextFFI const *dst,
                                 std::vector<uint64_t> cleartexts) {
  auto r = make_record(Kernel::CREATE_TRIVIAL_RADIX, origin);
  r.buffers = {blocks<Torus>(dst, 0, cleartexts.size())};
  r.args = std::move(cleartexts);
  r.meta_out = all_meta<Torus>(dst);
  Trace::get().push(std::move(r));
}

/// copy_radix_ciphertext_blocks_from_indexes_async (realign = false) and
/// copy_radix_ciphertext_blocks_to_indexes_async (realign = true).
template <typename Torus>
void record_indexed_copy(const char *origin, cudaStream_t stream,
                         uint32_t gpu_index, bool realign,
                         CudaRadixCiphertextFFI const *dst,
                         CudaRadixCiphertextFFI const *src,
                         Torus const *d_indexes, uint32_t num_blocks) {
  auto r = make_record(realign ? Kernel::REALIGN_WITH_INDEXES
                               : Kernel::ALIGN_WITH_INDEXES,
                       origin);
  r.buffers = {all_blocks<Torus>(dst), all_blocks<Torus>(src)};
  r.indexes = {read_device_array(stream, gpu_index, d_indexes, num_blocks)};
  r.meta_out = all_meta<Torus>(dst);
  Trace::get().push(std::move(r));
}

/// host_radix_blocks_rotate_right / _left.
template <typename Torus>
void record_blocks_rotate(const char *origin, bool right,
                          CudaRadixCiphertextFFI const *dst,
                          CudaRadixCiphertextFFI const *src, uint32_t rotations,
                          uint32_t num_blocks) {
  auto r = make_record(
      right ? Kernel::BLOCKS_ROTATE_RIGHT : Kernel::BLOCKS_ROTATE_LEFT, origin);
  r.buffers = {blocks<Torus>(dst, 0, num_blocks),
               blocks<Torus>(src, 0, num_blocks)};
  r.args = {rotations};
  r.meta_out = all_meta<Torus>(dst);
  Trace::get().push(std::move(r));
}

/// host_radix_blocks_reverse_inplace.
template <typename Torus>
void record_blocks_reverse_inplace(const char *origin,
                                   CudaRadixCiphertextFFI const *buf) {
  auto r = make_record(Kernel::BLOCKS_REVERSE_INPLACE, origin);
  r.buffers = {all_blocks<Torus>(buf)};
  r.meta_out = all_meta<Torus>(buf);
  Trace::get().push(std::move(r));
}

// ---------------------------------------------------------------------------
// Levelled arithmetic recorders
// ---------------------------------------------------------------------------

/// Kernels of the shape out[i] = f(in_0[i], in_1[i], ...) over the first
/// num_blocks blocks of every buffer: ADDITION, NEGATION, CLEARTEXT_*,
/// UNCHECKED_SUB_WITH_CORRECTING_TERM, NEGATION_WITH_CORRECTING_TERM,
/// PLAINTEXT_ADDITION*. Kernel-specific scalars go in args.
template <typename Torus>
void record_elementwise(const char *origin, Kernel kernel,
                        CudaRadixCiphertextFFI const *out,
                        std::vector<CudaRadixCiphertextFFI const *> const &ins,
                        uint32_t num_blocks, std::vector<uint64_t> args = {}) {
  auto r = make_record(kernel, origin);
  r.buffers.push_back(blocks<Torus>(out, 0, num_blocks));
  for (auto const *in : ins)
    r.buffers.push_back(blocks<Torus>(in, 0, num_blocks));
  r.args = std::move(args);
  r.meta_out = all_meta<Torus>(out);
  Trace::get().push(std::move(r));
}

/// host_add_the_same_block_to_all_blocks.
template <typename Torus>
void record_constant_addition(const char *origin,
                              CudaRadixCiphertextFFI const *out,
                              CudaRadixCiphertextFFI const *in,
                              CudaRadixCiphertextFFI const *single) {
  auto r = make_record(Kernel::CONSTANT_ADDITION, origin);
  r.buffers = {all_blocks<Torus>(out), all_blocks<Torus>(in),
               blocks<Torus>(single, 0, 1)};
  r.meta_out = all_meta<Torus>(out);
  Trace::get().push(std::move(r));
}

/// In-place body updates on the first num_blocks blocks:
/// SCALAR_ADDITION_INPLACE, ADD_SCALAR_ONE_INPLACE, SCALAR_SUBTRACTION_INPLACE.
/// `cleartexts` is empty for ADD_SCALAR_ONE_INPLACE.
template <typename Torus>
void record_inplace_scalar(const char *origin, Kernel kernel,
                           CudaRadixCiphertextFFI const *buf,
                           uint32_t num_blocks,
                           std::vector<uint64_t> cleartexts) {
  auto r = make_record(kernel, origin);
  r.buffers = {blocks<Torus>(buf, 0, num_blocks)};
  r.args = std::move(cleartexts);
  r.meta_out = all_meta<Torus>(buf);
  Trace::get().push(std::move(r));
}

/// pack_blocks.
template <typename Torus>
void record_pack_blocks(const char *origin, CudaRadixCiphertextFFI const *out,
                        CudaRadixCiphertextFFI const *in, uint32_t num_blocks,
                        uint32_t factor) {
  auto r = make_record(Kernel::PACK_BLOCKS, origin);
  r.buffers = {blocks<Torus>(out, 0, (num_blocks + 1) / 2),
               blocks<Torus>(in, 0, num_blocks)};
  r.args = {factor};
  r.meta_out = all_meta<Torus>(out);
  Trace::get().push(std::move(r));
}

/// host_pack_bivariate_blocks (single_rhs = false) and
/// host_pack_bivariate_blocks_with_single_block (single_rhs = true). Buffers
/// span whole ciphertexts since the kernel addresses them through indexes.
template <typename Torus>
void record_pack_bivariate(const char *origin, cudaStream_t stream,
                           uint32_t gpu_index, bool single_rhs,
                           CudaRadixCiphertextFFI const *out,
                           Torus const *d_indexes_out,
                           CudaRadixCiphertextFFI const *lhs,
                           CudaRadixCiphertextFFI const *rhs,
                           Torus const *d_indexes_in, uint32_t shift,
                           uint32_t num_blocks) {
  auto r =
      make_record(single_rhs ? Kernel::PACK_BIVARIATE_BLOCKS_WITH_SINGLE_BLOCK
                             : Kernel::PACK_BIVARIATE_BLOCKS,
                  origin);
  r.buffers = {all_blocks<Torus>(out), all_blocks<Torus>(lhs),
               single_rhs ? blocks<Torus>(rhs, 0, 1) : all_blocks<Torus>(rhs)};
  r.indexes = {read_device_array(stream, gpu_index, d_indexes_out, num_blocks),
               read_device_array(stream, gpu_index, d_indexes_in, num_blocks)};
  r.args = {shift};
  r.meta_out = all_meta<Torus>(out);
  Trace::get().push(std::move(r));
}

/// host_radix_sum_in_groups.
template <typename Torus>
void record_radix_sum_in_groups(const char *origin,
                                CudaRadixCiphertextFFI const *dst,
                                CudaRadixCiphertextFFI const *src1,
                                CudaRadixCiphertextFFI const *src2,
                                uint32_t num_blocks, uint32_t group_size) {
  auto r = make_record(Kernel::RADIX_SUM_IN_GROUPS, origin);
  uint32_t num_groups = (num_blocks + group_size - 1) / group_size;
  r.buffers = {blocks<Torus>(dst, 0, num_blocks),
               blocks<Torus>(src1, 0, num_blocks),
               blocks<Torus>(src2, 0, num_groups)};
  r.args = {group_size};
  r.meta_out = all_meta<Torus>(dst);
  Trace::get().push(std::move(r));
}

/// host_radix_cumulative_sum_in_groups.
template <typename Torus>
void record_radix_cumulative_sum_in_groups(const char *origin,
                                           CudaRadixCiphertextFFI const *dst,
                                           CudaRadixCiphertextFFI const *src,
                                           uint32_t num_blocks,
                                           uint32_t group_size) {
  auto r = make_record(Kernel::RADIX_CUMULATIVE_SUM_IN_GROUPS, origin);
  r.buffers = {blocks<Torus>(dst, 0, num_blocks),
               blocks<Torus>(src, 0, num_blocks)};
  r.args = {group_size};
  r.meta_out = all_meta<Torus>(dst);
  Trace::get().push(std::move(r));
}

/// host_radix_split_simulators_and_grouping_pgns.
template <typename Torus>
void record_split_simulators_and_grouping_pgns(
    const char *origin, CudaRadixCiphertextFFI const *simulators,
    CudaRadixCiphertextFFI const *grouping_pgns,
    CudaRadixCiphertextFFI const *src, uint32_t num_blocks, uint32_t group_size,
    Torus one) {
  auto r = make_record(Kernel::SPLIT_SIMULATORS_AND_GROUPING_PGNS, origin);
  r.buffers = {blocks<Torus>(simulators, 0, num_blocks),
               all_blocks<Torus>(grouping_pgns),
               blocks<Torus>(src, 0, num_blocks)};
  r.args = {group_size, (uint64_t)one};
  r.meta_out = all_meta<Torus>(simulators);
  append_meta(r.meta_out, all_meta<Torus>(grouping_pgns));
  Trace::get().push(std::move(r));
}

// ---------------------------------------------------------------------------
// PBS recorders
// ---------------------------------------------------------------------------

/// LWE / LUT index arrays a PBS uses: identity when the LUT uses trivial LWE
/// indexes, otherwise read from GPU 0, where the single-GPU path reads them.
template <typename Lut>
std::vector<uint64_t> pbs_lwe_indexes(cudaStream_t stream, uint32_t gpu_index,
                                      Lut const *lut, bool input,
                                      uint32_t num_blocks) {
  if (lut->using_trivial_lwe_indexes)
    return identity_indexes(num_blocks);
  return read_device_array(stream, gpu_index,
                           input ? lut->lwe_indexes_in : lut->lwe_indexes_out,
                           num_blocks);
}

/// Claimed metadata of the blocks a PBS reads. Call before the apply function
/// writes the output metadata: with in == out (in-place PBS) the input claims
/// are overwritten by that loop.
template <typename Torus, typename Lut>
std::vector<MetaEntry> pbs_meta_in(cudaStream_t stream, uint32_t gpu_index,
                                   CudaRadixCiphertextFFI const *in,
                                   Lut const *lut, uint32_t num_blocks) {
  std::vector<MetaEntry> out;
  for (auto b : pbs_lwe_indexes(stream, gpu_index, lut, true, num_blocks)) {
    PANIC_IF_FALSE(b < in->num_radix_blocks,
                   "Cuda error (verification trace): PBS input index %llu "
                   "out of range",
                   (unsigned long long)b);
    out.push_back(
        {block_address<Torus>(in, b), in->degrees[b], in->noise_levels[b]});
  }
  return out;
}

/// integer_radix_apply_{univariate,many_univariate,bivariate}_lookup_table.
/// `in` is the buffer the keyswitch reads (lut->tmp_lwe_before_ks for the
/// bivariate case, whose packing is recorded by its own leaf). `Lut` is
/// int_radix_lut, kept generic so this header does not depend on it.
/// `meta_in` comes from pbs_meta_in, taken before the output metadata loop.
template <typename Torus, typename Lut>
void record_programmable_bootstrap(const char *origin, cudaStream_t stream,
                                   uint32_t gpu_index,
                                   CudaRadixCiphertextFFI const *out,
                                   CudaRadixCiphertextFFI const *in,
                                   Lut const *lut, uint32_t num_blocks,
                                   uint32_t num_many_lut, uint32_t lut_stride,
                                   std::vector<MetaEntry> meta_in) {
  auto r = make_record(Kernel::PROGRAMMABLE_BOOTSTRAP, origin);
  r.buffers = {all_blocks<Torus>(out), all_blocks<Torus>(in)};
  r.indexes = {pbs_lwe_indexes(stream, gpu_index, lut, true, num_blocks),
               pbs_lwe_indexes(stream, gpu_index, lut, false, num_blocks),
               read_device_array(stream, gpu_index, lut->lut_indexes_vec[0],
                                 num_blocks)};
  r.meta_in = std::move(meta_in);

  uint64_t lut_size_in_words =
      (uint64_t)(lut->params.glwe_dimension + 1) * lut->params.polynomial_size;
  r.args = {num_blocks, num_many_lut, lut_stride,
            reinterpret_cast<uint64_t>(lut->lut_vec[0]), lut_size_in_words};
  r.meta_out = all_meta<Torus>(out);
  Trace::get().push(std::move(r));
}

/// generate_device_accumulator* / generate_many_lut_device_accumulator: call
/// right before the host accumulator is copied to `d_acc`. Nothing is copied,
/// hence nothing recorded, in the size-only scratch pass.
template <typename Torus>
void record_lut_def(const char *origin, Torus const *d_acc, Torus const *h_acc,
                    uint32_t glwe_dimension, uint32_t polynomial_size,
                    uint32_t input_message_modulus,
                    uint32_t input_carry_modulus,
                    uint32_t output_message_modulus,
                    uint32_t output_carry_modulus, bool encoded,
                    bool gpu_memory_allocated) {
  if (!gpu_memory_allocated)
    return;
  auto r = make_record(Kernel::LUT_DEF, origin);
  auto &l = r.lut;
  l.address = reinterpret_cast<uint64_t>(d_acc);
  l.glwe_dimension = glwe_dimension;
  l.polynomial_size = polynomial_size;
  l.input_message_modulus = input_message_modulus;
  l.input_carry_modulus = input_carry_modulus;
  l.output_message_modulus = output_message_modulus;
  l.output_carry_modulus = output_carry_modulus;
  l.encoded = encoded;

  // Run-length encode the body: constant on each box, so ~2p runs.
  Torus const *body = h_acc + (size_t)glwe_dimension * polynomial_size;
  for (uint32_t j = 0; j < polynomial_size; j++) {
    uint64_t value = (uint64_t)body[j];
    if (!l.body_runs.empty() && l.body_runs.back().second == value)
      l.body_runs.back().first++;
    else
      l.body_runs.emplace_back(1, value);
  }
  Trace::get().push(std::move(r));
}

} // namespace verification

#endif // VERIFICATION_TRACE
#endif // CUDA_VERIFICATION_TRACE_H
