#ifndef CUDA_VERIFICATION_TRACE_FORMAT_H
#define CUDA_VERIFICATION_TRACE_FORMAT_H

// Verification trace format, shared by the recorder (trace.h, inside the CUDA
// backend) and the plaintext interpreter (interpreter.h, plain C++). It only
// depends on the standard library, so traces can be replayed on a machine
// without CUDA.
//
// Text format, one record per line (all numbers in lists are hexadecimal):
//
//   #<seq> <KIND> origin=<fn> [label=<op>] [buf<k>=[addr,...]]
//       [idx<k>=[i,...]] [args=[a,...]] [meta_in=[addr:deg/noise,...]]
//       [meta_out=[...]] [LUT_DEF: addr=<a> glwe=<k> N=<n> in=<m>x<c>
//       out=<m>x<c> encoded=<0|1> runs=[count*value,...]]

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace verification {

/// One entry per GPU kernel (or memcpy / memset) launched by a leaf host
/// function. The comment of each value is the plaintext semantics that
/// plain_kernels.h implements; arithmetic is in Z_{2p} (see trace.h).
enum class Kernel : uint8_t {
  // --- Op boundaries ------------------------------------------------------
  // buffers[k] = k-th input ciphertext, seeded by the interpreter.
  // args = {message_modulus, carry_modulus, op args...}; meta_in = claimed
  // metadata.
  BEGIN,
  // buffers[k] = k-th output ciphertext; meta_in = claimed metadata.
  END,

  // --- Memory lifetime -----------------------------------------------------
  // buffers = {blocks}, args = {base, block_bytes, num_blocks}: a new
  // allocation, memset to 0, i.e. every block is a trivial 0 with noise 0.
  ALLOC,
  // args = {base}: the allocation starting at base is released.
  FREE,

  // --- Data movement -------------------------------------------------------
  // buffers = {dst, src}: dst[i] = src[i].
  MEMCPY_BLOCKS,
  // buffers = {dst}: dst[i] = trivial 0 (noise 0).
  MEMSET_ZERO,
  // buffers = {dst}, args = cleartexts s_i: dst[i] = trivial s_i (noise 0).
  CREATE_TRIVIAL_RADIX,
  // buffers = {dst, src}, indexes[0] = idx: dst[i] = src[idx[i]].
  ALIGN_WITH_INDEXES,
  // buffers = {dst, src}, indexes[0] = idx: dst[idx[i]] = src[i].
  REALIGN_WITH_INDEXES,
  // buffers = {dst, src}, args = {r}: dst[(i + r) % n] = src[i].
  BLOCKS_ROTATE_RIGHT,
  // buffers = {dst, src}, args = {r}: dst[(i - r) mod n] = src[i].
  BLOCKS_ROTATE_LEFT,
  // buffers = {buf}: buf[i] = buf[n - 1 - i].
  BLOCKS_REVERSE_INPLACE,

  // --- Levelled arithmetic (no PBS) ----------------------------------------
  // buffers = {out, a, b}: out[i] = a[i] + b[i].
  ADDITION,
  // buffers = {out, a, single}: out[i] = a[i] + single[0].
  CONSTANT_ADDITION,
  // buffers = {out, a, b}, args = {message_modulus, carry_modulus, degree}:
  // out[i] = a[i] - b[i] + z, z = max(ceil(degree / msg_mod), 1) * msg_mod.
  UNCHECKED_SUB_WITH_CORRECTING_TERM,
  // buffers = {out, in}: out[i] = -in[i].
  NEGATION,
  // buffers = {out, in}, args = {message_modulus}, z = ((2m - 1) / m) * m:
  // out[0] = z - in[0], out[i > 0] = z - (in[i] + z / m).
  NEGATION_WITH_CORRECTING_TERM,
  // buffers = {out, in}, args = torus plaintexts t_i (already scaled by
  // delta): out[i] = in[i] + t_i / delta. A t_i that is not a multiple of
  // delta is reported by the interpreter.
  PLAINTEXT_ADDITION,
  // buffers = {out, in}, args = {t} (torus): out[i] = in[i] + t / delta.
  PLAINTEXT_ADDITION_SCALAR,
  // buffers = {buf}, args = cleartexts s_i: buf[i] += s_i.
  SCALAR_ADDITION_INPLACE,
  // buffers = {buf}: buf[i] += 1.
  ADD_SCALAR_ONE_INPLACE,
  // buffers = {buf}, args = cleartexts s_i: buf[i] -= s_i.
  SCALAR_SUBTRACTION_INPLACE,
  // buffers = {out, in}, args = {c}: out[i] = in[i] * c.
  CLEARTEXT_MULTIPLICATION,
  // buffers = {out, in}, args = cleartexts c_i: out[i] = in[i] * c_i.
  CLEARTEXT_VEC_MULTIPLICATION,
  // buffers = {out, in}, args = {factor}, n = in blocks:
  // out[b] = in[2b] + factor * in[2b + 1]; if n is odd out[n/2] = in[n - 1].
  PACK_BLOCKS,
  // buffers = {out, lhs, rhs}, indexes = {idx_out, idx_in}, args = {shift}:
  // out[idx_out[i]] = lhs[idx_in[i]] * shift + rhs[idx_in[i]].
  PACK_BIVARIATE_BLOCKS,
  // buffers = {out, lhs, single}, indexes = {idx_out, idx_in}, args =
  // {shift}: out[idx_out[i]] = lhs[idx_in[i]] * shift + single[0].
  PACK_BIVARIATE_BLOCKS_WITH_SINGLE_BLOCK,
  // buffers = {dst, src1, src2}, args = {g}: dst[i] = src1[i] + src2[i / g].
  RADIX_SUM_IN_GROUPS,
  // buffers = {dst, src}, args = {g}:
  // dst[i] = sum of src[j] for j in [g * (i / g), i].
  RADIX_CUMULATIVE_SUM_IN_GROUPS,
  // buffers = {simulators, grouping_pgns, src}, args = {g, t} with t the
  // torus value used as "1" (expected: delta). For every block b < n:
  //   b % g != 0          : simulators[b] = src[b - 1]
  //   b == 0              : simulators[0] = trivial 0
  //   b % g == 0, b != 0  : simulators[b] = trivial t / delta
  //   b % g == 0 and b / g + 1 < ceil(n / g):
  //                         grouping_pgns[b / g] = src[b + g - 1]
  SPLIT_SIMULATORS_AND_GROUPING_PGNS,

  // --- Programmable bootstrapping ------------------------------------------
  // Keyswitch + PBS. buffers = {out, in}, indexes = {idx_in, idx_out,
  // lut_idx}, args = {num_blocks, num_many_lut, lut_stride, lut_base,
  // lut_size_in_words}. For i < num_blocks and slot s < num_many_lut:
  //   out[s * num_blocks + idx_out[i]] =
  //     PBS(LUT at lut_base + lut_idx[i] * lut_size_in_words * 8,
  //         in[idx_in[i]], extraction offset s * lut_stride)
  // meta_in holds the claimed metadata of every in[idx_in[i]].
  PROGRAMMABLE_BOOTSTRAP,
  // A LUT accumulator written to the GPU: see LutDef.
  LUT_DEF,

  // Number of kinds, not a record kind.
  COUNT,
};

/// @brief Kernel name, as printed in the text dump.
inline const char *kernel_name(Kernel kernel) {
  switch (kernel) {
  case Kernel::BEGIN:
    return "BEGIN";
  case Kernel::END:
    return "END";
  case Kernel::ALLOC:
    return "ALLOC";
  case Kernel::FREE:
    return "FREE";
  case Kernel::MEMCPY_BLOCKS:
    return "MEMCPY_BLOCKS";
  case Kernel::MEMSET_ZERO:
    return "MEMSET_ZERO";
  case Kernel::CREATE_TRIVIAL_RADIX:
    return "CREATE_TRIVIAL_RADIX";
  case Kernel::ALIGN_WITH_INDEXES:
    return "ALIGN_WITH_INDEXES";
  case Kernel::REALIGN_WITH_INDEXES:
    return "REALIGN_WITH_INDEXES";
  case Kernel::BLOCKS_ROTATE_RIGHT:
    return "BLOCKS_ROTATE_RIGHT";
  case Kernel::BLOCKS_ROTATE_LEFT:
    return "BLOCKS_ROTATE_LEFT";
  case Kernel::BLOCKS_REVERSE_INPLACE:
    return "BLOCKS_REVERSE_INPLACE";
  case Kernel::ADDITION:
    return "ADDITION";
  case Kernel::CONSTANT_ADDITION:
    return "CONSTANT_ADDITION";
  case Kernel::UNCHECKED_SUB_WITH_CORRECTING_TERM:
    return "UNCHECKED_SUB_WITH_CORRECTING_TERM";
  case Kernel::NEGATION:
    return "NEGATION";
  case Kernel::NEGATION_WITH_CORRECTING_TERM:
    return "NEGATION_WITH_CORRECTING_TERM";
  case Kernel::PLAINTEXT_ADDITION:
    return "PLAINTEXT_ADDITION";
  case Kernel::PLAINTEXT_ADDITION_SCALAR:
    return "PLAINTEXT_ADDITION_SCALAR";
  case Kernel::SCALAR_ADDITION_INPLACE:
    return "SCALAR_ADDITION_INPLACE";
  case Kernel::ADD_SCALAR_ONE_INPLACE:
    return "ADD_SCALAR_ONE_INPLACE";
  case Kernel::SCALAR_SUBTRACTION_INPLACE:
    return "SCALAR_SUBTRACTION_INPLACE";
  case Kernel::CLEARTEXT_MULTIPLICATION:
    return "CLEARTEXT_MULTIPLICATION";
  case Kernel::CLEARTEXT_VEC_MULTIPLICATION:
    return "CLEARTEXT_VEC_MULTIPLICATION";
  case Kernel::PACK_BLOCKS:
    return "PACK_BLOCKS";
  case Kernel::PACK_BIVARIATE_BLOCKS:
    return "PACK_BIVARIATE_BLOCKS";
  case Kernel::PACK_BIVARIATE_BLOCKS_WITH_SINGLE_BLOCK:
    return "PACK_BIVARIATE_BLOCKS_WITH_SINGLE_BLOCK";
  case Kernel::RADIX_SUM_IN_GROUPS:
    return "RADIX_SUM_IN_GROUPS";
  case Kernel::RADIX_CUMULATIVE_SUM_IN_GROUPS:
    return "RADIX_CUMULATIVE_SUM_IN_GROUPS";
  case Kernel::SPLIT_SIMULATORS_AND_GROUPING_PGNS:
    return "SPLIT_SIMULATORS_AND_GROUPING_PGNS";
  case Kernel::PROGRAMMABLE_BOOTSTRAP:
    return "PROGRAMMABLE_BOOTSTRAP";
  case Kernel::LUT_DEF:
    return "LUT_DEF";
  case Kernel::COUNT:
    break;
  }
  return "UNKNOWN";
}

/// Device addresses of the blocks a kernel pointer argument can reach.
using BlockArray = std::vector<uint64_t>;

/// Degree and noise level the host code claims for one block.
struct MetaEntry {
  uint64_t block;
  uint64_t degree;
  uint64_t noise_level;
};

/// A LUT accumulator as written to the GPU, recorded from the host buffer
/// right before the copy. Only the GLWE body is kept (the mask is zero); it is
/// run-length encoded since it is constant on each box.
///
/// The interpreter evaluates it like the PBS does on a noiseless input: for a
/// block value v, the modulus-switched body is v * 2N / (2p_in), and the
/// output is the negacyclic coefficient at that position plus the extraction
/// offset, decoded with delta_out = 2^63 / p_out. Recording the accumulator
/// rather than the generating function also checks the encoding itself.
struct LutDef {
  uint64_t address = 0; // device address of the accumulator (GLWE start)
  uint32_t glwe_dimension = 0;
  uint32_t polynomial_size = 0;
  uint32_t input_message_modulus = 0;
  uint32_t input_carry_modulus = 0;
  uint32_t output_message_modulus = 0;
  uint32_t output_carry_modulus = 0;
  // false for generate_lookup_table_no_encoding: raw torus coefficients
  bool encoded = true;
  // (run length, torus value) pairs covering the N body coefficients
  std::vector<std::pair<uint32_t, uint64_t>> body_runs;
};

struct TraceRecord {
  uint64_t seq = 0;
  Kernel kernel = Kernel::BEGIN;
  std::string origin; // leaf host function (__func__)
  std::vector<BlockArray> buffers;
  std::vector<std::vector<uint64_t>> indexes; // read back from the GPU
  std::vector<uint64_t> args;
  std::vector<MetaEntry> meta_in;
  std::vector<MetaEntry> meta_out;
  LutDef lut;        // LUT_DEF only
  std::string label; // BEGIN / END only
};

/// @brief Record kind of a dumped name; Kernel::COUNT if unknown.
inline Kernel kernel_from_name(std::string const &name) {
  for (int k = 0; k < (int)Kernel::COUNT; k++)
    if (name == kernel_name((Kernel)k))
      return (Kernel)k;
  return Kernel::COUNT;
}

// ---------------------------------------------------------------------------
// Text writer
// ---------------------------------------------------------------------------

inline void write_u64_list(FILE *file, const char *name,
                           std::vector<uint64_t> const &values) {
  std::fprintf(file, " %s=[", name);
  for (size_t i = 0; i < values.size(); i++)
    std::fprintf(file, i ? ",0x%llx" : "0x%llx", (unsigned long long)values[i]);
  std::fprintf(file, "]");
}

inline void write_meta(FILE *file, const char *name,
                       std::vector<MetaEntry> const &meta) {
  if (meta.empty())
    return;
  std::fprintf(file, " %s=[", name);
  for (size_t i = 0; i < meta.size(); i++)
    std::fprintf(file, "%s0x%llx:%llu/%llu", i ? "," : "",
                 (unsigned long long)meta[i].block,
                 (unsigned long long)meta[i].degree,
                 (unsigned long long)meta[i].noise_level);
  std::fprintf(file, "]");
}

inline void write_record(FILE *file, TraceRecord const &r) {
  std::fprintf(file, "#%llu %s origin=%s", (unsigned long long)r.seq,
               kernel_name(r.kernel), r.origin.c_str());
  if (!r.label.empty())
    std::fprintf(file, " label=%s", r.label.c_str());
  for (size_t k = 0; k < r.buffers.size(); k++) {
    std::string name = "buf" + std::to_string(k);
    write_u64_list(file, name.c_str(), r.buffers[k]);
  }
  for (size_t k = 0; k < r.indexes.size(); k++) {
    std::string name = "idx" + std::to_string(k);
    write_u64_list(file, name.c_str(), r.indexes[k]);
  }
  if (!r.args.empty())
    write_u64_list(file, "args", r.args);
  write_meta(file, "meta_in", r.meta_in);
  write_meta(file, "meta_out", r.meta_out);
  if (r.kernel == Kernel::LUT_DEF) {
    auto const &l = r.lut;
    std::fprintf(file,
                 " addr=0x%llx glwe=%u N=%u in=%ux%u out=%ux%u encoded=%d "
                 "runs=[",
                 (unsigned long long)l.address, l.glwe_dimension,
                 l.polynomial_size, l.input_message_modulus,
                 l.input_carry_modulus, l.output_message_modulus,
                 l.output_carry_modulus, (int)l.encoded);
    for (size_t i = 0; i < l.body_runs.size(); i++)
      std::fprintf(file, "%s%u*0x%llx", i ? "," : "", l.body_runs[i].first,
                   (unsigned long long)l.body_runs[i].second);
    std::fprintf(file, "]");
  }
  std::fprintf(file, "\n");
}

// ---------------------------------------------------------------------------
// Text reader (the inverse of write_record)
// ---------------------------------------------------------------------------

// Malformed traces are a test-tooling error: report and stop. No exceptions,
// since this header is also compiled by nvcc with --no-exceptions.
[[noreturn]] inline void format_error(std::string const &what,
                                      std::string const &line) {
  std::fprintf(stderr, "verification trace: %s in line: %s\n", what.c_str(),
               line.c_str());
  std::abort();
}

inline uint64_t parse_u64(std::string const &text, int base,
                          std::string const &line) {
  char *end = nullptr;
  uint64_t v = std::strtoull(text.c_str(), &end, base);
  if (text.empty() || *end != '\0')
    format_error("bad number '" + text + "'", line);
  return v;
}

/// Splits "[a,b,c]" into {"a", "b", "c"}; "[]" gives no items.
inline std::vector<std::string> parse_list(std::string const &text,
                                           std::string const &line) {
  if (text.size() < 2 || text.front() != '[' || text.back() != ']')
    format_error("bad list '" + text + "'", line);
  std::vector<std::string> items;
  std::string body = text.substr(1, text.size() - 2);
  size_t start = 0;
  while (start < body.size()) {
    size_t comma = body.find(',', start);
    if (comma == std::string::npos)
      comma = body.size();
    items.push_back(body.substr(start, comma - start));
    start = comma + 1;
  }
  return items;
}

inline std::vector<uint64_t> parse_u64_list(std::string const &text,
                                            std::string const &line) {
  std::vector<uint64_t> out;
  for (auto const &item : parse_list(text, line))
    out.push_back(parse_u64(item, 16, line));
  return out;
}

inline std::vector<MetaEntry> parse_meta(std::string const &text,
                                         std::string const &line) {
  std::vector<MetaEntry> out;
  for (auto const &item : parse_list(text, line)) {
    size_t colon = item.find(':'), slash = item.find('/');
    if (colon == std::string::npos || slash == std::string::npos)
      format_error("bad metadata '" + item + "'", line);
    out.push_back(
        {parse_u64(item.substr(0, colon), 16, line),
         parse_u64(item.substr(colon + 1, slash - colon - 1), 10, line),
         parse_u64(item.substr(slash + 1), 10, line)});
  }
  return out;
}

/// "<a>x<b>" as written for LUT encodings.
inline std::pair<uint32_t, uint32_t>
parse_modulus_pair(std::string const &text, std::string const &line) {
  size_t x = text.find('x');
  if (x == std::string::npos)
    format_error("bad modulus pair '" + text + "'", line);
  return {(uint32_t)parse_u64(text.substr(0, x), 10, line),
          (uint32_t)parse_u64(text.substr(x + 1), 10, line)};
}

inline TraceRecord parse_record(std::string const &line) {
  TraceRecord r;
  std::vector<std::string> tokens;
  size_t start = 0;
  while (start < line.size()) {
    size_t space = line.find(' ', start);
    if (space == std::string::npos)
      space = line.size();
    if (space > start)
      tokens.push_back(line.substr(start, space - start));
    start = space + 1;
  }
  if (tokens.size() < 2 || tokens[0][0] != '#')
    format_error("missing '#seq KIND'", line);
  r.seq = parse_u64(tokens[0].substr(1), 10, line);
  r.kernel = kernel_from_name(tokens[1]);
  if (r.kernel == Kernel::COUNT)
    format_error("unknown record kind '" + tokens[1] + "'", line);

  // Indexed fields (buf<k>, idx<k>) are placed at position k.
  auto at = [&](std::vector<std::vector<uint64_t>> &v, std::string const &key,
                size_t prefix) -> std::vector<uint64_t> & {
    size_t k = parse_u64(key.substr(prefix), 10, line);
    if (v.size() <= k)
      v.resize(k + 1);
    return v[k];
  };
  for (size_t t = 2; t < tokens.size(); t++) {
    size_t eq = tokens[t].find('=');
    if (eq == std::string::npos)
      format_error("bad field '" + tokens[t] + "'", line);
    std::string key = tokens[t].substr(0, eq), val = tokens[t].substr(eq + 1);
    if (key == "origin")
      r.origin = val;
    else if (key == "label")
      r.label = val;
    else if (key.rfind("buf", 0) == 0)
      at(r.buffers, key, 3) = parse_u64_list(val, line);
    else if (key.rfind("idx", 0) == 0)
      at(r.indexes, key, 3) = parse_u64_list(val, line);
    else if (key == "args")
      r.args = parse_u64_list(val, line);
    else if (key == "meta_in")
      r.meta_in = parse_meta(val, line);
    else if (key == "meta_out")
      r.meta_out = parse_meta(val, line);
    else if (key == "addr")
      r.lut.address = parse_u64(val, 16, line);
    else if (key == "glwe")
      r.lut.glwe_dimension = (uint32_t)parse_u64(val, 10, line);
    else if (key == "N")
      r.lut.polynomial_size = (uint32_t)parse_u64(val, 10, line);
    else if (key == "in")
      std::tie(r.lut.input_message_modulus, r.lut.input_carry_modulus) =
          parse_modulus_pair(val, line);
    else if (key == "out")
      std::tie(r.lut.output_message_modulus, r.lut.output_carry_modulus) =
          parse_modulus_pair(val, line);
    else if (key == "encoded")
      r.lut.encoded = parse_u64(val, 10, line) != 0;
    else if (key == "runs")
      for (auto const &item : parse_list(val, line)) {
        size_t star = item.find('*');
        if (star == std::string::npos)
          format_error("bad run '" + item + "'", line);
        r.lut.body_runs.emplace_back(
            (uint32_t)parse_u64(item.substr(0, star), 10, line),
            parse_u64(item.substr(star + 1), 16, line));
      }
    else
      format_error("unknown field '" + key + "'", line);
  }
  return r;
}

/// @brief Reads a trace written by Trace::dump_text.
inline std::vector<TraceRecord> read_trace(const char *path) {
  FILE *file = std::fopen(path, "r");
  if (file == nullptr)
    format_error(std::string("cannot open ") + path, "");
  std::vector<TraceRecord> records;
  std::string line;
  int c;
  while ((c = std::fgetc(file)) != EOF) {
    if (c != '\n') {
      line.push_back((char)c);
      continue;
    }
    if (!line.empty())
      records.push_back(parse_record(line));
    line.clear();
  }
  if (!line.empty())
    records.push_back(parse_record(line));
  std::fclose(file);
  return records;
}

} // namespace verification

#endif // CUDA_VERIFICATION_TRACE_FORMAT_H
