#ifndef CUDA_VERIFICATION_INTERPRETER_H
#define CUDA_VERIFICATION_INTERPRETER_H

// Replays a verification trace on plaintexts (pure C++, no CUDA).
//
// The work is split in two passes, since only the values depend on the
// inputs:
//
//   trace ──► analysis (once, in the constructor) ──► Findings
//                │  shadow memory: address → plain::Block (reachable values,
//                │  noise) + the degree / noise the GPU claimed
//                ▼
//             value program: SSA ops on value slots ─┐
//                                                     │
//   input values ──► run() (per input) ───────────────┴──► output values,
//                    executes the program, then the        compared by the
//                    witness checks of unsound claims      caller
//
// Reachable value sets, noise levels and claim checks are derived from the
// claimed input degrees, the same for every input, so the analysis runs once.
// It compiles each write into one op of the value program; every op writes a
// fresh slot, so records keep their parallel-assignment semantics and a
// MEMCPY just aliases its source slot. LUTs become tables over Z_{2p}. An
// unsound claim adds a witness check on the slot it was made on: run() then
// records the largest value seen above the claim ("value N seen").
//
// Every block address goes through:
//
//   (absent) --ALLOC/BEGIN--> alive --FREE--> dead
//
// and reading an absent or dead block is reported: either a leaf without a
// hook wrote it, or the algorithm reads freed memory.
//
// Claims are checked where they are made: a degree / noise level the host
// code writes on a block (meta_out of the record that wrote it, or a meta_in
// that differs from the last claim seen) is compared with the plaintext
// Block. A MEMCPY that copies the source claim along with the value does not
// make a new claim, so a wrong claim is reported once, where it appears.
//
// Unsound claims are attributed to their root cause:
// - STALE_CLAIM: the record wrote the block but left its claim unchanged,
//   i.e. the leaf does not update the metadata at all;
// - an unsound claim computed from inputs whose claims were already unsound
//   is marked `inherited` (the leaf's rule may be right, its inputs are not).
//   PBS outputs are never inherited: their claim comes from the LUT.

#include "verification/plain_kernels.h"
#include "verification/trace_format.h"
#include <algorithm>
#include <map>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace verification {

enum class FindingKind {
  // Errors: the trace cannot be replayed faithfully.
  READ_ABSENT_BLOCK, // read of a block no record wrote (missing hook)
  READ_DEAD_BLOCK,   // read of a freed block
  UNKNOWN_LUT,       // PBS on an accumulator no LUT_DEF recorded
  NO_TWIN,           // record kind / LUT without a plaintext twin yet
  // Unsound metadata.
  STALE_CLAIM,  // block written, claim left unchanged, and now unsound
  DEGREE_CLAIM, // claimed degree < max reachable value
  NOISE_CLAIM,  // claimed noise level < derived noise level
  NOISE_LIMIT,  // PBS input noise level above the parameter set maximum
  // Information.
  PADDING_INPUT, // PBS input may reach the padding bit (value >= p)
};

inline const char *finding_name(FindingKind kind) {
  switch (kind) {
  case FindingKind::READ_ABSENT_BLOCK:
    return "read-absent-block";
  case FindingKind::READ_DEAD_BLOCK:
    return "read-dead-block";
  case FindingKind::UNKNOWN_LUT:
    return "unknown-lut";
  case FindingKind::NO_TWIN:
    return "no-plaintext-twin";
  case FindingKind::STALE_CLAIM:
    return "metadata-not-updated";
  case FindingKind::DEGREE_CLAIM:
    return "degree-claim-too-low";
  case FindingKind::NOISE_CLAIM:
    return "noise-claim-below-bound";
  case FindingKind::NOISE_LIMIT:
    return "noise-above-limit";
  case FindingKind::PADDING_INPUT:
    return "pbs-input-uses-padding";
  }
  return "unknown";
}

inline bool is_error(FindingKind kind) {
  return kind == FindingKind::READ_ABSENT_BLOCK ||
         kind == FindingKind::READ_DEAD_BLOCK ||
         kind == FindingKind::UNKNOWN_LUT || kind == FindingKind::NO_TWIN;
}

struct Finding {
  FindingKind kind;
  uint64_t seq;       // record where it was found
  Kernel kernel;      // record kind
  std::string origin; // leaf host function
  std::string block;  // "alloc#<seq>[<i>]" or the address
  // Claims vs derived metadata (claim / bound); unused fields stay 0.
  uint64_t claimed_degree = 0;
  uint64_t degree_bound = 0;
  uint64_t claimed_noise = 0;
  uint64_t noise_bound = 0;
  // Largest value seen above the claimed degree over all runs (0: not
  // witnessed).
  uint64_t witness = 0;
  bool inherited = false;
};

/// Findings of one trace, merged on (kind, record, block). Each has a stable
/// id, used by run() to record witnesses.
class Findings {
public:
  size_t add(Finding finding) {
    auto key = std::make_tuple((int)finding.kind, finding.seq, finding.block);
    auto it = ids_.find(key);
    if (it != ids_.end()) {
      witness(it->second, finding.witness);
      return it->second;
    }
    ids_.emplace(key, list_.size());
    list_.push_back(std::move(finding));
    return list_.size() - 1;
  }

  size_t size() const { return list_.size(); }

  void witness(size_t id, uint64_t value) {
    list_[id].witness = std::max(list_[id].witness, value);
  }

  /// Sorted by record (i.e. by first occurrence), then kind and block.
  std::vector<Finding> list() const {
    std::vector<Finding> out;
    for (auto const &entry : ids_)
      out.push_back(list_[entry.second]);
    std::stable_sort(
        out.begin(), out.end(),
        [](Finding const &a, Finding const &b) { return a.seq < b.seq; });
    return out;
  }

  bool has_root_findings() const {
    for (auto const &f : list_)
      if (!f.inherited)
        return true;
    return false;
  }

  bool has_errors() const {
    for (auto const &f : list_)
      if (is_error(f.kind))
        return true;
    return false;
  }

private:
  std::map<std::tuple<int, uint64_t, std::string>, size_t> ids_;
  std::vector<Finding> list_;
};

/// What BEGIN declares about the op.
struct OpInfo {
  std::string label;
  plain::Space space;
  std::vector<uint64_t> args;          // op args after the moduli
  std::vector<size_t> input_sizes;     // blocks of each BEGIN buffer
  std::vector<MetaEntry> input_claims; // claimed input metadata
};

class Interpreter {
public:
  /// @brief Parses the op from BEGIN, then analyses the trace (findings) and
  /// compiles its value program.
  explicit Interpreter(std::vector<TraceRecord> records)
      : records_(std::move(records)) {
    for (auto const &r : records_) {
      if (r.kernel != Kernel::BEGIN)
        continue;
      if (r.args.size() < 2)
        format_error("BEGIN without moduli", r.label);
      op_.label = r.label;
      op_.space = {r.args[0], r.args[1]};
      op_.args.assign(r.args.begin() + 2, r.args.end());
      for (auto const &buf : r.buffers)
        op_.input_sizes.push_back(buf.size());
      op_.input_claims = r.meta_in;
      analyze();
      return;
    }
    format_error("trace has no BEGIN record", "");
  }

  OpInfo const &op() const { return op_; }
  std::vector<TraceRecord> const &records() const { return records_; }
  /// Findings of the analysis, with the witnesses merged so far.
  Findings const &findings() const { return findings_; }

  /// State of run(), one per thread: value slots, outputs and the largest
  /// value each finding's watch saw. Reused across inputs.
  struct Execution {
    std::vector<uint64_t> slots;
    std::vector<uint64_t> witnesses; // by finding id
    std::vector<std::vector<uint64_t>> outputs;
  };

  Execution new_execution() const {
    Execution e;
    e.slots.assign(program_.size(), 0);
    e.witnesses.assign(findings_.size(), 0);
    for (auto const &buf : end_slots_)
      e.outputs.emplace_back(buf.size());
    return e;
  }

  /// @brief Replays the trace with inputs[k][i] as the value of block i of
  /// the k-th BEGIN buffer. Returns the values of the END buffers (stored in
  /// `e`). Const: threads may run it concurrently, each with its own `e`.
  std::vector<std::vector<uint64_t>> const &
  run(std::vector<std::vector<uint64_t>> const &inputs, Execution &e) const {
    if (inputs.size() != op_.input_sizes.size())
      format_error("wrong number of input buffers", op_.label);
    for (size_t k = 0; k < inputs.size(); k++)
      if (inputs[k].size() != op_.input_sizes[k])
        format_error("wrong number of input blocks", op_.label);

    // Every op writes a fresh slot, so ops run in order without temporaries.
    uint64_t m = op_.space.modulus();
    auto &v = e.slots;
    for (auto const &o : program_) {
      switch (o.code) {
      case Code::CONST:
        v[o.dst] = o.k % m;
        break;
      case Code::INPUT:
        v[o.dst] = inputs[o.a][o.b] % m;
        break;
      case Code::ADD:
        v[o.dst] = (v[o.a] + v[o.b]) % m;
        break;
      case Code::ADD_CONST:
        v[o.dst] = (v[o.a] + o.k) % m;
        break;
      case Code::PACK:
        v[o.dst] = (v[o.a] * o.k + v[o.b]) % m;
        break;
      case Code::LUT:
        v[o.dst] = tables_[o.k][v[o.a]];
        break;
      }
    }
    for (auto const &w : watches_)
      if (v[w.slot] > w.threshold)
        e.witnesses[w.finding] = std::max(e.witnesses[w.finding], v[w.slot]);

    for (size_t k = 0; k < end_slots_.size(); k++)
      for (size_t i = 0; i < end_slots_[k].size(); i++)
        e.outputs[k][i] = v[end_slots_[k][i]];
    return e.outputs;
  }

  /// Adds the witnesses an Execution saw to findings().
  void merge(Execution const &e) {
    for (size_t id = 0; id < e.witnesses.size(); id++)
      findings_.witness(id, e.witnesses[id]);
  }

private:
  // --- value program ---------------------------------------------------------

  // dst = f(a, b, k), values in Z_{2p} of the op space.
  enum class Code : uint8_t {
    CONST,     // k
    INPUT,     // inputs[a][b]
    ADD,       // v[a] + v[b]
    ADD_CONST, // v[a] + k
    PACK,      // v[a] * k + v[b]
    LUT,       // tables_[k][v[a]]
  };
  struct Op {
    Code code;
    uint32_t dst, a, b;
    uint64_t k;
  };
  // After the program: a value above `threshold` in `slot` witnesses
  // `finding`.
  struct Watch {
    uint32_t slot;
    uint64_t threshold;
    size_t finding;
  };

  uint32_t emit(Code code, uint32_t a = 0, uint32_t b = 0, uint64_t k = 0) {
    // One slot per op: the op's index.
    uint32_t dst = (uint32_t)program_.size();
    program_.push_back({code, dst, a, b, k});
    return dst;
  }

  uint32_t const_slot(uint64_t cleartext) {
    auto it = const_slots_.find(cleartext);
    if (it != const_slots_.end())
      return it->second;
    uint32_t slot = emit(Code::CONST, 0, 0, cleartext);
    const_slots_.emplace(cleartext, slot);
    return slot;
  }

  // Table of a LUT extracted at `offset`, over every value of Z_{2p}.
  uint64_t table_of(uint64_t lut_address, plain::Lut const &lut,
                    uint64_t offset) {
    auto key = std::make_pair(lut_address, offset);
    auto it = table_ids_.find(key);
    if (it != table_ids_.end())
      return it->second;
    std::vector<uint64_t> table(op_.space.modulus());
    for (uint64_t v = 0; v < table.size(); v++)
      table[v] = lut.eval(v, offset);
    tables_.push_back(std::move(table));
    table_ids_.emplace(key, tables_.size() - 1);
    return tables_.size() - 1;
  }

  // --- analysis --------------------------------------------------------------

  // A block of the analysis and the slot holding its value at run time.
  struct Val {
    plain::Block block;
    uint32_t slot = 0;
  };
  using Writes = std::vector<std::pair<uint64_t, Val>>;

  struct Shadow {
    Val val;
    bool alive = false;
    bool has_claim = false;
    bool unsound = false; // its current claim is below the derived metadata
    uint64_t claim_degree = 0;
    uint64_t claim_noise = 0;
  };

  void analyze() {
    for (auto const &r : records_) {
      cur_ = &r;
      step(r);
    }
    cur_ = nullptr;
    mem_.clear();
    allocations_.clear();
    luts_.clear();
  }

  // --- findings ------------------------------------------------------------

  std::string name_of(uint64_t address) const {
    auto it = names_.find(address);
    if (it != names_.end())
      return it->second;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)address);
    return buf;
  }

  Finding make_finding(FindingKind kind, uint64_t address) const {
    Finding f{kind, cur_->seq, cur_->kernel, cur_->origin, name_of(address)};
    return f;
  }

  void report(FindingKind kind, uint64_t address) {
    findings_.add(make_finding(kind, address));
  }

  // --- shadow memory ---------------------------------------------------------

  Val read(uint64_t address) {
    auto it = mem_.find(address);
    if (it == mem_.end() || !it->second.alive) {
      report(it == mem_.end() ? FindingKind::READ_ABSENT_BLOCK
                              : FindingKind::READ_DEAD_BLOCK,
             address);
      return trivial(0);
    }
    reads_unsound_ |= it->second.unsound;
    return it->second.val;
  }

  Val trivial(uint64_t cleartext) {
    return {plain::trivial(op_.space, cleartext), const_slot(cleartext)};
  }

  // Parallel assignment: every read of a record happens before its writes.
  void apply(Writes const &writes) {
    for (auto const &w : writes) {
      auto &shadow = mem_[w.first];
      shadow.val = w.second;
      shadow.alive = true;
    }
  }

  // Compares a claim with the plaintext block, then records it as the
  // block's current claim. `report_it` is false for claims that are not new.
  void claim(uint64_t address, uint64_t degree, uint64_t noise, bool written,
             bool report_it) {
    auto &shadow = mem_[address];
    auto const &b = shadow.val.block;
    bool degree_ok = degree >= b.degree(), noise_ok = noise >= b.noise;
    if (report_it && !(degree_ok && noise_ok)) {
      bool stale = written && shadow.has_claim &&
                   shadow.claim_degree == degree && shadow.claim_noise == noise;
      auto f = make_finding(stale        ? FindingKind::STALE_CLAIM
                            : !degree_ok ? FindingKind::DEGREE_CLAIM
                                         : FindingKind::NOISE_CLAIM,
                            address);
      f.claimed_degree = degree;
      f.degree_bound = b.degree();
      f.claimed_noise = noise;
      f.noise_bound = b.noise;
      f.inherited = !stale && reads_unsound_ &&
                    cur_->kernel != Kernel::PROGRAMMABLE_BOOTSTRAP;
      watches_.push_back(
          {shadow.val.slot, degree, findings_.add(std::move(f))});
    }
    shadow.has_claim = true;
    shadow.unsound = !(degree_ok && noise_ok);
    shadow.claim_degree = degree;
    shadow.claim_noise = noise;
  }

  // Checks the claims a record makes. `written` are the blocks it wrote;
  // `inherited` maps copied blocks to the claim of their source.
  void
  check_claims(std::vector<MetaEntry> const &meta,
               std::unordered_set<uint64_t> const &written,
               std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> const
                   &inherited = {}) {
    for (auto const &m : meta) {
      auto it = mem_.find(m.block);
      if (it == mem_.end() || !it->second.alive)
        continue;
      auto const &shadow = it->second;
      auto inh = inherited.find(m.block);
      bool copied_claim = inh != inherited.end() &&
                          inh->second.first == m.degree &&
                          inh->second.second == m.noise_level;
      bool new_claim = !shadow.has_claim || shadow.claim_degree != m.degree ||
                       shadow.claim_noise != m.noise_level;
      bool was_written = written.count(m.block) != 0;
      claim(m.block, m.degree, m.noise_level, was_written,
            !copied_claim && (was_written || new_claim));
    }
  }

  // --- one record ------------------------------------------------------------

  void step(TraceRecord const &r) {
    auto const &s = op_.space;
    auto const &buf = r.buffers;
    Writes writes;
    reads_unsound_ = false;
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> inherited;

    switch (r.kernel) {
    case Kernel::BEGIN: {
      // Inputs carry the claimed metadata: the caller samples values within
      // the claimed degrees, so the claims are the derived bounds here.
      std::unordered_map<uint64_t, MetaEntry> claims;
      for (auto const &m : r.meta_in)
        claims[m.block] = m;
      for (size_t k = 0; k < buf.size(); k++)
        for (size_t i = 0; i < buf[k].size(); i++) {
          auto const &m = claims.at(buf[k][i]);
          writes.push_back({buf[k][i],
                            {plain::input(s, 0, m.degree, m.noise_level),
                             emit(Code::INPUT, (uint32_t)k, (uint32_t)i)}});
        }
      apply(writes);
      for (auto const &m : r.meta_in)
        claim(m.block, m.degree, m.noise_level, false, false);
      return;
    }
    case Kernel::END: {
      for (auto const &b : buf) {
        end_slots_.emplace_back();
        for (auto address : b)
          end_slots_.back().push_back(read(address).slot);
      }
      check_claims(r.meta_in, {});
      return;
    }
    case Kernel::ALLOC: {
      // args = {base, block_bytes, num_blocks}; blocks are trivial zeros.
      allocations_[r.args.at(0)] = buf.at(0);
      for (size_t i = 0; i < buf[0].size(); i++) {
        writes.push_back({buf[0][i], trivial(0)});
        names_[buf[0][i]] =
            "alloc#" + std::to_string(r.seq) + "[" + std::to_string(i) + "]";
      }
      break;
    }
    case Kernel::FREE: {
      auto it = allocations_.find(r.args.at(0));
      if (it != allocations_.end()) {
        for (auto address : it->second) {
          mem_[address].alive = false;
          mem_[address].has_claim = false;
          mem_[address].unsound = false;
        }
        allocations_.erase(it);
      }
      return;
    }
    case Kernel::LUT_DEF: {
      luts_[r.lut.address] = plain::Lut(r.lut);
      return;
    }
    case Kernel::MEMCPY_BLOCKS: {
      for (size_t i = 0; i < buf.at(0).size(); i++) {
        writes.push_back({buf[0][i], read(buf[1].at(i))});
        auto const &src = mem_[buf[1][i]];
        if (src.has_claim)
          inherited[buf[0][i]] = {src.claim_degree, src.claim_noise};
      }
      break;
    }
    case Kernel::ADDITION: {
      for (size_t i = 0; i < buf.at(0).size(); i++)
        writes.push_back(
            {buf[0][i], add(read(buf[1].at(i)), read(buf[2].at(i)))});
      break;
    }
    case Kernel::SCALAR_ADDITION_INPLACE: {
      for (size_t i = 0; i < buf.at(0).size(); i++) {
        auto a = read(buf[0][i]);
        uint64_t c = r.args.at(i);
        writes.push_back({buf[0][i],
                          {plain::scalar_add(s, a.block, c),
                           emit(Code::ADD_CONST, a.slot, 0, c % s.modulus())}});
      }
      break;
    }
    case Kernel::RADIX_CUMULATIVE_SUM_IN_GROUPS: {
      uint64_t g = r.args.at(0);
      Val sum;
      for (size_t i = 0; i < buf.at(0).size(); i++) {
        auto b = read(buf[1].at(i));
        sum = i % g == 0 ? b : add(sum, b);
        writes.push_back({buf[0][i], sum});
      }
      break;
    }
    case Kernel::RADIX_SUM_IN_GROUPS: {
      uint64_t g = r.args.at(0);
      for (size_t i = 0; i < buf.at(0).size(); i++)
        writes.push_back(
            {buf[0][i], add(read(buf[1].at(i)), read(buf[2].at(i / g)))});
      break;
    }
    case Kernel::SPLIT_SIMULATORS_AND_GROUPING_PGNS: {
      // See Kernel::SPLIT_SIMULATORS_AND_GROUPING_PGNS for the layout.
      uint64_t g = r.args.at(0), one = r.args.at(1) / s.delta();
      auto const &sims = buf.at(0), &pgns = buf.at(1), &src = buf.at(2);
      size_t n = sims.size(), num_groups = (n + g - 1) / g;
      for (size_t b = 0; b < n; b++) {
        if (b % g != 0) {
          writes.push_back({sims[b], read(src.at(b - 1))});
          continue;
        }
        writes.push_back({sims[b], trivial(b == 0 ? 0 : one)});
        if (b / g + 1 < num_groups)
          writes.push_back({pgns.at(b / g), read(src.at(b + g - 1))});
      }
      break;
    }
    case Kernel::PACK_BIVARIATE_BLOCKS: {
      auto const &idx_out = r.indexes.at(0), &idx_in = r.indexes.at(1);
      uint64_t shift = r.args.at(0);
      for (size_t i = 0; i < idx_out.size(); i++) {
        auto lhs = read(buf.at(1).at(idx_in[i]));
        auto rhs = read(buf.at(2).at(idx_in[i]));
        writes.push_back(
            {buf.at(0).at(idx_out[i]),
             {plain::pack_bivariate(s, lhs.block, rhs.block, shift),
              emit(Code::PACK, lhs.slot, rhs.slot, shift % s.modulus())}});
      }
      break;
    }
    case Kernel::PROGRAMMABLE_BOOTSTRAP: {
      pbs(r, writes);
      break;
    }
    default:
      report(FindingKind::NO_TWIN, 0);
      return;
    }

    std::unordered_set<uint64_t> written;
    for (auto const &w : writes)
      written.insert(w.first);
    apply(writes);
    check_claims(r.meta_out, written, inherited);
  }

  Val add(Val const &a, Val const &b) {
    return {plain::add(op_.space, a.block, b.block),
            emit(Code::ADD, a.slot, b.slot)};
  }

  // See Kernel::PROGRAMMABLE_BOOTSTRAP for the argument layout.
  void pbs(TraceRecord const &r, Writes &writes) {
    uint64_t num_blocks = r.args.at(0), num_many_lut = r.args.at(1),
             lut_stride = r.args.at(2), lut_base = r.args.at(3),
             lut_words = r.args.at(4);
    auto const &idx_in = r.indexes.at(0), &idx_out = r.indexes.at(1),
               &lut_idx = r.indexes.at(2);
    auto const &out = r.buffers.at(0), &in = r.buffers.at(1);

    // Input claims made since the block was written (op code may set
    // degrees directly) are checked first.
    check_claims(r.meta_in, {});

    for (uint64_t i = 0; i < num_blocks; i++) {
      uint64_t address = in.at(idx_in.at(i));
      auto input = read(address);
      auto const &block = input.block;
      if (block.noise > plain::max_noise_level(op_.space)) {
        auto f = make_finding(FindingKind::NOISE_LIMIT, address);
        f.claimed_noise = plain::max_noise_level(op_.space);
        f.noise_bound = block.noise;
        findings_.add(std::move(f));
      }
      if (block.degree() >= op_.space.p()) {
        auto f = make_finding(FindingKind::PADDING_INPUT, address);
        f.claimed_degree = op_.space.p() - 1;
        f.degree_bound = block.degree();
        watches_.push_back(
            {input.slot, op_.space.p() - 1, findings_.add(std::move(f))});
      }

      uint64_t lut_address = lut_base + lut_idx.at(i) * lut_words * 8;
      auto lut = luts_.find(lut_address);
      if (lut == luts_.end() || !lut->second.supported()) {
        report(lut == luts_.end() ? FindingKind::UNKNOWN_LUT
                                  : FindingKind::NO_TWIN,
               address);
        continue;
      }
      for (uint64_t slot = 0; slot < num_many_lut; slot++) {
        uint64_t offset = slot * lut_stride;
        writes.push_back({out.at(slot * num_blocks + idx_out.at(i)),
                          {lut->second.apply(block, offset),
                           emit(Code::LUT, input.slot, 0,
                                table_of(lut_address, lut->second, offset))}});
      }
    }
  }

  std::vector<TraceRecord> records_;
  OpInfo op_;
  Findings findings_;

  // Value program, built by the analysis.
  std::vector<Op> program_;
  std::vector<std::vector<uint64_t>> tables_;
  std::vector<Watch> watches_;
  std::vector<std::vector<uint32_t>> end_slots_;
  std::map<std::pair<uint64_t, uint64_t>, uint64_t> table_ids_;
  std::unordered_map<uint64_t, uint32_t> const_slots_;

  // Analysis state, cleared once it is done.
  std::unordered_map<uint64_t, Shadow> mem_;
  std::unordered_map<uint64_t, std::vector<uint64_t>> allocations_;
  std::unordered_map<uint64_t, plain::Lut> luts_;
  std::unordered_map<uint64_t, std::string> names_;
  TraceRecord const *cur_ = nullptr;
  bool reads_unsound_ = false; // the current record read an unsound claim
};

} // namespace verification

#endif // CUDA_VERIFICATION_INTERPRETER_H
