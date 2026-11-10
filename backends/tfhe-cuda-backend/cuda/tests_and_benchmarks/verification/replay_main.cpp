// Replays verification traces on plaintexts and checks them (no GPU needed).
//
//   usage: verification_replay [--iterations N] [--seed S] [--threads T]
//                              [--all] <trace>...
//
// For every trace: analyses it once (the findings), runs its value program on
// N inputs (random and edge cases, sampled within the claimed input degrees),
// compares the outputs with a reference implementation of the op, and prints
// the findings with the largest unsound values the inputs reached. Findings
// that only follow from an earlier unsound claim are counted, and listed with
// --all.
//
// The inputs are split between T OpenMP threads (default: all cores). Input
// number i only depends on (seed, i), so the report is the same for any T.
//
// Exit code: 0 clean, 1 unsound metadata found, 2 wrong results or a trace
// that cannot be replayed (missing hook, unknown LUT, ...).
#include "verification/interpreter.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#ifdef _OPENMP
#include <omp.h>
#endif

using namespace verification;
using Values = std::vector<std::vector<uint64_t>>;

namespace {

// ---------------------------------------------------------------------------
// Reference results
// ---------------------------------------------------------------------------

// outputFlag (integer/integer.h), kept here so this tool needs no CUDA header.
enum { FLAG_NONE = 0, FLAG_OVERFLOW = 1, FLAG_CARRY = 2 };

/// add_and_propagate_single_carry, op args {requested_flag, uses_carry,
/// num_blocks}; inputs {lhs, rhs[, carry_in]}; outputs {lhs[, carry_out]}.
/// Block-wise ripple addition, so any number of blocks works.
void reference_add_and_propagate(OpInfo const &op, Values const &in,
                                 Values &out) {
  uint64_t msg = op.space.message_modulus;
  uint64_t flag = op.args.at(0), uses_carry = op.args.at(1);
  auto const &a = in.at(0), &b = in.at(1);
  uint64_t carry = uses_carry ? in.at(2).at(0) : 0;

  // Signed overflow: carry into the top bit of the last block differs from
  // the carry out of it.
  uint64_t low_mask = msg / 2 - 1, top_shift = 0;
  while ((uint64_t(1) << (top_shift + 1)) < msg)
    top_shift++;
  out.resize(flag == FLAG_NONE ? 1 : 2);
  auto &sum = out[0];
  sum.resize(a.size());
  uint64_t carry_into_top = 0;
  for (size_t i = 0; i < a.size(); i++) {
    if (i + 1 == a.size())
      carry_into_top =
          ((a[i] & low_mask) + (b[i] & low_mask) + carry) >> top_shift;
    uint64_t t = a[i] + b[i] + carry;
    sum[i] = t % msg;
    carry = t / msg;
  }
  if (flag == FLAG_CARRY)
    out[1].assign(1, carry);
  else if (flag == FLAG_OVERFLOW)
    out[1].assign(1, carry_into_top != carry ? 1u : 0u);
}

/// Writes the expected outputs of the op on `in` into `out`.
using Reference = void (*)(OpInfo const &, Values const &, Values &);
const std::map<std::string, Reference> kReferences = {
    {"add_and_propagate_single_carry", reference_add_and_propagate},
};

// ---------------------------------------------------------------------------
// Inputs: every block value stays within its claimed degree.
// ---------------------------------------------------------------------------

/// splitmix64, seeded per input: input i only depends on (seed, i), whatever
/// thread draws it.
struct SplitMix64 {
  uint64_t state;
  uint64_t operator()() {
    uint64_t z = (state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
  }
};

SplitMix64 input_rng(uint64_t seed, uint64_t iteration) {
  SplitMix64 mix{seed};
  return {mix() ^ (iteration * 0xd1342543de82ef95ull)};
}

/// Fills `in` (reusing its buffers) with the inputs of `iteration`;
/// `max_values` are the claimed degrees of the flattened input blocks.
void sample_inputs(OpInfo const &op, std::vector<uint64_t> const &max_values,
                   uint64_t iteration, SplitMix64 &rng, Values &in) {
  auto rand_upto = [&](uint64_t max) { return rng() % (max + 1); };

  in.resize(op.input_sizes.size());
  size_t flat = 0;
  for (size_t k = 0; k < op.input_sizes.size(); k++) {
    in[k].clear();
    for (size_t i = 0; i < op.input_sizes[k]; i++, flat++) {
      uint64_t max = max_values.at(flat);
      uint64_t v;
      switch (iteration % 5) {
      case 1: // all maximal: every block generates
        v = max;
        break;
      case 2: // all zero
        v = 0;
        break;
      case 3: // second input completes the first: long propagate chains
        v = k == 1 ? max - std::min(max, in[0].at(i)) : rand_upto(max);
        break;
      case 4: // maximal first input, sparse second: one carry ripples far
        v = k == 0 ? max
                   : (rng() % op.input_sizes[k] == 0 ? rand_upto(max) : 0);
        break;
      default:
        v = rand_upto(max);
      }
      in[k].push_back(v);
    }
  }
}

std::string join(std::vector<uint64_t> const &v) {
  std::string s;
  for (size_t i = 0; i < v.size(); i++)
    s += (i ? "," : "") + std::to_string(v[i]);
  return s;
}

// ---------------------------------------------------------------------------
// One trace
// ---------------------------------------------------------------------------

struct WrongResult {
  uint64_t iteration;
  Values in, out, expected;
};

int replay(const char *path, uint64_t iterations, uint64_t seed,
           bool show_all) {
  Interpreter interpreter(read_trace(path));
  auto const &op = interpreter.op();
  std::printf("%s  op=%s args=[%s]\n", path, op.label.c_str(),
              join(op.args).c_str());

  auto ref = kReferences.find(op.label);
  Reference reference = ref == kReferences.end() ? nullptr : ref->second;
  std::vector<uint64_t> max_values;
  for (auto const &m : op.input_claims)
    max_values.push_back(m.degree);

  // Each thread runs a contiguous range of inputs with its own Execution and
  // buffers, keeps its first 3 wrong results, then merges into the totals.
  uint64_t wrong = 0;
  std::vector<WrongResult> examples;
#pragma omp parallel
  {
    auto execution = interpreter.new_execution();
    Values in, expected;
    uint64_t my_wrong = 0;
    std::vector<WrongResult> my_examples;
#pragma omp for schedule(static)
    for (int64_t it = 0; it < (int64_t)iterations; it++) {
      auto rng = input_rng(seed, it);
      sample_inputs(op, max_values, it, rng, in);
      auto const &out = interpreter.run(in, execution);
      if (!reference)
        continue;
      reference(op, in, expected);
      if (out != expected && my_wrong++ < 3)
        my_examples.push_back({(uint64_t)it, in, out, expected});
    }
#pragma omp critical
    {
      interpreter.merge(execution);
      wrong += my_wrong;
      examples.insert(examples.end(), my_examples.begin(), my_examples.end());
    }
  }

  // The 3 lowest wrong inputs overall: each thread's first ones are its
  // lowest.
  std::sort(examples.begin(), examples.end(),
            [](WrongResult const &a, WrongResult const &b) {
              return a.iteration < b.iteration;
            });
  for (size_t i = 0; i < std::min<size_t>(3, examples.size()); i++) {
    std::printf("  WRONG RESULT on inputs:");
    for (auto const &v : examples[i].in)
      std::printf(" [%s]", join(v).c_str());
    std::printf("\n    got     :");
    for (auto const &v : examples[i].out)
      std::printf(" [%s]", join(v).c_str());
    std::printf("\n    expected:");
    for (auto const &v : examples[i].expected)
      std::printf(" [%s]", join(v).c_str());
    std::printf("\n");
  }
  if (!reference)
    std::printf("  result: no reference for this op, findings only\n");
  else
    std::printf("  result: %llu/%llu inputs correct\n",
                (unsigned long long)(iterations - wrong),
                (unsigned long long)iterations);

  // One line per (record, kind): number of blocks and the worst example.
  std::map<std::pair<uint64_t, int>, std::vector<Finding>> grouped;
  auto const &findings = interpreter.findings();
  size_t inherited = 0;
  for (auto const &f : findings.list()) {
    if (f.inherited && !show_all) {
      inherited++;
      continue;
    }
    grouped[{f.seq, (int)f.kind}].push_back(f);
  }
  for (auto const &group : grouped) {
    auto const &fs = group.second;
    auto worst = fs.front();
    for (auto const &f : fs)
      if (f.degree_bound > worst.degree_bound || f.witness > worst.witness)
        worst = f;
    std::printf("  %-6s #%-4llu %s%s\n         %s in %s, %zu block(s), e.g. %s",
                is_error(worst.kind)                       ? "ERROR"
                : worst.kind == FindingKind::PADDING_INPUT ? "INFO"
                                                           : "FIND",
                (unsigned long long)worst.seq, finding_name(worst.kind),
                worst.inherited ? " (inherited)" : "",
                kernel_name(worst.kernel), worst.origin.c_str(), fs.size(),
                worst.block.c_str());
    switch (worst.kind) {
    case FindingKind::STALE_CLAIM:
    case FindingKind::DEGREE_CLAIM:
    case FindingKind::NOISE_CLAIM:
      std::printf(": claims degree %llu / noise %llu, derived %llu / %llu",
                  (unsigned long long)worst.claimed_degree,
                  (unsigned long long)worst.claimed_noise,
                  (unsigned long long)worst.degree_bound,
                  (unsigned long long)worst.noise_bound);
      if (worst.witness)
        std::printf(", value %llu seen", (unsigned long long)worst.witness);
      break;
    case FindingKind::NOISE_LIMIT:
      std::printf(": noise %llu > max %llu",
                  (unsigned long long)worst.noise_bound,
                  (unsigned long long)worst.claimed_noise);
      break;
    case FindingKind::PADDING_INPUT:
      std::printf(": reachable up to %llu >= p",
                  (unsigned long long)worst.degree_bound);
      if (worst.witness)
        std::printf(", value %llu seen", (unsigned long long)worst.witness);
      break;
    default:
      break;
    }
    std::printf("\n");
  }
  if (inherited)
    std::printf("  (+%zu inherited finding(s), from the unsound claims above; "
                "--all lists them)\n",
                inherited);
  if (findings.has_errors() || wrong)
    return 2;
  return findings.has_root_findings() ? 1 : 0;
}
} // namespace

int main(int argc, char **argv) {
  uint64_t iterations = 1000, seed = 7;
  bool show_all = false;
  std::vector<const char *> traces;
  for (int i = 1; i < argc; i++) {
    if (!std::strcmp(argv[i], "--iterations") && i + 1 < argc)
      iterations = std::strtoull(argv[++i], nullptr, 10);
    else if (!std::strcmp(argv[i], "--seed") && i + 1 < argc)
      seed = std::strtoull(argv[++i], nullptr, 10);
    else if (!std::strcmp(argv[i], "--threads") && i + 1 < argc) {
      int threads = std::atoi(argv[++i]);
#ifdef _OPENMP
      if (threads > 0)
        omp_set_num_threads(threads);
#else
      (void)threads;
#endif
    } else if (!std::strcmp(argv[i], "--all"))
      show_all = true;
    else
      traces.push_back(argv[i]);
  }
  if (traces.empty()) {
    std::fprintf(stderr,
                 "usage: %s [--iterations N] [--seed S] [--threads T] [--all] "
                 "<trace>...\n",
                 argv[0]);
    return 2;
  }
  int status = 0;
  for (auto const *t : traces)
    status = std::max(status, replay(t, iterations, seed, show_all));
  return status;
}
