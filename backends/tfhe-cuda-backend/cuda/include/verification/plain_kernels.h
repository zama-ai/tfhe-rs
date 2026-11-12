#ifndef CUDA_VERIFICATION_PLAIN_KERNELS_H
#define CUDA_VERIFICATION_PLAIN_KERNELS_H

// Plaintext twins of the GPU integer kernels (see verification/trace.h for
// the records that name them). Pure C++, no CUDA: the interpreter replays a
// trace by calling these on plaintext blocks instead of ciphertexts.
//
// A ciphertext block becomes a plaintext Block: the value it encrypts, plus
// the set of values it can take and the noise level the twins derive from the
// input blocks, independently of what the GPU host code claims.
//
//   ciphertext block (2_2)              plaintext Block
//   ┌──────────────────────────┐        ┌───────────────────────────────────┐
//   │ LWE(m * delta), degree d,│  ───►  │ value     = [pad | c1 c0 | m1 m0] │
//   │ noise level n (claimed)  │        │             in Z_{2p}, p = 16     │
//   └──────────────────────────┘        │ reachable = values over all inputs│
//                                       │ degree()  = max(reachable)        │
//                                       │ noise     = noise level (derived) │
//                                       └───────────────────────────────────┘
//
// The reachable set covers every input the trace can run on, so comparing its
// maximum with the claimed degree finds unsound claims without needing the
// input that reaches them; the value then gives a concrete witness. A set in
// Z_{2p} (rather than an integer bound) stays exact when an algorithm wraps a
// value on purpose, e.g. 31 + 1 = 32 = 0 on the torus.

#include "verification/trace_format.h"
#include <algorithm>
#include <bitset>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace verification {
namespace plain {

/// Plaintext space of a parameter set: Z_{2p}, p = message * carry modulus,
/// the extra bit being the padding bit.
struct Space {
  uint64_t message_modulus = 0;
  uint64_t carry_modulus = 0;

  uint64_t p() const { return message_modulus * carry_modulus; }
  uint64_t modulus() const { return 2 * p(); }
  uint64_t delta() const { return (uint64_t(1) << 63) / p(); }
};

/// Noise level after a PBS / of a trivial ciphertext (NoiseLevel in
/// integer_utilities.h).
constexpr uint64_t NOMINAL_NOISE = 1;
constexpr uint64_t ZERO_NOISE = 0;

/// @brief Maximum noise level a PBS input may have, as CHECK_NOISE_LEVEL
/// enforces it in DEBUG builds; UINT64_MAX when the set has no bound there.
inline uint64_t max_noise_level(Space const &space) {
  auto m = space.message_modulus, c = space.carry_modulus;
  if (m == 2 && c == 2)
    return 3;
  if (m == 2 && c == 1)
    return 14;
  if (m == 4 && c == 4)
    return 5;
  if (m == 8 && c == 8)
    return 9;
  return UINT64_MAX;
}

/// Set of values of Z_m, m = 2p <= MAX_MODULUS.
class ValueSet {
public:
  static constexpr uint64_t MAX_MODULUS = 512;

  ValueSet() = default;
  explicit ValueSet(uint64_t modulus) : modulus_(modulus) {
    if (modulus == 0 || modulus > MAX_MODULUS) {
      std::fprintf(stderr, "plain::ValueSet: unsupported modulus %llu\n",
                   (unsigned long long)modulus);
      std::abort();
    }
  }

  static ValueSet single(uint64_t modulus, uint64_t v) {
    ValueSet s(modulus);
    s.bits_.set(v % modulus);
    return s;
  }
  /// {0, ..., max} (all of Z_m if max >= m).
  static ValueSet up_to(uint64_t modulus, uint64_t max) {
    ValueSet s(modulus);
    for (uint64_t v = 0; v <= std::min(max, modulus - 1); v++)
      s.bits_.set(v);
    return s;
  }

  uint64_t modulus() const { return modulus_; }
  bool contains(uint64_t v) const { return bits_.test(v % modulus_); }
  uint64_t max() const {
    for (uint64_t v = modulus_; v-- > 0;)
      if (bits_.test(v))
        return v;
    return 0;
  }

  /// {f(v) mod m : v in this}, with f's results in a set of modulus m.
  template <typename F> ValueSet map(uint64_t modulus, F f) const {
    ValueSet out(modulus);
    for (uint64_t v = 0; v < modulus_; v++)
      if (bits_.test(v))
        out.bits_.set(f(v) % modulus);
    return out;
  }
  /// {a + k mod m}.
  ValueSet plus(uint64_t k) const {
    return map(modulus_, [&](uint64_t v) { return v + k; });
  }
  /// {a * k + b mod m : a in this, b in other}.
  ValueSet scaled_plus(uint64_t k, ValueSet const &other) const {
    ValueSet out(modulus_);
    for (uint64_t a = 0; a < modulus_; a++)
      if (bits_.test(a))
        out.bits_ |= other.plus(a * k).bits_;
    return out;
  }

private:
  uint64_t modulus_ = 1;
  std::bitset<MAX_MODULUS> bits_;
};

struct Block {
  uint64_t value = 0;
  ValueSet reachable;
  uint64_t noise = 0;

  uint64_t degree() const { return reachable.max(); }
};

// ---------------------------------------------------------------------------
// Levelled twins: value in Z_{2p}, degree and noise follow the usual rules.
// ---------------------------------------------------------------------------

/// A fresh input block: `value` drawn within the claimed degree.
inline Block input(Space const &s, uint64_t value, uint64_t claimed_degree,
                   uint64_t claimed_noise) {
  return {value % s.modulus(), ValueSet::up_to(s.modulus(), claimed_degree),
          claimed_noise};
}

/// Trivial encryption of a cleartext (memset 0, trivial radix, simulators).
inline Block trivial(Space const &s, uint64_t cleartext) {
  return {cleartext % s.modulus(), ValueSet::single(s.modulus(), cleartext),
          ZERO_NOISE};
}

/// ADDITION, RADIX_SUM_IN_GROUPS, one step of RADIX_CUMULATIVE_SUM_IN_GROUPS.
inline Block add(Space const &s, Block const &a, Block const &b) {
  return {(a.value + b.value) % s.modulus(),
          a.reachable.scaled_plus(1, b.reachable), a.noise + b.noise};
}

/// SCALAR_ADDITION_INPLACE: adds a cleartext to the body, noise unchanged.
inline Block scalar_add(Space const &s, Block const &a, uint64_t cleartext) {
  return {(a.value + cleartext) % s.modulus(), a.reachable.plus(cleartext),
          a.noise};
}

/// PACK_BIVARIATE_BLOCKS: lhs * shift + rhs, the input of a bivariate LUT.
inline Block pack_bivariate(Space const &s, Block const &lhs, Block const &rhs,
                            uint64_t shift) {
  return {(lhs.value * shift + rhs.value) % s.modulus(),
          lhs.reachable.scaled_plus(shift, rhs.reachable),
          lhs.noise * shift + rhs.noise};
}

// ---------------------------------------------------------------------------
// PBS twin
// ---------------------------------------------------------------------------

/// A recorded LUT accumulator, evaluated like a noiseless keyswitch + PBS:
///
///   v ──mod switch──► pos = v * N / p_in (+ extraction offset)
///   out = body[pos]         if pos <  N
///         -body[pos - N]    if pos >= N   (negacyclic: v uses the padding bit)
///   decoded with delta_out = 2^63 / p_out, rounded, in Z_{2 p_out}
///
/// Evaluating the accumulator itself, not the function it was generated from,
/// also checks the encoding (box layout, half-box rotation, delta).
class Lut {
public:
  Lut() = default;
  explicit Lut(LutDef const &def) : def_(def) {
    for (auto const &run : def.body_runs)
      body_.insert(body_.end(), run.first, run.second);
  }

  /// False when the recorded body is not N coefficients, or not encoded
  /// (generate_lookup_table_no_encoding has no plaintext twin yet).
  bool supported() const {
    return def_.encoded && body_.size() == def_.polynomial_size &&
           def_.polynomial_size != 0;
  }

  Space input_space() const {
    return {def_.input_message_modulus, def_.input_carry_modulus};
  }
  Space output_space() const {
    return {def_.output_message_modulus, def_.output_carry_modulus};
  }

  /// @brief Decoded output for input value v, sample-extracted at `offset`.
  uint64_t eval(uint64_t v, uint64_t offset) const {
    uint64_t n = def_.polynomial_size;
    Space in = input_space(), out = output_space();
    uint64_t pos = ((v % in.modulus()) * (n / in.p()) + offset) % (2 * n);
    uint64_t coeff = pos < n ? body_[pos] : uint64_t(0) - body_[pos - n];
    uint64_t delta = out.delta();
    // Rounding wraps modulo 2^64 = 2 p_out * delta, i.e. modulo 2 p_out.
    return ((coeff + delta / 2) / delta) % out.modulus();
  }

  /// @brief PBS on one block: the value and every reachable input value go
  /// through the LUT, the noise is reset.
  Block apply(Block const &in, uint64_t offset) const {
    return {eval(in.value, offset),
            in.reachable.map(output_space().modulus(),
                             [&](uint64_t v) { return eval(v, offset); }),
            NOMINAL_NOISE};
  }

private:
  LutDef def_;
  std::vector<uint64_t> body_;
};

} // namespace plain
} // namespace verification

#endif // CUDA_VERIFICATION_PLAIN_KERNELS_H
