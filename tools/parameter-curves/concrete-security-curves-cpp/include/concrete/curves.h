// Part of the Concrete Compiler Project, under the BSD3 License with Zama
// Exceptions. See
// https://github.com/zama-ai/concrete-compiler-internal/blob/main/LICENSE.txt
// for license information.

#ifndef CONCRETELANG_SUPPORT_V0CURVES_H_
#define CONCRETELANG_SUPPORT_V0CURVES_H_

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>

namespace concrete {

enum KeyFormat {
  BINARY,
};

/// @brief SecurityCurves represents a curves of security
struct SecurityCurve {
  /// @brief Number of bits of security
  int bits;
  /// @brief A term of the curve
  double slope;
  /// @brief A term of the curve
  double bias;
  /// @brief The minimal secure n
  int minimalLweDimension;
  /// @brief The format of the key
  int keyFormat;

  SecurityCurve() = delete;

  SecurityCurve(int bits, double slope, double bias, int minimalLweDimension,
                KeyFormat keyFormat)
      : bits(bits), slope(slope), bias(bias),
        minimalLweDimension(minimalLweDimension), keyFormat(keyFormat) {}

  /// @brief Returns the secure encryption variance for glwe ciphertexts
  /// @param glweDimension The dimension of the glwe
  /// @param polynomialSize The size of the polynom of the glwe
  /// @param logQ The log of q
  /// @return The secure encryption variances
  double getVariance(int glweDimension, int polynomialSize, int logQ) {
    auto size = glweDimension * polynomialSize;
    if (size < minimalLweDimension) {
      return NAN;
    }
    auto a = std::pow(2, (slope * size + bias) * 2);
    auto b = std::pow(2, -2 * (logQ - 2));
    return a > b ? a : b;
  }
};

#include "curves.gen.h"

/// @brief Return the security curve for a given level and a key format.
/// @param bitsOfSecurity The number of bits of security
/// @param keyFormat The format of the key
/// @return The security curve or nullptr if the curve is not found.
SecurityCurve *getSecurityCurve(int bitsOfSecurity, KeyFormat keyFormat) {
  for (size_t i = 0; i < curvesLen; i++) {
    if (curves[i].bits == bitsOfSecurity && curves[i].keyFormat == keyFormat)
      return &curves[i];
  }
  return nullptr;
}

} // namespace concrete

#endif
