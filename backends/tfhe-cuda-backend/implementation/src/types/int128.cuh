#ifndef CNCRT_INT128_CUH
#define CNCRT_INT128_CUH

// abseil's int128 type
// licensed under Apache license

class uint128 {
public:
  __device__ uint128(uint64_t high, uint64_t low) : hi_(high), lo_(low) {}

  uint64_t lo_;
  uint64_t hi_;
};

class int128 {
public:
  int128() = default;

  __device__ operator unsigned long long() const {
    return static_cast<unsigned long long>(lo_);
  }

  __device__ int128(int64_t high, uint64_t low) : hi_(high), lo_(low) {}

  uint64_t lo_;
  int64_t hi_;
};

__device__ inline uint128 make_uint128(uint64_t high, uint64_t low) {
  return uint128(high, low);
}

template <typename T> __device__ uint128 make_uint128_from_float(T v) {
  if (v >= ldexp(static_cast<T>(1), 64)) {
    uint64_t hi = static_cast<uint64_t>(ldexp(v, -64));
    uint64_t lo = static_cast<uint64_t>(v - ldexp(static_cast<T>(hi), 64));
    return make_uint128(hi, lo);
  }

  return make_uint128(0, static_cast<uint64_t>(v));
}

__device__ inline int128 make_int128(int64_t high, uint64_t low) {
  return int128(high, low);
}

__device__ inline int64_t bitcast_to_signed(uint64_t v) {
  return v & (uint64_t{1} << 63) ? ~static_cast<int64_t>(~v)
                                 : static_cast<int64_t>(v);
}

__device__ inline uint64_t uint128_high64(uint128 v) { return v.hi_; }
__device__ inline uint64_t uint128_low64(uint128 v) { return v.lo_; }

__device__ __forceinline__ uint128 operator-(uint128 val) {
  uint64_t hi = ~uint128_high64(val);
  uint64_t lo = ~uint128_low64(val) + 1;
  if (lo == 0)
    ++hi; // carry
  return make_uint128(hi, lo);
}

template <typename T> __device__ int128 make_int128_from_float(T v) {

  // We must convert the absolute value and then negate as needed, because
  // floating point types are typically sign-magnitude. Otherwise, the
  // difference between the high and low 64 bits when interpreted as two's
  // complement overwhelms the precision of the mantissa.
  uint128 result =
      v < 0 ? -make_uint128_from_float(-v) : make_uint128_from_float(v);

  return make_int128(bitcast_to_signed(uint128_high64(result)),
                     uint128_low64(result));
}

#endif
