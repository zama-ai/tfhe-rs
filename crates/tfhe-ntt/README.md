tfhe-ntt is a pure Rust high performance Number Theoretic Transform library that processes
vectors of sizes that are powers of two.

This library provides three kinds of NTT:
- The prime NTT computes the transform in a field $\mathbb{Z}/p \mathbb{Z}$
  with $p$ prime, allowing for arithmetic operations on the polynomial modulo $p$.
- The native NTT internally computes the transform of the first kind with
  several primes, allowing the simulation of arithmetic modulo the product of
  those primes, and truncates the
result when the inverse transform is desired. The truncated result is guaranteed to be as if
the computations were performed with wrapping arithmetic, as long as the full integer result
would have be smaller than half the product of the primes, in absolute value. It is guaranteed
to be suitable for multiplying two polynomials with arbitrary coefficients, and returns the
result in wrapping arithmetic.
- The native binary NTT is similar to the native NTT, but is optimized for the case where one
of the operands of the multiplication has coefficients in $\lbrace 0, 1 \rbrace$.

# Rust requirements
tfhe-ntt requires a Rust version >= 1.67.0.

# Features

- `std` (default): This enables runtime arch detection for accelerated SIMD instructions.
- `nightly`: This enables unstable Rust features to further speed up the NTT, by enabling
AVX512 instructions on CPUs that support them. This feature requires a nightly Rust
toolchain.

# Example

```rust
use tfhe_ntt::prime32::Plan;

const N: usize = 32;
let p = 1062862849;
let plan = Plan::try_new(N, p).unwrap();

let data = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31,
];

let mut transformed_fwd = data;
plan.fwd(&mut transformed_fwd);

let mut transformed_inv = transformed_fwd;
plan.inv(&mut transformed_inv);

for (&actual, expected) in transformed_inv.iter().zip(data.iter().map(|x| x * N as u32)) {
    assert_eq!(expected, actual);
}
```

More examples can be found in the `examples` directory.

- `mul_poly_prime.rs`: Negacyclic polynomial multiplication with a prime modulus.
Run the example with `cargo run --example mul_poly_prime`.
- `mul_poly_native.rs`: Negacyclic polynomial multiplication with a native modulus (`2^32`, `2^64`, or `2^128`).
Run the example with `cargo run --example mul_poly_native`.

# Benchmarks

Benchmarks can be executed with `cargo bench`. If a nightly toolchain is
available, then AVX512 acceleration can be enabled by passing the
`--features=nightly` flag.
