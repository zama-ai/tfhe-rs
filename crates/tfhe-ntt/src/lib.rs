//! tfhe-ntt is a pure Rust high performance number theoretic transform library that processes
//! vectors of sizes that are powers of two.
//!
//! This library provides three kinds of NTT:
//! - The prime NTT computes the transform in a field $\mathbb{Z}/p\mathbb{Z}$ with $p$ prime,
//!   allowing for arithmetic operations on the polynomial modulo $p$.
//! - The native NTT internally computes the transform of the first kind with several primes,
//!   allowing the simulation of arithmetic modulo the product of those primes, and truncates the
//!   result when the inverse transform is desired. The truncated result is guaranteed to be as if
//!   the computations were performed with wrapping arithmetic, as long as the full integer result
//!   would have been smaller than half the product of the primes, in absolute value. It is
//!   guaranteed to be suitable for multiplying two polynomials with arbitrary coefficients, and
//!   returns the result in wrapping arithmetic.
//! - The native binary NTT is similar to the native NTT, but is optimized for the case where one of
//!   the operands of the multiplication has coefficients in $\lbrace 0, 1 \rbrace$.
//!
//! # Features
//!
//! - `std` (default): This enables runtime arch detection for accelerated SIMD instructions.
//! - `nightly`: This enables unstable Rust features to further speed up the NTT, by enabling AVX512
//!   instructions on CPUs that support them. This feature requires a nightly Rust toolchain.
//!
//! # Example
//!
//! ```
//! use tfhe_ntt::prime32::Plan;
//!
//! const N: usize = 32;
//! let p = 1062862849;
//! let plan = Plan::try_new(N, p).unwrap();
//!
//! let data = [
//!     0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
//!     25, 26, 27, 28, 29, 30, 31,
//! ];
//!
//! let mut transformed_fwd = data;
//! plan.fwd(&mut transformed_fwd);
//!
//! let mut transformed_inv = transformed_fwd;
//! plan.inv(&mut transformed_inv);
//!
//! for (&actual, expected) in transformed_inv
//!     .iter()
//!     .zip(data.iter().map(|x| x * N as u32))
//! {
//!     assert_eq!(expected, actual);
//! }
//! ```

#![cfg_attr(
    all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")),
    feature(avx512_target_feature, stdarch_x86_avx512)
)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments, clippy::let_unit_value)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Implementation notes:
///
/// we use `NullaryFnOnce` instead of a closure because we need the `#[inline(always)]`
/// annotation, which doesn't always work with closures for some reason.
///
/// Shoup modular multiplication  
/// <https://pdfs.semanticscholar.org/e000/fa109f1b2a6a3e52e04462bac4b7d58140c9.pdf>
///
/// Lemire modular reduction  
/// <https://lemire.me/blog/2019/02/08/faster-remainders-when-the-divisor-is-a-constant-beating-compilers-and-libdivide/>
///
/// Barrett reduction  
/// <https://arxiv.org/pdf/2103.16400.pdf> Algorithm 8
///
/// Chinese remainder theorem solution:
/// The art of computer programming (Donald E. Knuth), section 4.3.2
#[allow(dead_code)]
fn implementation_notes() {}

use u256_impl::u256;

#[allow(unused_imports)]
use pulp::*;

#[doc(hidden)]
pub mod prime;
mod roots;
mod u256_impl;

/// Fast division by a constant divisor.
pub mod fastdiv;
/// 32bit negacyclic NTT for a prime modulus.
pub mod prime32;
/// 64bit negacyclic NTT for a prime modulus.
pub mod prime64;

/// Negacyclic NTT for multiplying two polynomials with values less than `2^128`.
pub mod native128;
/// Negacyclic NTT for multiplying two polynomials with values less than `2^32`.
pub mod native32;
/// Negacyclic NTT for multiplying two polynomials with values less than `2^64`.
pub mod native64;

/// Negacyclic NTT for multiplying a polynomial with values less than `2^128` with a binary
/// polynomial.
pub mod native_binary128;
/// Negacyclic NTT for multiplying a polynomial with values less than `2^32` with a binary
/// polynomial.
pub mod native_binary32;
/// Negacyclic NTT for multiplying a polynomial with values less than `2^64` with a binary
/// polynomial.
pub mod native_binary64;

pub mod product;

// Fn arguments are (simd, z0, z1, w, w_shoup, p, neg_p, two_p)
trait Butterfly<S: Copy, V: Copy>: Copy + Fn(S, V, V, V, V, V, V, V) -> (V, V) {}
impl<F: Copy + Fn(S, V, V, V, V, V, V, V) -> (V, V), S: Copy, V: Copy> Butterfly<S, V> for F {}

#[inline]
fn bit_rev(nbits: u32, i: usize) -> usize {
    i.reverse_bits() >> (usize::BITS - nbits)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
struct V3(pulp::x86::V3);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
struct V4(pulp::x86::V4);

#[cfg(all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")))]
pulp::simd_type! {
    struct V4IFma {
        pub sse: "sse",
        pub sse2: "sse2",
        pub fxsr: "fxsr",
        pub sse3: "sse3",
        pub ssse3: "ssse3",
        pub sse4_1: "sse4.1",
        pub sse4_2: "sse4.2",
        pub popcnt: "popcnt",
        pub avx: "avx",
        pub avx2: "avx2",
        pub bmi1: "bmi1",
        pub bmi2: "bmi2",
        pub fma: "fma",
        pub lzcnt: "lzcnt",
        pub avx512f: "avx512f",
        pub avx512bw: "avx512bw",
        pub avx512cd: "avx512cd",
        pub avx512dq: "avx512dq",
        pub avx512vl: "avx512vl",
        pub avx512ifma: "avx512ifma",
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl V4 {
    #[inline]
    pub fn try_new() -> Option<Self> {
        pulp::x86::V4::try_new().map(Self)
    }

    /// Returns separately two vectors containing the low 64 bits of the result,
    /// and the high 64 bits of the result.
    #[inline(always)]
    pub fn widening_mul_u64x8(self, a: u64x8, b: u64x8) -> (u64x8, u64x8) {
        // https://stackoverflow.com/a/28827013
        let avx = self.avx512f;
        let x = cast(a);
        let y = cast(b);

        let lo_mask = avx._mm512_set1_epi64(0x0000_0000_FFFF_FFFFu64 as _);
        let x_hi = avx._mm512_shuffle_epi32::<0b1011_0001>(x);
        let y_hi = avx._mm512_shuffle_epi32::<0b1011_0001>(y);

        let z_lo_lo = avx._mm512_mul_epu32(x, y);
        let z_lo_hi = avx._mm512_mul_epu32(x, y_hi);
        let z_hi_lo = avx._mm512_mul_epu32(x_hi, y);
        let z_hi_hi = avx._mm512_mul_epu32(x_hi, y_hi);

        let z_lo_lo_shift = avx._mm512_srli_epi64::<32>(z_lo_lo);

        let sum_tmp = avx._mm512_add_epi64(z_lo_hi, z_lo_lo_shift);
        let sum_lo = avx._mm512_and_si512(sum_tmp, lo_mask);
        let sum_mid = avx._mm512_srli_epi64::<32>(sum_tmp);

        let sum_mid2 = avx._mm512_add_epi64(z_hi_lo, sum_lo);
        let sum_mid2_hi = avx._mm512_srli_epi64::<32>(sum_mid2);
        let sum_hi = avx._mm512_add_epi64(z_hi_hi, sum_mid);

        let prod_hi = avx._mm512_add_epi64(sum_hi, sum_mid2_hi);
        let prod_lo = avx._mm512_add_epi64(
            avx._mm512_slli_epi64::<32>(avx._mm512_add_epi64(z_lo_hi, z_hi_lo)),
            z_lo_lo,
        );

        (cast(prod_lo), cast(prod_hi))
    }

    /// Multiplies the low 32 bits of each 64 bit integer and returns the 64 bit result.
    #[inline(always)]
    pub fn mul_low_32_bits_u64x8(self, a: u64x8, b: u64x8) -> u64x8 {
        pulp::cast(self.avx512f._mm512_mul_epu32(pulp::cast(a), pulp::cast(b)))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl V4IFma {
    /// Returns separately two vectors containing the low 52 bits of the result,
    /// and the high 52 bits of the result.
    #[inline(always)]
    pub fn widening_mul_u52x8(self, a: u64x8, b: u64x8) -> (u64x8, u64x8) {
        let a = cast(a);
        let b = cast(b);
        let zero = cast(self.splat_u64x8(0));
        (
            cast(self.avx512ifma._mm512_madd52lo_epu64(zero, a, b)),
            cast(self.avx512ifma._mm512_madd52hi_epu64(zero, a, b)),
        )
    }

    /// (a * b + c) mod 2^52 for each 52 bit integer in a, b, and c.
    #[inline(always)]
    pub fn wrapping_mul_add_u52x8(self, a: u64x8, b: u64x8, c: u64x8) -> u64x8 {
        self.and_u64x8(
            cast(
                self.avx512ifma
                    ._mm512_madd52lo_epu64(cast(c), cast(a), cast(b)),
            ),
            self.splat_u64x8((1u64 << 52) - 1),
        )
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
trait SupersetOfV4: Copy {
    fn get_v4(self) -> V4;
    fn vectorize(self, f: impl pulp::NullaryFnOnce);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl SupersetOfV4 for V4 {
    #[inline(always)]
    fn get_v4(self) -> V4 {
        self
    }
    #[inline(always)]
    fn vectorize(self, f: impl pulp::NullaryFnOnce) {
        self.0.vectorize(f);
    }
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl SupersetOfV4 for V4IFma {
    #[inline(always)]
    fn get_v4(self) -> V4 {
        *self
    }
    #[inline(always)]
    fn vectorize(self, f: impl pulp::NullaryFnOnce) {
        self.vectorize(f);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl V3 {
    #[inline]
    pub fn try_new() -> Option<Self> {
        pulp::x86::V3::try_new().map(Self)
    }

    /// Returns separately two vectors containing the low 64 bits of the result,
    /// and the high 64 bits of the result.
    #[inline(always)]
    pub fn widening_mul_u64x4(self, a: u64x4, b: u64x4) -> (u64x4, u64x4) {
        // https://stackoverflow.com/a/28827013
        let avx = self.avx;
        let avx2 = self.avx2;
        let x = cast(a);
        let y = cast(b);
        let lo_mask = avx._mm256_set1_epi64x(0x0000_0000_FFFF_FFFFu64 as _);
        let x_hi = avx2._mm256_shuffle_epi32::<0b10110001>(x);
        let y_hi = avx2._mm256_shuffle_epi32::<0b10110001>(y);

        let z_lo_lo = avx2._mm256_mul_epu32(x, y);
        let z_lo_hi = avx2._mm256_mul_epu32(x, y_hi);
        let z_hi_lo = avx2._mm256_mul_epu32(x_hi, y);
        let z_hi_hi = avx2._mm256_mul_epu32(x_hi, y_hi);

        let z_lo_lo_shift = avx2._mm256_srli_epi64::<32>(z_lo_lo);

        let sum_tmp = avx2._mm256_add_epi64(z_lo_hi, z_lo_lo_shift);
        let sum_lo = avx2._mm256_and_si256(sum_tmp, lo_mask);
        let sum_mid = avx2._mm256_srli_epi64::<32>(sum_tmp);

        let sum_mid2 = avx2._mm256_add_epi64(z_hi_lo, sum_lo);
        let sum_mid2_hi = avx2._mm256_srli_epi64::<32>(sum_mid2);
        let sum_hi = avx2._mm256_add_epi64(z_hi_hi, sum_mid);

        let prod_hi = avx2._mm256_add_epi64(sum_hi, sum_mid2_hi);
        let prod_lo = avx2._mm256_add_epi64(
            avx2._mm256_slli_epi64::<32>(avx2._mm256_add_epi64(z_lo_hi, z_hi_lo)),
            z_lo_lo,
        );

        (cast(prod_lo), cast(prod_hi))
    }

    /// Multiplies the low 32 bits of each 64 bit integer and returns the 64 bit result.
    #[inline(always)]
    pub fn mul_low_32_bits_u64x4(self, a: u64x4, b: u64x4) -> u64x4 {
        pulp::cast(self.avx2._mm256_mul_epu32(pulp::cast(a), pulp::cast(b)))
    }

    // (a * b mod 2^32) mod 2^64 for each element in a and b.
    #[inline(always)]
    pub fn wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(self, a: u64x4, b: u64x4) -> u64x4 {
        let a = cast(a);
        let b = cast(b);
        let avx2 = self.avx2;
        let x_hi = avx2._mm256_shuffle_epi32::<0b10110001>(a);
        let z_lo_lo = avx2._mm256_mul_epu32(a, b);
        let z_hi_lo = avx2._mm256_mul_epu32(x_hi, b);
        cast(avx2._mm256_add_epi64(avx2._mm256_slli_epi64::<32>(z_hi_lo), z_lo_lo))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl core::ops::Deref for V4 {
    type Target = pulp::x86::V4;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl core::ops::Deref for V4IFma {
    type Target = V4;

    #[inline]
    fn deref(&self) -> &Self::Target {
        let Self {
            sse,
            sse2,
            fxsr,
            sse3,
            ssse3,
            sse4_1,
            sse4_2,
            popcnt,
            avx,
            avx2,
            bmi1,
            bmi2,
            fma,
            lzcnt,
            avx512f,
            avx512bw,
            avx512cd,
            avx512dq,
            avx512vl,
            avx512ifma: _,
        } = *self;
        let simd_ref = (pulp::x86::V4 {
            sse,
            sse2,
            fxsr,
            sse3,
            ssse3,
            sse4_1,
            sse4_2,
            popcnt,
            avx,
            avx2,
            bmi1,
            bmi2,
            fma,
            lzcnt,
            avx512f,
            avx512bw,
            avx512cd,
            avx512dq,
            avx512vl,
        })
        .to_ref();

        // SAFETY
        // `pulp::x86::V4` and `crate::V4` have the same layout, since the latter is
        // #[repr(transparent)].
        unsafe { &*(simd_ref as *const pulp::x86::V4 as *const V4) }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl core::ops::Deref for V3 {
    type Target = pulp::x86::V3;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// the magic constants are such that
// for all x < 2^64
// x / P_i == ((x * P_i_MAGIC) >> 64) >> P_i_MAGIC_SHIFT
//
// this can be used to implement the modulo operation in constant time to avoid side channel
// attacks, can also speed up the operation x % P_i, since the compiler doesn't manage to vectorize
// it on its own.
//
// how to:
// run `cargo test generate_primes -- --nocapture`
//
// copy paste the generated primes in this function
// ```
// pub fn codegen(x: u64) -> u64 {
//     x / $PRIME
// }
// ```
//
// look at the generated assembly for codegen
// extract primes that satisfy the desired property
//
// asm should look like this on x86_64
// ```
// mov rax, rdi
// movabs rcx, P_MAGIC (as i64 signed value)
// mul rcx
// mov rax, rdx
// shr rax, P_MAGIC_SHIFT
// ret
// ```
#[allow(dead_code)]
pub(crate) mod primes32 {
    use crate::{
        fastdiv::{Div32, Div64},
        prime::exp_mod32,
    };

    pub const P0: u32 = 0b0011_1111_0101_1010_0000_0000_0000_0001;
    pub const P1: u32 = 0b0011_1111_0101_1101_0000_0000_0000_0001;
    pub const P2: u32 = 0b0011_1111_0111_0110_0000_0000_0000_0001;
    pub const P3: u32 = 0b0011_1111_1000_0010_0000_0000_0000_0001;
    pub const P4: u32 = 0b0011_1111_1010_1100_0000_0000_0000_0001;
    pub const P5: u32 = 0b0011_1111_1010_1111_0000_0000_0000_0001;
    pub const P6: u32 = 0b0011_1111_1011_0001_0000_0000_0000_0001;
    pub const P7: u32 = 0b0011_1111_1011_1011_0000_0000_0000_0001;
    pub const P8: u32 = 0b0011_1111_1101_1110_0000_0000_0000_0001;
    pub const P9: u32 = 0b0011_1111_1111_1100_0000_0000_0000_0001;

    pub const P0_MAGIC: u64 = 9317778228489988551;
    pub const P1_MAGIC: u64 = 4658027473943558643;
    pub const P2_MAGIC: u64 = 1162714878353869247;
    pub const P3_MAGIC: u64 = 4647426722536610861;
    pub const P4_MAGIC: u64 = 9270903515973367219;
    pub const P5_MAGIC: u64 = 2317299382174935855;
    pub const P6_MAGIC: u64 = 9268060552616330319;
    pub const P7_MAGIC: u64 = 2315594963384859737;
    pub const P8_MAGIC: u64 = 9242552129100825291;
    pub const P9_MAGIC: u64 = 576601523622774689;

    pub const P0_MAGIC_SHIFT: u32 = 29;
    pub const P1_MAGIC_SHIFT: u32 = 28;
    pub const P2_MAGIC_SHIFT: u32 = 26;
    pub const P3_MAGIC_SHIFT: u32 = 28;
    pub const P4_MAGIC_SHIFT: u32 = 29;
    pub const P5_MAGIC_SHIFT: u32 = 27;
    pub const P6_MAGIC_SHIFT: u32 = 29;
    pub const P7_MAGIC_SHIFT: u32 = 27;
    pub const P8_MAGIC_SHIFT: u32 = 29;
    pub const P9_MAGIC_SHIFT: u32 = 25;

    const fn mul_mod(modulus: u32, a: u32, b: u32) -> u32 {
        let wide = a as u64 * b as u64;
        (wide % modulus as u64) as u32
    }

    const fn inv_mod(modulus: u32, x: u32) -> u32 {
        exp_mod32(Div32::new(modulus), x, modulus - 2)
    }

    const fn shoup(modulus: u32, w: u32) -> u32 {
        (((w as u64) << 32) / modulus as u64) as u32
    }

    const fn mul_mod64(modulus: u64, a: u64, b: u64) -> u64 {
        let wide = a as u128 * b as u128;
        (wide % modulus as u128) as u64
    }

    const fn exp_mod64(modulus: u64, base: u64, pow: u64) -> u64 {
        crate::prime::exp_mod64(Div64::new(modulus), base, pow)
    }

    const fn shoup64(modulus: u64, w: u64) -> u64 {
        (((w as u128) << 64) / modulus as u128) as u64
    }

    pub const P0_INV_MOD_P1: u32 = inv_mod(P1, P0);
    pub const P0_INV_MOD_P1_SHOUP: u32 = shoup(P1, P0_INV_MOD_P1);
    pub const P01_INV_MOD_P2: u32 = inv_mod(P2, mul_mod(P2, P0, P1));
    pub const P01_INV_MOD_P2_SHOUP: u32 = shoup(P2, P01_INV_MOD_P2);
    pub const P012_INV_MOD_P3: u32 = inv_mod(P3, mul_mod(P3, mul_mod(P3, P0, P1), P2));
    pub const P012_INV_MOD_P3_SHOUP: u32 = shoup(P3, P012_INV_MOD_P3);
    pub const P0123_INV_MOD_P4: u32 =
        inv_mod(P4, mul_mod(P4, mul_mod(P4, mul_mod(P4, P0, P1), P2), P3));
    pub const P0123_INV_MOD_P4_SHOUP: u32 = shoup(P4, P0123_INV_MOD_P4);

    pub const P0_MOD_P2_SHOUP: u32 = shoup(P2, P0);
    pub const P0_MOD_P3_SHOUP: u32 = shoup(P3, P0);
    pub const P1_MOD_P3_SHOUP: u32 = shoup(P3, P1);
    pub const P0_MOD_P4_SHOUP: u32 = shoup(P4, P0);
    pub const P1_MOD_P4_SHOUP: u32 = shoup(P4, P1);
    pub const P2_MOD_P4_SHOUP: u32 = shoup(P4, P2);

    pub const P1_INV_MOD_P2: u32 = inv_mod(P2, P1);
    pub const P1_INV_MOD_P2_SHOUP: u32 = shoup(P2, P1_INV_MOD_P2);
    pub const P3_INV_MOD_P4: u32 = inv_mod(P4, P3);
    pub const P3_INV_MOD_P4_SHOUP: u32 = shoup(P4, P3_INV_MOD_P4);
    pub const P12: u64 = P1 as u64 * P2 as u64;
    pub const P34: u64 = P3 as u64 * P4 as u64;
    pub const P0_INV_MOD_P12: u64 =
        exp_mod64(P12, P0 as u64, (P1 as u64 - 1) * (P2 as u64 - 1) - 1);
    pub const P0_INV_MOD_P12_SHOUP: u64 = shoup64(P12, P0_INV_MOD_P12);
    pub const P0_MOD_P34_SHOUP: u64 = shoup64(P34, P0 as u64);
    pub const P012_INV_MOD_P34: u64 = exp_mod64(
        P34,
        mul_mod64(P34, P0 as u64, P12),
        (P3 as u64 - 1) * (P4 as u64 - 1) - 1,
    );
    pub const P012_INV_MOD_P34_SHOUP: u64 = shoup64(P34, P012_INV_MOD_P34);

    pub const P2_INV_MOD_P3: u32 = inv_mod(P3, P2);
    pub const P2_INV_MOD_P3_SHOUP: u32 = shoup(P3, P2_INV_MOD_P3);
    pub const P4_INV_MOD_P5: u32 = inv_mod(P5, P4);
    pub const P4_INV_MOD_P5_SHOUP: u32 = shoup(P5, P4_INV_MOD_P5);
    pub const P6_INV_MOD_P7: u32 = inv_mod(P7, P6);
    pub const P6_INV_MOD_P7_SHOUP: u32 = shoup(P7, P6_INV_MOD_P7);
    pub const P8_INV_MOD_P9: u32 = inv_mod(P9, P8);
    pub const P8_INV_MOD_P9_SHOUP: u32 = shoup(P9, P8_INV_MOD_P9);

    pub const P01: u64 = P0 as u64 * P1 as u64;
    pub const P23: u64 = P2 as u64 * P3 as u64;
    pub const P45: u64 = P4 as u64 * P5 as u64;
    pub const P67: u64 = P6 as u64 * P7 as u64;
    pub const P89: u64 = P8 as u64 * P9 as u64;

    pub const P01_MOD_P45_SHOUP: u64 = shoup64(P45, P01);
    pub const P01_MOD_P67_SHOUP: u64 = shoup64(P67, P01);
    pub const P01_MOD_P89_SHOUP: u64 = shoup64(P89, P01);

    pub const P23_MOD_P67_SHOUP: u64 = shoup64(P67, P23);
    pub const P23_MOD_P89_SHOUP: u64 = shoup64(P89, P23);

    pub const P45_MOD_P89_SHOUP: u64 = shoup64(P89, P45);

    pub const P01_INV_MOD_P23: u64 = exp_mod64(P23, P01, (P2 as u64 - 1) * (P3 as u64 - 1) - 1);
    pub const P01_INV_MOD_P23_SHOUP: u64 = shoup64(P23, P01_INV_MOD_P23);
    pub const P0123_INV_MOD_P45: u64 = exp_mod64(
        P45,
        mul_mod64(P45, P01, P23),
        (P4 as u64 - 1) * (P5 as u64 - 1) - 1,
    );
    pub const P0123_INV_MOD_P45_SHOUP: u64 = shoup64(P45, P0123_INV_MOD_P45);
    pub const P012345_INV_MOD_P67: u64 = exp_mod64(
        P67,
        mul_mod64(P67, mul_mod64(P67, P01, P23), P45),
        (P6 as u64 - 1) * (P7 as u64 - 1) - 1,
    );
    pub const P012345_INV_MOD_P67_SHOUP: u64 = shoup64(P67, P012345_INV_MOD_P67);
    pub const P01234567_INV_MOD_P89: u64 = exp_mod64(
        P89,
        mul_mod64(P89, mul_mod64(P89, mul_mod64(P89, P01, P23), P45), P67),
        (P8 as u64 - 1) * (P9 as u64 - 1) - 1,
    );
    pub const P01234567_INV_MOD_P89_SHOUP: u64 = shoup64(P89, P01234567_INV_MOD_P89);

    pub const P0123: u128 = u128::wrapping_mul(P01 as u128, P23 as u128);
    pub const P012345: u128 = u128::wrapping_mul(P0123, P45 as u128);
    pub const P01234567: u128 = u128::wrapping_mul(P012345, P67 as u128);
    pub const P0123456789: u128 = u128::wrapping_mul(P01234567, P89 as u128);
}

#[allow(dead_code)]
pub(crate) mod primes52 {
    use crate::fastdiv::Div64;

    pub const P0: u64 = 0b0011_1111_1111_1111_1111_1111_1110_0111_0111_0000_0000_0000_0001;
    pub const P1: u64 = 0b0011_1111_1111_1111_1111_1111_1110_1011_1001_0000_0000_0000_0001;
    pub const P2: u64 = 0b0011_1111_1111_1111_1111_1111_1110_1100_1000_0000_0000_0000_0001;
    pub const P3: u64 = 0b0011_1111_1111_1111_1111_1111_1111_1000_1011_0000_0000_0000_0001;
    pub const P4: u64 = 0b0011_1111_1111_1111_1111_1111_1111_1011_1000_0000_0000_0000_0001;
    pub const P5: u64 = 0b0011_1111_1111_1111_1111_1111_1111_1100_0111_0000_0000_0000_0001;

    pub const P0_MAGIC: u64 = 9223372247845040859;
    pub const P1_MAGIC: u64 = 4611686106205779591;
    pub const P2_MAGIC: u64 = 4611686102179247601;
    pub const P3_MAGIC: u64 = 2305843024917166187;
    pub const P4_MAGIC: u64 = 4611686037754736721;
    pub const P5_MAGIC: u64 = 4611686033728204851;

    pub const P0_MAGIC_SHIFT: u32 = 49;
    pub const P1_MAGIC_SHIFT: u32 = 48;
    pub const P2_MAGIC_SHIFT: u32 = 48;
    pub const P3_MAGIC_SHIFT: u32 = 47;
    pub const P4_MAGIC_SHIFT: u32 = 48;
    pub const P5_MAGIC_SHIFT: u32 = 48;

    const fn mul_mod(modulus: u64, a: u64, b: u64) -> u64 {
        let wide = a as u128 * b as u128;
        (wide % modulus as u128) as u64
    }

    const fn inv_mod(modulus: u64, x: u64) -> u64 {
        crate::prime::exp_mod64(Div64::new(modulus), x, modulus - 2)
    }

    const fn shoup(modulus: u64, w: u64) -> u64 {
        (((w as u128) << 52) / modulus as u128) as u64
    }

    pub const P0_INV_MOD_P1: u64 = inv_mod(P1, P0);
    pub const P0_INV_MOD_P1_SHOUP: u64 = shoup(P1, P0_INV_MOD_P1);

    pub const P01_INV_MOD_P2: u64 = inv_mod(P2, mul_mod(P2, P0, P1));
    pub const P01_INV_MOD_P2_SHOUP: u64 = shoup(P2, P01_INV_MOD_P2);
    pub const P012_INV_MOD_P3: u64 = inv_mod(P3, mul_mod(P3, mul_mod(P3, P0, P1), P2));
    pub const P012_INV_MOD_P3_SHOUP: u64 = shoup(P3, P012_INV_MOD_P3);
    pub const P0123_INV_MOD_P4: u64 =
        inv_mod(P4, mul_mod(P4, mul_mod(P4, mul_mod(P4, P0, P1), P2), P3));
    pub const P0123_INV_MOD_P4_SHOUP: u64 = shoup(P4, P0123_INV_MOD_P4);

    pub const P0_MOD_P2_SHOUP: u64 = shoup(P2, P0);
    pub const P0_MOD_P3_SHOUP: u64 = shoup(P3, P0);
    pub const P1_MOD_P3_SHOUP: u64 = shoup(P3, P1);
    pub const P0_MOD_P4_SHOUP: u64 = shoup(P4, P0);
    pub const P1_MOD_P4_SHOUP: u64 = shoup(P4, P1);
    pub const P2_MOD_P4_SHOUP: u64 = shoup(P4, P2);
}

macro_rules! izip {
    (@ __closure @ ($a:expr)) => { |a| (a,) };
    (@ __closure @ ($a:expr, $b:expr)) => { |(a, b)| (a, b) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr)) => { |((a, b), c)| (a, b, c) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr)) => { |(((a, b), c), d)| (a, b, c, d) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr)) => { |((((a, b), c), d), e)| (a, b, c, d, e) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr)) => { |(((((a, b), c), d), e), f)| (a, b, c, d, e, f) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr)) => { |((((((a, b), c), d), e), f), g)| (a, b, c, d, e, f, g) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr)) => { |(((((((a, b), c), d), e), f), g), h)| (a, b, c, d, e, f, g, h) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr)) => { |((((((((a, b), c), d), e), f), g), h), i)| (a, b, c, d, e, f, g, h, i) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr)) => { |(((((((((a, b), c), d), e), f), g), h), i), j)| (a, b, c, d, e, f, g, h, i, j) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr)) => { |((((((((((a, b), c), d), e), f), g), h), i), j), k)| (a, b, c, d, e, f, g, h, i, j, k) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr)) => { |(((((((((((a, b), c), d), e), f), g), h), i), j), k), l)| (a, b, c, d, e, f, g, h, i, j, k, l) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr)) => { |((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m)| (a, b, c, d, e, f, g, h, i, j, k, l, m) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr)) => { |(((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr, $o:expr)) => { |((((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n), o)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o) };

    ( $first:expr $(,)?) => {
        {
            ::core::iter::IntoIterator::into_iter($first)
        }
    };
    ( $first:expr, $($rest:expr),+ $(,)?) => {
        {
            ::core::iter::IntoIterator::into_iter($first)
                $(.zip($rest))*
                .map(crate::izip!(@ __closure @ ($first, $($rest),*)))
        }
    };
}
pub(crate) use izip;

#[cfg(test)]
mod tests {
    use crate::prime::largest_prime_in_arithmetic_progression64;
    use rand::random;

    #[test]
    fn test_barrett32() {
        let p =
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap() as u32;

        let big_q: u32 = p.ilog2() + 1;
        let big_l: u32 = big_q + 31;
        let k: u32 = ((1u128 << big_l) / p as u128).try_into().unwrap();

        for _ in 0..10000 {
            let a = random::<u32>() % p;
            let b = random::<u32>() % p;

            let d = a as u64 * b as u64;
            // Q < 31
            // d < 2^(2Q)
            // (d >> (Q-1)) < 2^(Q+1)         -> c1 fits in u32
            let c1 = (d >> (big_q - 1)) as u32;
            // c2 < 2^(Q+33)
            let c3 = ((c1 as u64 * k as u64) >> 32) as u32;
            let c = (d as u32).wrapping_sub(p.wrapping_mul(c3));
            let c = if c >= p { c - p } else { c };
            assert_eq!(c as u64, d % p as u64);
        }
    }

    #[test]
    fn test_barrett52() {
        let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 51).unwrap();

        let big_q: u32 = p.ilog2() + 1;
        let big_l: u32 = big_q + 51;
        let k: u64 = ((1u128 << big_l) / p as u128).try_into().unwrap();

        for _ in 0..10000 {
            let a = random::<u64>() % p;
            let b = random::<u64>() % p;

            let d = a as u128 * b as u128;
            // Q < 51
            // d < 2^(2Q)
            // (d >> (Q-1)) < 2^(Q+1)         -> c1 fits in u64
            let c1 = (d >> (big_q - 1)) as u64;
            // c2 < 2^(Q+53)
            let c3 = ((c1 as u128 * k as u128) >> 52) as u64;
            let c = (d as u64).wrapping_sub(p.wrapping_mul(c3));
            let c = if c >= p { c - p } else { c };
            assert_eq!(c as u128, d % p as u128);
        }
    }

    #[test]
    fn test_barrett64() {
        let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 62, 1 << 63).unwrap();

        let big_q: u32 = p.ilog2() + 1;
        let big_l: u32 = big_q + 63;
        let k: u64 = ((1u128 << big_l) / p as u128).try_into().unwrap();

        for _ in 0..10000 {
            let a = random::<u64>() % p;
            let b = random::<u64>() % p;

            let d = a as u128 * b as u128;
            // Q < 63
            // d < 2^(2Q)
            // (d >> (Q-1)) < 2^(Q+1)         -> c1 fits in u64
            let c1 = (d >> (big_q - 1)) as u64;
            // c2 < 2^(Q+65)
            let c3 = ((c1 as u128 * k as u128) >> 64) as u64;
            let c = (d as u64).wrapping_sub(p.wrapping_mul(c3));
            let c = if c >= p { c - p } else { c };
            assert_eq!(c as u128, d % p as u128);
        }
    }

    // primes should be of the form x * LARGEST_POLYNOMIAL_SIZE(2^16) + 1
    // primes should be < 2^30 or < 2^50, for NTT efficiency
    // primes should satisfy the magic property documented above the primes32 module
    // primes should be as large as possible
    #[cfg(feature = "std")]
    #[test]
    fn generate_primes() {
        let mut p = 1u64 << 30;
        for _ in 0..100 {
            p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, p - 1).unwrap();
            println!("{p:#034b}");
        }

        let mut p = 1u64 << 50;
        for _ in 0..100 {
            p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, p - 1).unwrap();
            println!("{p:#054b}");
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(test)]
mod x86_tests {
    use super::*;
    use rand::random as rnd;

    #[test]
    fn test_widening_mul() {
        if let Some(simd) = crate::V3::try_new() {
            let a = u64x4(rnd(), rnd(), rnd(), rnd());
            let b = u64x4(rnd(), rnd(), rnd(), rnd());
            let (lo, hi) = simd.widening_mul_u64x4(a, b);
            assert_eq!(
                lo,
                u64x4(
                    u64::wrapping_mul(a.0, b.0),
                    u64::wrapping_mul(a.1, b.1),
                    u64::wrapping_mul(a.2, b.2),
                    u64::wrapping_mul(a.3, b.3),
                ),
            );
            assert_eq!(
                hi,
                u64x4(
                    ((a.0 as u128 * b.0 as u128) >> 64) as u64,
                    ((a.1 as u128 * b.1 as u128) >> 64) as u64,
                    ((a.2 as u128 * b.2 as u128) >> 64) as u64,
                    ((a.3 as u128 * b.3 as u128) >> 64) as u64,
                ),
            );
        }

        #[cfg(feature = "nightly")]
        if let Some(simd) = crate::V4::try_new() {
            let a = u64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            let b = u64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            let (lo, hi) = simd.widening_mul_u64x8(a, b);
            assert_eq!(
                lo,
                u64x8(
                    u64::wrapping_mul(a.0, b.0),
                    u64::wrapping_mul(a.1, b.1),
                    u64::wrapping_mul(a.2, b.2),
                    u64::wrapping_mul(a.3, b.3),
                    u64::wrapping_mul(a.4, b.4),
                    u64::wrapping_mul(a.5, b.5),
                    u64::wrapping_mul(a.6, b.6),
                    u64::wrapping_mul(a.7, b.7),
                ),
            );
            assert_eq!(
                hi,
                u64x8(
                    ((a.0 as u128 * b.0 as u128) >> 64) as u64,
                    ((a.1 as u128 * b.1 as u128) >> 64) as u64,
                    ((a.2 as u128 * b.2 as u128) >> 64) as u64,
                    ((a.3 as u128 * b.3 as u128) >> 64) as u64,
                    ((a.4 as u128 * b.4 as u128) >> 64) as u64,
                    ((a.5 as u128 * b.5 as u128) >> 64) as u64,
                    ((a.6 as u128 * b.6 as u128) >> 64) as u64,
                    ((a.7 as u128 * b.7 as u128) >> 64) as u64,
                ),
            );
        }
    }

    #[test]
    fn test_mul_low_32_bits() {
        if let Some(simd) = crate::V3::try_new() {
            let a = u64x4(rnd(), rnd(), rnd(), rnd());
            let b = u64x4(rnd(), rnd(), rnd(), rnd());
            let res = simd.mul_low_32_bits_u64x4(a, b);
            assert_eq!(
                res,
                u64x4(
                    a.0 as u32 as u64 * b.0 as u32 as u64,
                    a.1 as u32 as u64 * b.1 as u32 as u64,
                    a.2 as u32 as u64 * b.2 as u32 as u64,
                    a.3 as u32 as u64 * b.3 as u32 as u64,
                ),
            );
        }
        #[cfg(feature = "nightly")]
        if let Some(simd) = crate::V4::try_new() {
            let a = u64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            let b = u64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            let res = simd.mul_low_32_bits_u64x8(a, b);
            assert_eq!(
                res,
                u64x8(
                    a.0 as u32 as u64 * b.0 as u32 as u64,
                    a.1 as u32 as u64 * b.1 as u32 as u64,
                    a.2 as u32 as u64 * b.2 as u32 as u64,
                    a.3 as u32 as u64 * b.3 as u32 as u64,
                    a.4 as u32 as u64 * b.4 as u32 as u64,
                    a.5 as u32 as u64 * b.5 as u32 as u64,
                    a.6 as u32 as u64 * b.6 as u32 as u64,
                    a.7 as u32 as u64 * b.7 as u32 as u64,
                ),
            );
        }
    }

    #[test]
    fn test_mul_lhs_with_low_32_bits_of_rhs() {
        if let Some(simd) = crate::V3::try_new() {
            let a = u64x4(rnd(), rnd(), rnd(), rnd());
            let b = u64x4(rnd(), rnd(), rnd(), rnd());
            let res = simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(a, b);
            assert_eq!(
                res,
                u64x4(
                    u64::wrapping_mul(a.0, b.0 as u32 as u64),
                    u64::wrapping_mul(a.1, b.1 as u32 as u64),
                    u64::wrapping_mul(a.2, b.2 as u32 as u64),
                    u64::wrapping_mul(a.3, b.3 as u32 as u64),
                ),
            );
        }
    }
}
