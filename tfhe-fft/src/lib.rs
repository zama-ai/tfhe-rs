//! tfhe-fft is a pure Rust high performance fast Fourier transform library that processes
//! vectors of sizes that are powers of two.
//!
//! This library provides two FFT modules:
//!  - The ordered module FFT applies a forward/inverse FFT that takes its input in standard
//!  order, and outputs the result in standard order. For more detail on what the FFT
//!  computes, check the ordered module-level documentation.
//!  - The unordered module FFT applies a forward FFT that takes its input in standard order,
//!  and outputs the result in a certain permuted order that may depend on the FFT plan. On the
//!  other hand, the inverse FFT takes its input in that same permuted order and outputs its result
//!  in standard order. This is useful for cases where the order of the coefficients in the
//!  Fourier domain is not important. An example is using the Fourier transform for vector
//!  convolution. The only operations that are performed in the Fourier domain are elementwise, and
//!  so the order of the coefficients does not affect the results.
//!
//! Additionally, an optional 128-bit negacyclic FFT module is provided.
//!
//! # Features
//!
//!  - `std` (default): This enables runtime arch detection for accelerated SIMD instructions, and
//!  an FFT plan that measures the various implementations to choose the fastest one at runtime.
//!  - `fft128`: This flag provides access to the 128-bit FFT, which is accessible in the
//!  `fft128` module.
//!  - `nightly`: This enables unstable Rust features to further speed up the FFT, by enabling
//!  AVX512F instructions on CPUs that support them. This feature requires a nightly Rust
//!  toolchain.
//!  - `serde`: This enables serialization and deserialization functions for the unordered plan.
//!  These allow for data in the Fourier domain to be serialized from the permuted order to the
//!  standard order, and deserialized from the standard order to the permuted order.
//!  This is needed since the inverse transform must be used with the same plan that
//!  computed/deserialized the forward transform (or more specifically, a plan with the same
//!  internal base FFT size).
//!
//! # Example
#![cfg_attr(feature = "std", doc = "```")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! use tfhe_fft::c64;
//! use tfhe_fft::ordered::{Plan, Method};
//! use dyn_stack::{PodStack, GlobalPodBuffer};
//! use num_complex::ComplexFloat;
//! use std::time::Duration;
//!
//! const N: usize = 4;
//! let plan = Plan::new(4, Method::Measure(Duration::from_millis(10)));
//! let mut scratch_memory = GlobalPodBuffer::new(plan.fft_scratch().unwrap());
//! let stack = PodStack::new(&mut scratch_memory);
//!
//! let data = [
//!     c64::new(1.0, 0.0),
//!     c64::new(2.0, 0.0),
//!     c64::new(3.0, 0.0),
//!     c64::new(4.0, 0.0),
//! ];
//!
//! let mut transformed_fwd = data;
//! plan.fwd(&mut transformed_fwd, stack);
//!
//! let mut transformed_inv = transformed_fwd;
//! plan.inv(&mut transformed_inv, stack);
//!
//! for (actual, expected) in transformed_inv.iter().map(|z| z / N as f64).zip(data) {
//!     assert!((expected - actual).abs() < 1e-9);
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(
    clippy::erasing_op,
    clippy::identity_op,
    clippy::zero_prefixed_literal,
    clippy::excessive_precision,
    clippy::type_complexity,
    clippy::too_many_arguments,
    non_camel_case_types
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(rustdoc::broken_intra_doc_links)]

use core::marker::PhantomData;

use fft_simd::{FftSimd, Pod};
use num_complex::Complex64;

/// 64-bit complex floating point type.
pub type c64 = Complex64;

macro_rules! izip {
    // implemented this way to avoid a bug with type hints in rust-analyzer
    // https://github.com/rust-lang/rust-analyzer/issues/13526
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
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr, $o:expr, $p: expr)) => { |(((((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n), o), p)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) };

    ( $first:expr $(,)?) => {
        {
            ::core::iter::IntoIterator::into_iter($first)
        }
    };
    ( $first:expr, $($rest:expr),+ $(,)?) => {
        {
            ::core::iter::IntoIterator::into_iter($first)
                $(.zip($rest))*
                .map(izip!(@ __closure @ ($first, $($rest),*)))
        }
    };
}

mod fft_simd;
mod nat;

#[cfg(feature = "std")]
pub(crate) mod time;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

type FnArray = [fn(&mut [c64], &mut [c64], &[c64], &[c64]); 10];

#[derive(Copy, Clone)]
struct FftImpl {
    fwd: FnArray,
    inv: FnArray,
}

impl FftImpl {
    #[inline]
    pub fn make_fn_ptr(&self, n: usize) -> [fn(&mut [c64], &mut [c64], &[c64], &[c64]); 2] {
        let idx = n.trailing_zeros() as usize - 1;
        [self.fwd[idx], self.inv[idx]]
    }
}

/// Computes the FFT of size 2^(N+1).
trait RecursiveFft: nat::Nat {
    fn fft_recurse_impl<c64xN: Pod>(
        simd: impl FftSimd<c64xN>,
        fwd: bool,
        read_from_x: bool,
        s: usize,
        x: &mut [c64xN],
        y: &mut [c64xN],
        w_init: &[c64xN],
        w: &[c64],
    );
}

#[inline]
fn fn_ptr<const FWD: bool, N: RecursiveFft, c64xN: Pod, Simd: FftSimd<c64xN>>(
    simd: Simd,
) -> fn(&mut [c64], &mut [c64], &[c64], &[c64]) {
    // we can't pass `simd` to the closure even though it's a zero-sized struct,
    // because we want the closure to be coercible to a function pointer.
    // so we ignore the passed parameter and reconstruct it inside the closure -------------
    let _ = simd;

    #[inline(never)]
    |buf: &mut [c64], scratch: &mut [c64], w_init: &[c64], w: &[c64]| {
        struct Impl<'a, const FWD: bool, N, c64xN, Simd> {
            simd: Simd,
            buf: &'a mut [c64],
            scratch: &'a mut [c64],
            w_init: &'a [c64],
            w: &'a [c64],
            __marker: PhantomData<(N, c64xN)>,
        }
        // `simd` is reconstructed here. we know the unwrap can never fail because it was already
        // passed to us as a function parameter, which proves that it's possible to construct.
        let simd = Simd::try_new().unwrap();

        // we use NullaryFnOnce instead of a closure because we need the #[inline(always)]
        // annotation, which doesn't always work with closures for some reason.
        impl<const FWD: bool, N: RecursiveFft, c64xN: Pod, Simd: FftSimd<c64xN>> pulp::NullaryFnOnce
            for Impl<'_, FWD, N, c64xN, Simd>
        {
            type Output = ();

            #[inline(always)]
            fn call(self) -> Self::Output {
                let Self {
                    simd,
                    buf,
                    scratch,
                    w_init,
                    w,
                    __marker: _,
                } = self;
                let n = 1 << (N::VALUE + 1);
                assert_eq!(buf.len(), n);
                assert_eq!(scratch.len(), n);
                assert_eq!(w_init.len(), n);
                assert_eq!(w.len(), n);
                N::fft_recurse_impl(
                    simd,
                    FWD,
                    true,
                    1,
                    bytemuck::cast_slice_mut(buf),
                    bytemuck::cast_slice_mut(scratch),
                    bytemuck::cast_slice(w_init),
                    w,
                );
            }
        }

        simd.vectorize(Impl::<FWD, N, c64xN, Simd> {
            simd,
            buf,
            scratch,
            w_init,
            w,
            __marker: PhantomData,
        })
    }
}

mod dif2;
mod dit2;

mod dif4;
mod dit4;

mod dif8;
mod dit8;

mod dif16;
mod dit16;

pub mod ordered;
pub mod unordered;

#[cfg(feature = "fft128")]
#[cfg_attr(docsrs, doc(cfg(feature = "fft128")))]
pub mod fft128;
