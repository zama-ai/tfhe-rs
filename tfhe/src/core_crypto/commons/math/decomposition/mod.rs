//! Signed decomposition of unsigned integers.
//!
//! Multiple homomorphic operations used in Zama's variant of the TFHE scheme use a signed
//! decomposition to reduce the amount of noise. This module contains a [`SignedDecomposer`] which
//! offer a clean api for this decomposition in the case of power of two moduli. The
//! [`SignedDecomposerNonNative`] offers the same kind of APIs in the case of non power of two
//! moduli.
//!
//! # Description
//!
//! ## Power of two moduli
//!
//! We assume a number $\theta$ lives in $\mathbb{Z}/q\mathbb{Z}$, with $q$ a power of two. Such
//! a number can also be seen as a signed integer in $[ -\frac{q}{2}; \frac{q}{2}-1]$. Assuming a
//! given base $B=2^{b}$ and a number of levels $l$ such that $B^l\leq q$, such a $\theta$ can be
//! approximately decomposed as:
//! $$
//!     \theta \approx \sum\_{i=1}^l\tilde{\theta}\_i\frac{q}{B^i}
//! $$
//! With the $\tilde{\theta}\_i\in[-\frac{B}{2}, \frac{B}{2}]$. When $B^l = q$, the decomposition
//! is no longer an approximation, and becomes exact. The rationale behind using an approximate
//! decomposition like that, is that when using this decomposition the approximation error will be
//! located in the least significant bits, which are already erroneous.
//!
//! ## Non power of two moduli
//!
//! We assume a number $\theta$ lives in $\mathbb{Z}/q\mathbb{Z}$, with $q$ a modulus that is not a
//! power of two. One can apply the same decomposition as above (with some additional approximations
//! in the result) by seeing $\theta$ as living in $\mathbb{Z}/v\mathbb{Z}$ where:
//! $$ \lambda = \lceil{\log_2{q}}\rceil $$
//! $$ v = 2^{\lambda} $$
//! $\theta$ can be approximately decomposed as:
//! $$
//!     \theta \approx \sum\_{i=1}^l\tilde{\theta}\_i\frac{v}{B^i} \mod q
//! $$
//! With the $\tilde{\theta}\_i\in[-\frac{B}{2}, \frac{B}{2}]$.
use std::fmt::Debug;

pub use decomposer::*;
pub use iter::*;
pub use term::*;

mod decomposer;
mod iter;
mod term;
#[cfg(test)]
mod tests;

/// The level of a given term of a decomposition.
///
/// When decomposing an integer over the $l$ levels, this type represent the level (in $[0,l)$)
/// currently manipulated.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct DecompositionLevel(pub usize);
