//! A module to manipulate polynomials.
//!
//! This module allows to manipulate modular polynomials In particular, we provide three generic
//! types to manipulate such objects:
//!
//! + [`Monomial`], which represents a free monomial term (not bound to a given modular degree)
//! + [`Polynomial`], which represents a dense polynomial of a given degree.
//! + [`PolynomialList`], which represent a set of polynomials with the same degree, on which
//! operations can be performed.

pub use list::*;
pub use monomial::*;
pub use polynomial::*;

#[cfg(test)]
mod tests;

mod list;
mod monomial;
#[allow(clippy::module_inception)]
mod polynomial;

pub use crate::core_crypto::prelude::MonomialDegree;
