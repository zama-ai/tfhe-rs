//! Bootstrapping keys.
//!
//! The bootstrapping operation allows to reduce the level of noise in an LWE ciphertext, while
//! evaluating an univariate function.

mod seeded_standard;
mod standard;

pub use seeded_standard::StandardSeededBootstrapKey;
pub use standard::StandardBootstrapKey;

#[cfg(test)]
mod tests;
