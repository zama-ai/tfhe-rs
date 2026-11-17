//! Module with the definition of the encryption PublicKey.

pub mod compact;

pub use compact::{CompactPrivateKey, CompactPublicKey, CompressedCompactPublicKey};

#[cfg(test)]
mod tests;
