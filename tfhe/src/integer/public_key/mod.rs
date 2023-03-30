//! Module with the definition of the encryption PublicKey.

pub mod compressed;
pub mod standard;

pub use compressed::{CompressedPublicKeyBase, CompressedPublicKeyBig, CompressedPublicKeySmall};
pub use standard::{PublicKey, PublicKeyBig, PublicKeySmall};

#[cfg(test)]
mod tests;
