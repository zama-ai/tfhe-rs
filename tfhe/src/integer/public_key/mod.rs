//! Module with the definition of the encryption PublicKey.

pub mod compact;
pub mod compressed;
pub mod standard;

pub use compact::{
    CompactPublicKeyBase, CompactPublicKeyBig, CompactPublicKeySmall,
    CompressedCompactPublicKeyBase, CompressedCompactPublicKeyBig, CompressedCompactPublicKeySmall,
};
pub use compressed::{CompressedPublicKeyBase, CompressedPublicKeyBig, CompressedPublicKeySmall};
pub use standard::{PublicKey, PublicKeyBig, PublicKeySmall};

#[cfg(test)]
mod tests;
