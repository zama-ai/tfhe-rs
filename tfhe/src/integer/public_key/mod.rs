//! Module with the definition of the encryption PublicKey.

pub mod compressed;
pub mod standard;

pub use compressed::CompressedPublicKey;
pub use standard::PublicKey;

#[cfg(test)]
mod tests;
