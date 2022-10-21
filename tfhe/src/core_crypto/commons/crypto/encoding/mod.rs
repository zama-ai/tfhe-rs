//! Encoding cleartexts into plaintexts

#[cfg(test)]
mod tests;

mod encoder;
pub use encoder::*;

mod cleartext;
pub use cleartext::*;

mod plaintext;
pub use plaintext::*;
