//! One-time pad: XOR the input data with a random encrypted pad.
//!
//! With this transciphering method, the keystream is directly the pre-generated pad,
//! so the only FHE operation is the XOR with the input data.
//! The pad is finite and single-use, and must be at least as long as the data. As a
//! result, this cipher is worthwhile when decrypting a pad as large as the data is
//! possible and efficient enough.

mod fhe;
mod plain;
#[cfg(test)]
mod test;

pub use fhe::{OneTimePadFheSecretMask, OneTimePadFheState};
pub use plain::{
    OneTimePadPlainSecretMask, OneTimePadPlainSecretMaskConformanceParams, OneTimePadPlainState,
};
