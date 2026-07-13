mod fhe;
mod plain;
#[cfg(test)]
mod test;

pub use fhe::{PreGenedOtpFheSecretMask, PreGenedOtpFheState};
pub use plain::{PreGenedOtpPlainSecretMask, PreGenedOtpPlainState};
