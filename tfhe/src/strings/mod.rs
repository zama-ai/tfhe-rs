pub mod ciphertext;
pub mod client_key;
pub mod server_key;

mod backward_compatibility;
mod char_iter;
#[cfg(test)]
mod test_functions;

// Used as the const argument for StaticUnsignedBigInt, specifying the max chars length of a
// ClearString
const N: usize = 32;

pub use client_key::ClientKey;
pub use server_key::{ServerKey, ServerKeyRef};
