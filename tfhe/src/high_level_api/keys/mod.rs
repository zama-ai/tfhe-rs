#[macro_use]
mod client;
#[macro_use]
mod public;
mod server;

use crate::high_level_api::config::Config;
pub use client::ClientKey;
pub use public::{CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey, PublicKey};
pub use server::{CompressedServerKey, ServerKey};

/// Generates keys using the provided config.
///
/// # Example
///
/// ```
/// use tfhe::{generate_keys, ConfigBuilder};
///
/// let config = ConfigBuilder::default().build();
/// let (client_key, server_key) = generate_keys(config);
/// ```
pub fn generate_keys<C: Into<Config>>(config: C) -> (ClientKey, ServerKey) {
    let client_kc = ClientKey::generate(config);
    let server_kc = client_kc.generate_server_key();

    (client_kc, server_kc)
}
