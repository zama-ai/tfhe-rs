#[macro_use]
mod client;
#[macro_use]
mod public;
mod server;

use crate::typed_api::config::Config;
pub use client::{ClientKey, RefKeyFromKeyChain};
pub use public::{
    CompressedPublicKey, PublicKey, RefKeyFromCompressedPublicKeyChain, RefKeyFromPublicKeyChain,
};
pub use server::ServerKey;

/// Generates keys using the provided config.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "shortint")]
/// # {
/// use tfhe::{generate_keys, ConfigBuilder};
///
/// let config = ConfigBuilder::all_disabled().enable_default_uint3().build();
/// let (client_key, server_key) = generate_keys(config);
/// # }
/// ```
pub fn generate_keys<C: Into<Config>>(config: C) -> (ClientKey, ServerKey) {
    let client_kc = ClientKey::generate(config);
    let server_kc = client_kc.generate_server_key();

    (client_kc, server_kc)
}
