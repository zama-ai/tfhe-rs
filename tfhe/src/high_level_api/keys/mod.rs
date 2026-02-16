mod client;
pub(crate) mod expanded;
mod public;
mod server;

mod cpk_re_randomization;
mod inner;
mod key_switching_key;

use crate::high_level_api::config::Config;
pub use client::ClientKey;
pub use cpk_re_randomization::{
    CompressedReRandomizationKey, CompressedReRandomizationKeySwitchingKey, ReRandomizationKey,
    ReRandomizationKeySwitchingKey,
};
pub(crate) use cpk_re_randomization::{
    ReRandomizationKeyGenInfo, ReRandomizationKeySwitchingKeyGenInfo,
};
pub(crate) use inner::CompactPrivateKey;
pub use key_switching_key::KeySwitchingKey;
pub use public::{CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey, PublicKey};
#[cfg(feature = "gpu")]
pub use server::CudaServerKey;
#[cfg(feature = "hpu")]
pub(in crate::high_level_api) use server::HpuTaggedDevice;
pub use server::{CompressedServerKey, ReRandomizationSupport, ServerKey};
pub(crate) use server::{InternalServerKey, InternalServerKeyRef};

pub(in crate::high_level_api) use inner::{
    IntegerClientKey, IntegerCompactPublicKey, IntegerCompressedCompactPublicKey,
    IntegerCompressedServerKey, IntegerConfig, IntegerServerKey, IntegerServerKeyConformanceParams,
};

/// Generates keys using the provided config.
///
/// # Example
///
/// ```rust
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
