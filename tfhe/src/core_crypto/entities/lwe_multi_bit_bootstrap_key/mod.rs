//! Module containing the definition of the [`LweMultiBitBootstrapKey`].

pub mod fft64_lwe_multi_bit_bootstrap_key;
pub mod standard_lwe_multi_bit_bootstrap_key;

pub use fft64_lwe_multi_bit_bootstrap_key::{
    FourierLweMultiBitBootstrapKey, FourierLweMultiBitBootstrapKeyMutView,
    FourierLweMultiBitBootstrapKeyOwned, FourierLweMultiBitBootstrapKeyView,
};
pub use standard_lwe_multi_bit_bootstrap_key::{
    lwe_multi_bit_bootstrap_key_fork_config, lwe_multi_bit_bootstrap_key_size,
    LweMultiBitBootstrapKey, LweMultiBitBootstrapKeyOwned, MultiBitBootstrapKeyConformanceParams,
};
