use crate::core_crypto::hpu::from_with::IntoWith;
use tfhe_hpu_backend::prelude::HpuDevice;

use super::CompressedServerKey;
use crate::shortint::ServerKey;
pub mod ciphertext;

/// Utility function for HpuDevice initialisation
/// Init from Compressed material
pub fn init_device(device: &HpuDevice, server_key: CompressedServerKey) {
    let params = device.params();
    // Extract and convert bsk
    let bsk = match server_key.key.bootstrapping_key {
        crate::shortint::server_key::ShortintCompressedBootstrappingKey::Classic(seeded_bsk) => {
            seeded_bsk.decompress_into_lwe_bootstrap_key()
        }
        crate::shortint::server_key::ShortintCompressedBootstrappingKey::MultiBit { .. } => {
            panic!("Hpu currently not support multibit. Required a Classic BSK")
        }
    };
    let hpu_bsk = bsk.as_view().into_with(params.clone());
    // Extract and convert ksk
    let ksk = server_key
        .key
        .key_switching_key
        .decompress_into_lwe_keyswitch_key();
    let hpu_ksk = ksk.as_view().into_with(params.clone());
    // Upload them on Hpu and configure internal Fw/Lut
    device.init(
        hpu_bsk,
        hpu_ksk,
        crate::core_crypto::hpu::glwe_lookuptable::create_hpu_lookuptable,
    )
}

/// Utility function for HpuDevice initialisation
/// Init from shortint uncompressed material.
/// Warn: This function could panic if the given key is in FFT format
pub fn init_device_shortint(device: &HpuDevice, server_key: ServerKey) {
    let params = device.params();
    // Extract and convert bsk
    let bsk = match &server_key.bootstrapping_key {
        crate::shortint::server_key::ShortintBootstrappingKey::ClassicNtt(bsk_ntt) => bsk_ntt,
        _ => panic!("Hpu currently support only ClassicNtt BSK"),
    };
    let hpu_bsk = bsk.as_view().into_with(params.clone());
    // Extract and convert ksk
    let ksk = server_key.key_switching_key.as_view();
    let hpu_ksk = ksk.into_with(params.clone());
    // Upload them on Hpu and configure internal Fw/Lut
    device.init(
        hpu_bsk,
        hpu_ksk,
        crate::core_crypto::hpu::glwe_lookuptable::create_hpu_lookuptable,
    )
}
