use crate::core_crypto::hpu::from_with::IntoWith;
use crate::shortint::ClassicPBSParameters;
use tfhe_hpu_backend::prelude::HpuDevice;

use super::CompressedServerKey;
pub mod ciphertext;

/// Utility function for HpuDevice initialisation
/// Init from Compressed material
pub fn init_device(device: &HpuDevice, server_key: CompressedServerKey) -> crate::Result<()> {
    let params = device.params();
    let tfhe_params = ClassicPBSParameters::from(&params);

    // Extract and convert bsk
    let bsk = match server_key.key.bootstrapping_key {
        crate::shortint::server_key::ShortintCompressedBootstrappingKey::Classic {
            bsk, ..
        } => {
            let bsk = bsk.decompress_into_lwe_bootstrap_key();

            // Check that given key is compliant with current device configuration
            if tfhe_params.lwe_dimension != bsk.input_lwe_dimension() {
                return Err("BootstrappingKey has incompatible input_lwe_dimension".into());
            }
            if tfhe_params.glwe_dimension.to_glwe_size() != bsk.glwe_size() {
                return Err("BootstrappingKey has incompatible glwe_size".into());
            }
            if tfhe_params.polynomial_size != bsk.polynomial_size() {
                return Err("BootstrappingKey has incompatible polynomial size".into());
            }
            if tfhe_params.pbs_base_log != bsk.decomposition_base_log() {
                return Err("BootstrappingKey has incompatible decomposition_base_log".into());
            }
            if tfhe_params.pbs_level != bsk.decomposition_level_count() {
                return Err("BootstrappingKey has incompatible decomposition_level_count".into());
            }
            if tfhe_params.ciphertext_modulus != bsk.ciphertext_modulus() {
                return Err("BootstrappingKey has incompatible ciphertext_modulus".into());
            }
            Ok(bsk)
        }
        crate::shortint::server_key::ShortintCompressedBootstrappingKey::MultiBit { .. } => {
            Err("Hpu currently not support multibit. Required a Classic BSK")
        }
    }?;
    let hpu_bsk = bsk.as_view().into_with(params.clone());
    // Extract and convert ksk
    let ksk = server_key
        .key
        .key_switching_key
        .decompress_into_lwe_keyswitch_key();
    // Check that given key is compliant with current device configuration
    if tfhe_params.ks_base_log != ksk.decomposition_base_log() {
        return Err("KeyswitchingKey has incompatible decomposition_base_log".into());
    }
    if tfhe_params.ks_level != ksk.decomposition_level_count() {
        return Err("KeyswitchingKey has incompatible decomposition_level_count".into());
    }
    let hpu_ksk = ksk.as_view().into_with(params);

    // Upload them on Hpu and configure internal Fw/Lut
    device.init(
        hpu_bsk,
        hpu_ksk,
        crate::core_crypto::hpu::glwe_lookuptable::create_hpu_lookuptable,
    );

    Ok(())
}
