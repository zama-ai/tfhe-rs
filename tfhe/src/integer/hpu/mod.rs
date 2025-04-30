use crate::core_crypto::prelude::CreateFrom;
use crate::shortint::parameters::KeySwitch32PBSParameters;
use tfhe_hpu_backend::prelude::*;

use super::CompressedServerKey;
pub mod ciphertext;

/// Utility function for HpuDevice initialisation
/// Init from Compressed material
pub fn init_device(device: &HpuDevice, server_key: CompressedServerKey) -> crate::Result<()> {
    let params = device.params().clone();
    let tfhe_params = KeySwitch32PBSParameters::from(&params);

    let ap_key =  match server_key.key.compressed_ap_server_key {
            crate::shortint::atomic_pattern::compressed::CompressedAtomicPatternServerKey::Standard(_) => {
                Err("Hpu not support Standard keys. Required a KeySwitch32 keys")
                }
            crate::shortint::atomic_pattern::compressed::CompressedAtomicPatternServerKey::KeySwitch32(keys) => Ok(keys),
    }?;

    // Extract and convert bsk
    let bsk = match ap_key.bootstrapping_key() {
        crate::shortint::server_key::ShortintCompressedBootstrappingKey::Classic {
            bsk, ..
        } => {
            let bsk = bsk
                .clone() // TODO fix API this shouldn't be needed
                .decompress_into_lwe_bootstrap_key();

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
    let hpu_bsk = HpuLweBootstrapKeyOwned::create_from(bsk.as_view(), params.clone());
    // Extract and convert ksk
    let ksk = ap_key
        .key_switching_key()
        .clone() // TODO fix API this shouldn't be needed
        .decompress_into_lwe_keyswitch_key();
    // Check that given key is compliant with current device configuration
    if tfhe_params.ks_base_log != ksk.decomposition_base_log() {
        return Err("KeyswitchingKey has incompatible decomposition_base_log".into());
    }
    if tfhe_params.ks_level != ksk.decomposition_level_count() {
        return Err("KeyswitchingKey has incompatible decomposition_level_count".into());
    }
    let hpu_ksk = HpuLweKeyswitchKeyOwned::create_from(ksk.as_view(), params);

    // Upload them on Hpu and configure internal Fw/Lut
    device.init(
        hpu_bsk,
        hpu_ksk,
        crate::core_crypto::hpu::glwe_lookuptable::create_hpu_lookuptable,
    );

    Ok(())
}
