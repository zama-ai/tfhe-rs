use tfhe::core_crypto::prelude::*;
// use tfhe::prelude::*;
use tfhe::*;

#[cfg(feature = "hpu")]
use tfhe_hpu_backend::prelude::*;

#[cfg(feature = "hpu")]
use tfhe::core_crypto::hpu::from_with::FromWith;

#[cfg(feature = "hpu")]
#[test]
fn hpu_key_loopback() {
    // Instanciate HpuDevice --------------------------------------------------
    // -> Aims is to read the expected Hpu configuration
    // NB: Change working dir to top level repository
    // -> Enable to have stable path in configuration file
    std::env::set_current_dir(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap(),
    )
    .unwrap();

    let hpu_device = {
        let config = HpuConfig::read_from("backends/tfhe-hpu-backend/config/hpu_config.toml");
        HpuDevice::new(config)
    };

    // Generate Keys ---------------------------------------------------------
    // Extract pbs_configuration from Hpu
    let mut pbs_params = tfhe::shortint::ClassicPBSParameters::from(hpu_device.params());
    // Modify parameters to force NTT-based PBS
    pbs_params.encryption_key_choice =
        shortint::EncryptionKeyChoice::BigNtt(tfhe::shortint::CiphertextModulus::new(
            hpu_device.params().ntt_params.prime_modulus as u128,
        ));

    // Generate shortint keys
    let (_cks, sks) = tfhe::shortint::gen_keys(pbs_params);

    // KSK Loopback conversion and check -------------------------------------
    let mut cpu_ksk_orig = sks.key_switching_key;
    let hpu_ksk = HpuLweKeyswitchKeyOwned::from_with(cpu_ksk_orig.as_view(), hpu_device.params());
    let cpu_ksk_lb = LweKeyswitchKeyOwned::from(hpu_ksk.as_view());

    // NB: Some hw modifications such as bit shrinki couldn't be reversed
    cpu_ksk_orig.as_mut().iter_mut().for_each(|coef| {
        let ks_p = hpu_device.params().ks_params;
        // Apply Hw rounding
        // Extract info bits and rounding if required
        let coef_info = *coef >> (u64::BITS - ks_p.width as u32);
        let coef_rounding = if (ks_p.width as u32) < u64::BITS {
            (*coef >> (u64::BITS - (ks_p.width + 1) as u32)) & 0x1
        } else {
            0
        };
        *coef = (coef_info + coef_rounding) << (u64::BITS - ks_p.width as u32);
    });

    let ksk_mismatch: usize =
        std::iter::zip(cpu_ksk_orig.as_ref().iter(), cpu_ksk_lb.as_ref().iter())
            .enumerate()
            .map(|(i, (x, y))| {
                if x != y {
                    println!("Ksk mismatch @{i}:: {x:x} != {y:x}");
                    1
                } else {
                    0
                }
            })
            .sum();

    // BSK Loopback conversion and check -------------------------------------
    let cpu_bsk_orig = match sks.bootstrapping_key {
        shortint::server_key::ShortintBootstrappingKey::ClassicNtt(bsk) => bsk,
        _ => panic!("BootstrapKey loopback only work on NttLweBootstrappingKey"),
    };

    let hpu_bsk = HpuLweBootstrapKeyOwned::from_with(cpu_bsk_orig.as_view(), hpu_device.params());
    let cpu_bsk_lb = NttLweBootstrapKeyOwned::from(hpu_bsk.as_view());

    let bsk_mismatch: usize = std::iter::zip(
        cpu_bsk_orig.as_view().into_container().iter(),
        cpu_bsk_lb.as_view().into_container().iter(),
    )
    .enumerate()
    .map(|(i, (x, y))| {
        if x != y {
            println!("@{i}:: {x:x} != {y:x}");
            1
        } else {
            0
        }
    })
    .sum();

    println!("Ksk loopback with {ksk_mismatch} errors");
    println!("Bsk loopback with {bsk_mismatch} errors");

    assert_eq!(ksk_mismatch + bsk_mismatch, 0);
}
