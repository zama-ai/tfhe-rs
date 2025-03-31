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
        let config_file = ShellString::new(
            "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string(),
        );
        let config = HpuConfig::from_toml(&config_file.expand());
        HpuDevice::new(config)
    };

    // Generate Keys ---------------------------------------------------------
    let pbs_params = tfhe::shortint::PBSParameters::PBS(hpu_device.params().into());
    let config = ConfigBuilder::default()
        .use_custom_parameters(pbs_params)
        .build();

    // Generate Keys
    let (cks, _sks) = generate_keys(config);
    let sks_compressed =
        tfhe::integer::CompressedServerKey::from(cks.generate_compressed_server_key())
            .into_raw_parts();

    // KSK Loopback conversion and check -------------------------------------
    // Extract and convert ksk
    let mut cpu_ksk_orig = sks_compressed
        .key_switching_key
        .decompress_into_lwe_keyswitch_key();
    let hpu_ksk =
        HpuLweKeyswitchKeyOwned::from_with(cpu_ksk_orig.as_view(), hpu_device.params().clone());
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
    // Extract and convert ksk
    let cpu_bsk_orig = match sks_compressed.bootstrapping_key {
        crate::shortint::server_key::ShortintCompressedBootstrappingKey::Classic {
            bsk: seeded_bsk,
            ..
        } => seeded_bsk.decompress_into_lwe_bootstrap_key(),
        crate::shortint::server_key::ShortintCompressedBootstrappingKey::MultiBit { .. } => {
            panic!("Hpu currently not support multibit. Required a Classic BSK")
        }
    };
    let cpu_bsk_ntt = {
        // Convert the LweBootstrapKey in Ntt domain
        let mut ntt_bsk = NttLweBootstrapKeyOwned::<u64>::new(
            0_u64,
            cpu_bsk_orig.input_lwe_dimension(),
            cpu_bsk_orig.glwe_size(),
            cpu_bsk_orig.polynomial_size(),
            cpu_bsk_orig.decomposition_base_log(),
            cpu_bsk_orig.decomposition_level_count(),
            CiphertextModulus::new(hpu_device.params().ntt_params.prime_modulus as u128),
        );

        // Conversion to ntt domain
        par_convert_standard_lwe_bootstrap_key_to_ntt64(&cpu_bsk_orig, &mut ntt_bsk);
        ntt_bsk
    };
    let hpu_bsk =
        HpuLweBootstrapKeyOwned::from_with(cpu_bsk_orig.as_view(), hpu_device.params().clone());

    let cpu_bsk_lb = NttLweBootstrapKeyOwned::from(hpu_bsk.as_view());

    let bsk_mismatch: usize = std::iter::zip(
        cpu_bsk_ntt.as_view().into_container().iter(),
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
