use tfhe_hpu_backend::prelude::HpuDevice;

use crate::{set_server_key, ClientKey, CompressedServerKey, Config};

fn setup_hpu(hpu_device_cfg_path: &str) -> ClientKey {
    let hpu_device = HpuDevice::from_config(hpu_device_cfg_path);

    let config = Config::from_hpu_device(&hpu_device);

    // Generate Keys
    let cks = ClientKey::generate(config);
    let csks = CompressedServerKey::new(&cks);

    set_server_key((hpu_device, csks));

    cks
}

fn setup_default_hpu() -> ClientKey {
    let config_path = std::env::var("TFHE_HPU_CONFIG")
        .map(|x| x.to_string())
        .unwrap();
    setup_hpu(&config_path)
}

#[test]
fn test_uint8_quickstart_hpu() {
    let client_key = setup_default_hpu();
    super::test_case_uint8_quickstart(&client_key);
}
