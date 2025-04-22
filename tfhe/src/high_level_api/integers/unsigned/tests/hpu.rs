use std::sync::LazyLock;
use tfhe_hpu_backend::prelude::HpuDevice;

use crate::high_level_api::tests::setup_default_cpu;
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

static HPU_CLIENT_KEY: LazyLock<ClientKey> = LazyLock::new(|| {
    let config_name = std::env::var("HPU_CONFIG").unwrap();
    let backend_dir = std::env::var("HPU_BACKEND_DIR").unwrap();
    let config_path = format!("{backend_dir}/config_store/{config_name}/hpu_config.toml");

    setup_hpu(&config_path)
});

fn setup_default_hpu() -> ClientKey {
    HPU_CLIENT_KEY.clone()
}

#[test]
fn test_uint8_quickstart_hpu() {
    let client_key = setup_default_hpu();
    super::test_case_uint8_quickstart(&client_key);
}

#[test]
fn test_uint64_quickstart_hpu() {
    let client_key = setup_default_hpu();
    super::test_case_uint64_quickstart(&client_key);
}

#[test]
fn test_uint8_compare_hpu() {
    let client_key = setup_default_hpu();
    super::test_case_uint8_compare(&client_key);
}

#[test]
fn test_uint32_bitwise() {
    let client_key = setup_default_cpu();
    super::test_case_uint32_bitwise(&client_key);
}
