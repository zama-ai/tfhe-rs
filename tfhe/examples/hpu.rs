#[cfg(feature = "hpu")]
fn main() {
    use tfhe::prelude::*;
    use tfhe::{set_server_key, ClientKey, CompressedServerKey, Config, FheUint8};
    use tfhe_hpu_backend::prelude::*;

    // Instanciate HpuDevice --------------------------------------------------
    let hpu_device = HpuDevice::from_config("backends/tfhe-hpu-backend/config/hpu_config.toml");
    println!("{:?}", hpu_device.params());

    let config = Config::from_hpu_device(&hpu_device);

    // Generate Keys
    let cks = ClientKey::generate(config);
    let csks = CompressedServerKey::new(&cks);

    set_server_key((hpu_device, csks));

    let a = FheUint8::encrypt(255u8, &cks);
    let b = FheUint8::encrypt(2u8, &cks);

    let c = a + b;
    c.wait();
    let dc: u16 = c.decrypt(&cks);
    println!("{dc}");
    assert_eq!(c.current_device(), tfhe::Device::Hpu);
}

#[cfg(not(feature = "hpu"))]
fn main() {}
