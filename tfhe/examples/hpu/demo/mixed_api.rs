use tfhe::prelude::*;
use tfhe::*;
use tfhe_hpu_backend::prelude::*;

use rand::Rng;

// Some utilities to report execution time of each section
mod util;
use util::*;

pub fn main() {
    // Register tracing subscriber that use env-filter
    // Select verbosity with env_var: e.g. `RUST_LOG=Alu=trace`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        // Display source code file paths
        .with_file(false)
        // Display source code line numbers
        .with_line_number(false)
        .without_time()
        // Build & register the subscriber
        .init();

    // Instanciate HpuDevice --------------------------------------------------
    let config_name =
        ShellString("${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string());
    let hpu_device = HpuDevice::from_config(&config_name.expand());

    // Extract pbs_configuration from Hpu and generate top-level config
    let pbs_params = tfhe::shortint::PBSParameters::PBS(hpu_device.params().into());
    let config = ConfigBuilder::default()
        .use_custom_parameters(pbs_params)
        .build();

    // Generate Keys
    let (cks, sks) = generate_keys(config);
    let sks_compressed = cks.generate_compressed_server_key();

    // Init cpu side server keys
    set_server_key(sks);

    // Init Hpu device with server key and firmware
    tfhe::integer::hpu::init_device(&hpu_device, sks_compressed.into());

    // ------------------------------------------------------------------------
    // Plan here is to compute (a.b) ^ c
    // Computation is made at the same time on Cpu & on Hpu to show that both backend
    // could be used at the same time

    // Draw random value as input
    let a = rand::thread_rng().gen_range(0..u8::MAX);
    let b = rand::thread_rng().gen_range(0..u8::MAX);
    let c = rand::thread_rng().gen_range(0..u8::MAX);

    // Encrypt them on Cpu side
    let a_fhe = FheUint8::encrypt(a, &cks);
    let b_fhe = FheUint8::encrypt(b, &cks);
    let c_fhe = FheUint8::encrypt(c, &cks);

    let mut time = Time::begin();
    // Clone a,b,c ciphertext and move them in HpuWorld
    // NB: Data doesn't move over Pcie at this stage
    //     Data are only arranged in Hpu ordered an copy in the host internal buffer
    let a_hpu = a_fhe.clone_on(&hpu_device);
    let b_hpu = b_fhe.clone_on(&hpu_device);
    let c_hpu = c_fhe.clone_on(&hpu_device);

    // Start Compute on Hpu side
    // At this stage Data come across the Pcie interface
    // NB: 3 values synced on Hw side
    let axb_hpu = a_hpu * b_hpu;
    let axb_c_hpu = axb_hpu ^ c_hpu;

    // Compute on Cpu side
    time.cpu_begin();
    let axb_fhe = &a_fhe * &b_fhe;
    let axb_c_fhe = &axb_fhe ^ &c_fhe;
    time.cpu_end();

    // Retrived Hpu result
    // NB: only axb_c is synced back, intermediate result axb never come through the Pcie bridge
    let axb_c_hpu = FheUint8::from(axb_c_hpu);
    time.end();

    // Decrypt, display and compare results
    let cpu_dec: u8 = axb_c_fhe.decrypt(&cks);
    let hpu_dec: u8 = axb_c_hpu.decrypt(&cks);

    println!("Executed operation: ({a} * {b}) ^ {c}");
    println!("Cpu result: {cpu_dec}");
    println!("Hpu result: {hpu_dec}");
    println!("Cpu ^ Hpu: 0x{:x}", cpu_dec ^ hpu_dec);
    println!("Timing report: {time}");

    assert_eq!(cpu_dec, hpu_dec, "Computation mismatch between Cpu & Hpu");
}
