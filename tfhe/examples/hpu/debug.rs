use tfhe::prelude::*;
use tfhe::*;
use tfhe_hpu_backend::prelude::*;

use rand::Rng;

const TEST_ITERATION: usize = 100;

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

    // Encryption/Decryption round-trip test
    // ------------------------------------------------------------------------
    let mut encdec_errors = 0;
    for i in 0..TEST_ITERATION {
        let clear = rand::thread_rng().gen_range(0..u16::MAX);
        let fhe = FheUint16::encrypt(clear, &cks);
        let dec_fhe: u16 = fhe.decrypt(&cks);
        if dec_fhe != clear {
            println!("EncDec Error@{i}: get {dec_fhe} expect {clear}");
            encdec_errors += 1;
        }
    }
    println!("Encryption/Decription test run {TEST_ITERATION} with {encdec_errors} errors.");
    assert_eq!(0, encdec_errors, "Encryption/Decryption test failed");

    // Mul/Add test
    // ------------------------------------------------------------------------
    let mut cpu_errors = 0;
    let mut hpu_errors = 0;

    for i in 0..TEST_ITERATION {
        // Draw random value as input
        let a = rand::thread_rng().gen_range(0..u16::MAX);
        let b = rand::thread_rng().gen_range(0..u16::MAX);
        let c = rand::thread_rng().gen_range(0..u16::MAX);

        // Encrypt them on Cpu side
        let a_fhe = FheUint16::encrypt(a, &cks);
        let b_fhe = FheUint16::encrypt(b, &cks);
        let c_fhe = FheUint16::encrypt(c, &cks);

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
        let axb_c_hpu = axb_hpu + c_hpu;

        // Compute on Cpu side
        let axb_fhe = &a_fhe * &b_fhe;
        let axb_c_fhe = &axb_fhe + &c_fhe;

        // Retrived Hpu result
        // NB: only axb_c is synced back, intermediate result axb never come through the Pcie bridge
        let axb_c_hpu = FheUint16::from(axb_c_hpu);

        // Decrypt, display and compare results
        let cpu_dec: u16 = axb_c_fhe.decrypt(&cks);
        let hpu_dec: u16 = axb_c_hpu.decrypt(&cks);

        println!("Executed operation: ({a} * {b}) + {c}");
        println!("Cpu result: {cpu_dec}");
        println!("Hpu result: {hpu_dec}");
        println!("Cpu ^ Hpu: 0x{:x}", cpu_dec ^ hpu_dec);

        let clear = a.wrapping_mul(b).wrapping_add(c);
        if clear != cpu_dec {
            println!("CPU Error@{i}: get {cpu_dec} expect {clear}");
            cpu_errors += 1;
        }
        if clear != hpu_dec {
            println!("HPU Error@{i}: get {hpu_dec} expect {clear}");
            hpu_errors += 1;
        }
    }

    assert_eq!(
        0, cpu_errors,
        "Computation mismatch {cpu_errors} time between Cpu_fhe and clear"
    );
    assert_eq!(
        0, hpu_errors,
        "Computation mismatch {hpu_errors} time between Hpu_fhe and clear"
    );
}
