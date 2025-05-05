// tfhe
use tfhe::prelude::*;
// hpu
use crate::tfhe_hpu_backend::prelude::ShellString;
use crate::tfhe_hpu_backend::prelude::*;
use tfhe::{set_server_key, FheUint64, *};
// cpu
// use tfhe::{set_server_key, generate_keys, FheUint64, ConfigBuilder, *};
// misc
pub use clap::Parser;
use rand::Rng;

fn main() {
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

    println!("\n----------------------------------------------");
    println!("- hpu demo: matrix x vector multiplication -");
    println!("----------------------------------------------");
    /// Define CLI arguments
    #[derive(clap::Parser, Debug, Clone, serde::Serialize)]
    #[clap(long_about = "HPU example that shows the use of the HighLevelAPI.")]

    pub struct Args {
        #[clap(
            long,
            value_parser,
            default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
        )]
        pub config: ShellString,

        /// Dimension of the matrix
        #[clap(long, value_parser, default_value_t = 5)]
        pub dimension: usize,
    }
    let args = Args::parse();
    let hpu_device = HpuDevice::from_config(&args.config.expand());

    println!("\n 1. Key generation");
    // let config = ConfigBuilder::default().build(); // CPU
    // let (client_key, server_key) = generate_keys(config); // CPU
    //
    println!("   Generate client and server keys...");
    let config = Config::from_hpu_device(&hpu_device);
    let client_key = ClientKey::generate(config);
    let server_key = CompressedServerKey::new(&client_key);

    println!("   Upload keys-material on HPU...");
    set_server_key((hpu_device, server_key));
    // set_server_key(server_key); // CPU

    println!("\n 2. Matrix and vector definition");
    let random_vector = (0..args.dimension)
        .map(|_| rand::thread_rng().gen::<u64>())
        .collect::<Vec<_>>();
    let random_matrix = (0..args.dimension)
        .map(|_| {
            (0..args.dimension)
                .map(|_| rand::thread_rng().gen::<u64>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<Vec<_>>>();

    println!("\n 3. Encrypting matrix and vector");
    let encrypted_vector = random_vector
        .iter()
        .map(|&val| FheUint64::encrypt(val, &client_key))
        .collect::<Vec<FheUint64>>();

    let encrypted_matrix: Vec<Vec<FheUint64>> = random_matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|&val| FheUint64::encrypt(val, &client_key))
                .collect()
        })
        .collect();

    println!("\n 4. Triggering operations through hl_api");
    // Iterate over matrix row and do a cartesian product with the vector
    let fhe_result = encrypted_matrix
        .iter()
        .map(|row| {
            row.iter().enumerate().fold(
                FheUint64::try_encrypt(0u64, &client_key).unwrap(),
                |acc, (j, x)| acc + x * &encrypted_vector[j],
            )
        })
        .collect::<Vec<_>>();

    println!("\n 5. Wait for computation");
    fhe_result
        .last()
        .expect("Compute over empty matrix or vector")
        .wait();

    println!("\n 6. Decrypting result");
    let dec_result = fhe_result
        .iter()
        .map(|ct| ct.decrypt(&client_key))
        .collect::<Vec<u64>>();

    println!("\n----------------------------------------------");
    println!("- checker: cleartext computation -");
    println!("----------------------------------------------");
    let clear_result = random_matrix
        .iter()
        .map(|row| {
            row.iter().enumerate().fold(0_u64, |acc, (j, x)| {
                acc.wrapping_add(x.wrapping_mul(random_vector[j]))
            })
        })
        .collect::<Vec<_>>();
    println!("\n> decrypted result {:?}", dec_result);
    println!("> cleartext result {:?}", clear_result);

    assert!(clear_result == dec_result, "vectors are not the same");
}
