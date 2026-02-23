// tfhe
use tfhe::prelude::*;
// hpu
use crate::tfhe_hpu_backend::prelude::*;
use tfhe::{set_server_key, FheUint64, *};
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
    println!("- hpu demo: matrix multiplication -");
    println!("----------------------------------------------");
    // This examples performs a matrix multiplication between matrix_a and matrix_b
    // matrix_a as m rows and n columns
    // matrix_b as n rows and p columns
    // m=3, n=2 and p=2 can be set using CLI by adding: -- --m=3 --n=2 --p=2

    /// Define CLI arguments
    #[derive(clap::Parser, Debug, Clone, serde::Serialize)]
    #[command(long_about = "HPU example that shows the use of the HighLevelAPI.")]
    pub struct Args {
        #[arg(
            long,
            default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
        )]
        pub config: ShellString,

        /// Number of rows in matrix A
        #[arg(long, default_value_t = 2)]
        pub m: usize,
        /// Number of columns in matrix A and Number of rows in matrix B
        #[arg(long, default_value_t = 2)]
        pub n: usize,
        /// Number of columns in matrix B
        #[arg(long, default_value_t = 2)]
        pub p: usize,
    }
    let args = Args::parse();
    let hpu_device = HpuDevice::from_config(&args.config.expand());

    println!("\n 1. Key generation");
    println!("   Generate client and server keys...");
    // println!("   -> targeting CPU");
    // let config = ConfigBuilder::default().build();
    // let (client_key, server_key) = generate_keys(config);
    println!("   -> targeting HPU");
    let config = Config::from_hpu_device(&hpu_device);
    let client_key = ClientKey::generate(config);
    let server_key = CompressedServerKey::new(&client_key);

    // println!("   Upload keys-material on CPU...");
    // set_server_key(server_key);
    println!("   Upload keys-material on HPU...");
    set_server_key((hpu_device, server_key));

    println!("\n 2. Matrices definition");
    let random_matrix_a = (0..args.m)
        .map(|_| {
            (0..args.n)
                .map(|_| rand::rng().gen::<u64>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<Vec<_>>>();
    let random_matrix_b = (0..args.n)
        .map(|_| {
            (0..args.p)
                .map(|_| rand::rng().gen::<u64>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<Vec<_>>>();

    println!("\n 3. Encrypting the two matrices");
    let encrypted_matrix_a: Vec<Vec<FheUint64>> = random_matrix_a
        .iter()
        .map(|row| {
            row.iter()
                .map(|&val| FheUint64::encrypt(val, &client_key))
                .collect()
        })
        .collect();

    let encrypted_matrix_b: Vec<Vec<FheUint64>> = random_matrix_b
        .iter()
        .map(|row| {
            row.iter()
                .map(|&val| FheUint64::encrypt(val, &client_key))
                .collect()
        })
        .collect();

    println!("\n 4. Triggering operations through hl_api");
    // Do a cartesian product over matrix_a rows and matrix_b cols
    let fhe_result = (0..args.m)
        .map(|i| {
            (0..args.p)
                .map(|j| {
                    (0..args.n).fold(
                        FheUint64::try_encrypt(0u64, &client_key).unwrap(),
                        |acc, k| acc + &encrypted_matrix_a[i][k] * &encrypted_matrix_b[k][j],
                    )
                })
                .collect::<Vec<FheUint64>>()
        })
        .collect::<Vec<Vec<FheUint64>>>();

    println!("\n 5. Wait for computation");
    fhe_result
        .last() // last row
        .expect("Compute over empty row matrix ")
        .last() // last coef of the row
        .expect("Compute over empty column matrix")
        .wait();

    println!("\n 6. Decrypting result");
    let dec_result = fhe_result
        .iter()
        .map(|row| {
            row.iter()
                .map(|x| x.decrypt(&client_key))
                .collect::<Vec<u64>>()
        })
        .collect::<Vec<Vec<u64>>>();

    println!("\n----------------------------------------------");
    println!("- checker: cleartext computation -");
    println!("----------------------------------------------");
    let clear_result = (0..args.m)
        .map(|i| {
            (0..args.p)
                .map(|j| {
                    (0..args.n).fold(0_u64, |acc, k| {
                        acc.wrapping_add(random_matrix_a[i][k].wrapping_mul(random_matrix_b[k][j]))
                    })
                })
                .collect::<Vec<u64>>()
        })
        .collect::<Vec<Vec<u64>>>();
    println!("\n> decrypted result {dec_result:?}");
    println!("> cleartext result {clear_result:?}");

    assert!(clear_result == dec_result, "matrices are not the same");
}
