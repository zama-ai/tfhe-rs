use core_crypto::entities::LweCiphertextOwned;
use core_crypto::hpu::from_with::FromWith;
pub use hpu_asm::strum::IntoEnumIterator;
pub use hpu_asm::Asm;
use integer::hpu::ciphertext::HpuRadixCiphertext;
use shortint::parameters::{Degree, NoiseLevel};
use shortint::{Ciphertext, ClassicPBSParameters};
pub use tfhe::prelude::*;
pub use tfhe::*;
pub use tfhe_hpu_backend::prelude::*;

pub use rand::rngs::StdRng;
pub use rand::{Rng, SeedableRng};
pub use std::collections::HashMap;
pub use std::fs::OpenOptions;
pub use std::io::Write;
pub use std::path::Path;
pub use std::time::{Duration, Instant};

/// Define CLI arguments
pub use clap::Parser;
pub use clap_num::maybe_hex;
#[derive(clap::Parser, Debug, Clone, serde::Serialize)]
#[clap(long_about = "HPU trace application: Generate operation at on 1 block only.")]
pub struct Args {
    // Fpga configuration ------------------------------------------------------
    /// Toml top-level configuration file
    #[clap(
        long,
        value_parser,
        default_value = "backends/tfhe-hpu-backend/config/hpu_config.toml"
    )]
    pub config: String,

    // Exec configuration ----------------------------------------------------
    /// Iop to expand and simulate
    /// If None default to All IOp
    #[clap(long, value_parser)]
    pub iop: Vec<hpu_asm::IOpName>,

    /// Force input value for A operand
    /// Warn: Currently force all IOp input A, there is no way to force only some of them
    #[clap(long, value_parser=maybe_hex::<usize>)]
    pub src_a: Option<usize>,

    /// Force input value for B operand
    /// Warn: Currently force all IOp input B, there is no way to force only some of them
    #[clap(long, value_parser=maybe_hex::<usize>)]
    pub src_b: Option<usize>,

    /// Seed used for some rngs
    #[clap(long, value_parser)]
    pub seed: Option<u128>,

    // Debug option ----------------------------------------------------------
    #[cfg(feature = "hpu-debug")]
    /// Hpu io dump path
    #[clap(long, value_parser)]
    pub io_dump: Option<String>,

    // Reports configuration -------------------------------------------------
    /// JsonLine output file
    #[clap(long, value_parser, default_value = "output/hpu_bench.jsonl")]
    pub out_jsonl: String,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub user_args: Args,
    #[serde(flatten)]
    pub perf: HashMap<String, Duration>,
}

fn main() {
    let args = Args::parse();
    println!("User Options: {args:?}");

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

    // Seeder for args randomization ------------------------------------------
    let mut rng: StdRng = if let Some(seed) = args.seed {
        SeedableRng::seed_from_u64((seed & u64::MAX as u128) as u64)
    } else {
        SeedableRng::from_entropy()
    };

    // Hpu io dump for debug  -------------------------------------------------
    #[cfg(feature = "seeder-manual")]
    // Register seed inside tfhe-rs.
    tfhe::core_crypto::seeders::seeder_manual::set_manual_seed(args.seed);

    #[cfg(feature = "hpu-debug")]
    if let Some(dump_path) = args.io_dump.as_ref() {
        set_hpu_io_dump(dump_path);
    }

    // Instanciate HpuDevice --------------------------------------------------
    let hpu_device = {
        let mut config = HpuConfig::from_toml(&args.config);
        config.firmware.integer_w = vec![2];
        HpuDevice::new(config)
    };

    // Extract pbs_configuration from Hpu and generate top-level config
    let mut pbs_params = tfhe::shortint::ClassicPBSParameters::from(hpu_device.params());
    // Modify parameters to force NTT-based PBS
    pbs_params.encryption_key_choice =
        shortint::EncryptionKeyChoice::BigNtt(tfhe::shortint::CiphertextModulus::new(
            hpu_device.params().ntt_params.prime_modulus as u128,
        ));
    // Generate shortint keys
    let (cks, sks) = tfhe::shortint::gen_keys(pbs_params);

    // Init Hpu device with server key and firmware
    tfhe::integer::hpu::init_device_shortint(&hpu_device, sks);

    // Create IOps list ------------------------------------------------------
    let bench_iop = if !args.iop.is_empty() {
        args.iop.clone()
    } else {
        hpu_asm::IOpName::iter()
            .filter(|x| !(x.to_string().contains("CUST") | x.to_string().contains("CTL")))
            .collect::<Vec<_>>()
    };

    // Benchmark body --------------------------------------------------------
    let mut perf_report = HashMap::new();
    for iop in bench_iop {
        let imm_fmt = hpu_asm::IOp::from(iop).has_imm();

        // Generate clear value
        let a = if let Some(val) = args.src_a {
            val as u8
        } else {
            rng.gen_range(0..2)
        };

        let b = if let Some(val) = args.src_b {
            val as u8
        } else {
            rng.gen_range(0..2)
        };

        // Encrypt on cpu side
        // Use inner shortint ciphertext representation
        let a_fhe = cks.encrypt(a as u64);
        let b_fhe = cks.encrypt(b as u64);

        // Copy value in Hpu world
        // Use inner shortint API
        let a_hpu = {
            let hpu_ct = HpuLweCiphertextOwned::from_with(a_fhe.ct.as_view(), hpu_device.params());
            HpuRadixCiphertext::new(hpu_device.new_var_from(vec![hpu_ct]))
        };
        let b_hpu = {
            let hpu_ct = HpuLweCiphertextOwned::from_with(b_fhe.ct.as_view(), hpu_device.params());
            HpuRadixCiphertext::new(hpu_device.new_var_from(vec![hpu_ct]))
        };

        println!("Start execution trace for IOp {iop} ...");
        let roi_start = Instant::now();

        let res_hpu = if imm_fmt {
            a_hpu.into_var().iop_imm(iop, b as usize)
        } else {
            a_hpu.into_var().iop_ct(iop, b_hpu.into_var())
        };

        let res_fhe = {
            let pbs_p = ClassicPBSParameters::from(hpu_device.params());
            let hpu_ct = res_hpu.into_ct();
            let cpu_ct = LweCiphertextOwned::from(hpu_ct[0].as_view());
            // Hpu output clean ciphertext without carry
            Ciphertext::new(
                cpu_ct,
                Degree::new(pbs_p.message_modulus.0),
                NoiseLevel::NOMINAL,
                pbs_p.message_modulus,
                pbs_p.carry_modulus,
                pbs_p.encryption_key_choice.into(),
            )
        };

        let roi_duration = roi_start.elapsed();
        let op_duration = roi_duration;
        let res: u8 = cks.decrypt(&res_fhe) as u8;
        println!("Performance: {iop} -> {op_duration:?} [{roi_duration:?}]");
        println!("Behavior         : {res} <- {a} [{iop} {b}]",);
        println!("Behavior (in hex): {res:x} <- {a:x} [{iop} {b:x}]",);
        perf_report.insert(iop.to_string(), op_duration);
    }

    // Display report ----------------------------------------------------------
    println!("Benchmark report: ---------------------------------------------------");
    for (op, dur) in perf_report.iter() {
        println!(" {op} -> {dur:?}");
    }
    println!("---------------------------------------------------------------------");

    // JsonL report ------------------------------------------------------------
    // open file
    let mut out_f = {
        let filepath = Path::new(&args.out_jsonl);
        if let Some(dirpath) = filepath.parent() {
            std::fs::create_dir_all(dirpath).unwrap();
        }

        OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(filepath)
            .unwrap()
    };

    // gather user args and execution properties
    let full_report = Report {
        user_args: args,
        perf: perf_report,
    };
    // serialize in it file
    writeln!(out_f, "{}", serde_json::to_string(&full_report).unwrap()).unwrap();
}
