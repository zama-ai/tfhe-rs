pub use hpu_asm::strum::IntoEnumIterator;
pub use hpu_asm::Asm;
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
#[clap(
    long_about = "HPU benchmark application: Start operation on HPU in a loop and report performences."
)]
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

    /// Number of iteration for each IOp
    #[clap(long, value_parser, default_value_t = 1)]
    pub iter: usize,

    /// Force input value for A operand
    /// Warn: Currently force all IOp input A, there is no way to force only some of them
    #[clap(long, value_parser=maybe_hex::<usize>)]
    pub src_a: Option<usize>,

    /// Force input value for B operand
    /// Warn: Currently force all IOp input B, there is no way to force only some of them
    #[clap(long, value_parser=maybe_hex::<usize>)]
    pub src_b: Option<usize>,

    /// Check that result match expected one
    #[clap(long, value_parser)]
    pub check: Vec<usize>,

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

#[macro_export]
macro_rules! impl_hpu_bench {
    ($fhe_type: ty, $fhe_id: ty, $user_type: ty, $user_size: tt) => {
        ::paste::paste! {
        pub fn main() {
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
            #[cfg(feature="hpu-debug")]
            if let Some(dump_path) = args.io_dump.as_ref()
            {
                set_hpu_io_dump(dump_path);
            }

            // Instanciate HpuDevice --------------------------------------------------
            let hpu_device = {
                let mut config = HpuConfig::read_from(&args.config);
                config.firmware.integer_w = vec![$user_size];
                HpuDevice::new(config)
            };


            // Extract pbs_configuration from Hpu and generate top-level config
            let pbs_params = tfhe::shortint::PBSParameters::PBS(hpu_device.params().into());
            let config = ConfigBuilder::default()
                .use_custom_parameters(pbs_params)
                .build();

            // Force key seeder if seed specified by user
            if let Some(seed) = args.seed {
                let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
                let shortint_engine = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder);
                crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
                    std::mem::replace(engine, shortint_engine)
                });
            }

            let (cks, sks) = generate_keys(config);
            let sks_compressed = cks.generate_compressed_server_key();

            // Init cpu side server keys
            set_server_key(sks);

            // Init Hpu device with server key and firmware
            tfhe::integer::hpu::init_device(&hpu_device, sks_compressed.into());
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
                    val as $user_type
                } else {
                    rng.gen_range(0..$user_type::MAX)
                };

                let b = if let Some(val) = args.src_b {
                    val as $user_type
                } else {
                    rng.gen_range(0..$user_type::MAX)
                };

                // Encrypt on cpu side
                let a_fhe = $fhe_type::encrypt(a, &cks);
                let b_fhe = $fhe_type::encrypt(b, &cks);

                // Copy value in Hpu world
                let a_hpu = a_fhe.clone_on(&hpu_device);
                let b_hpu = b_fhe.clone_on(&hpu_device);

                // Iteration over same operation reuse previous result
                // in the following manner: res_{i} = res_{i-1} OP src_b
                println!("Start test loop for IOp {iop} ...");
                let roi_start = Instant::now();

                let res_hpu = if imm_fmt {
                    (1..args.iter).fold(a_hpu.iop_imm(iop, b as usize), |acc, _val| {
                        acc.iop_imm(iop, b as usize)
                    })
                } else {
                    (1..args.iter).fold(a_hpu.iop_ct(iop, b_hpu.clone()), |acc, _val| {
                        acc.iop_ct(iop, b_hpu.clone())
                    })
                };
                let res_fhe = $fhe_type::from(res_hpu);
                let roi_duration = roi_start.elapsed();
                let op_duration = roi_duration / (args.iter as u32);
                let res: $user_type = res_fhe.decrypt(&cks);
                println!("Performance: {iop} -> {op_duration:?} [{roi_duration:?}]");
                println!(
                    "Behavior         : {res} <- {a} [{iop} {b}]{{{}}}",
                    args.iter
                );
                println!(
                    "Behavior (in hex): {res:x} <- {a:x} [{iop} {b:x}]{{{}}}",
                    args.iter
                );
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

                }
    };
}
