//! Application dedicated to quick HW test/benchmark and RTL stimulus generation
//! This could be used in tandem with `mockups/tfhe-hpu-mockup/src/mockup.rs or
//! with the real hardware directly.
//!
//! With the `dump-out` option it enable to generate bit-accurate stimulus
//! for RTL simulation

use std::collections::{HashMap, HashSet};
pub use std::time::{Duration, Instant};

use integer::hpu::ciphertext::HpuRadixCiphertext;
use tfhe::integer::{ClientKey, CompressedServerKey, ServerKey};

use itertools::Itertools;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::parameters::KeySwitch32PBSParameters;
use tfhe::*;
use tfhe_hpu_backend::prelude::*;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Define CLI arguments
pub use clap::Parser;
pub use clap_num::maybe_hex;
#[derive(clap::Parser, Debug, Clone, serde::Serialize)]
#[clap(
    long_about = "HPU stimulus generation application: Start operation on HPU for RTL test purpose."
)]
pub struct Args {
    // Fpga configuration ------------------------------------------------------
    /// Toml top-level configuration file
    #[clap(
        long,
        value_parser,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
    )]
    pub config: ShellString,

    // Exec configuration ----------------------------------------------------
    /// Select integer width to bench
    /// If None default to All available one (c.f. Firmware configuration)
    #[clap(long, value_parser)]
    pub integer_w: Vec<usize>,

    /// Iop to expand and simulate
    /// If None default to All IOp
    #[clap(long, value_parser)]
    pub iop: Vec<hpu_asm::AsmIOpcode>,

    /// Number of iteration for each IOp
    #[clap(long, value_parser, default_value_t = 1)]
    pub iter: usize,

    /// Force ct input values
    #[clap(long, value_parser=maybe_hex::<u128>)]
    pub src: Vec<u128>,

    /// Force immediat input values
    #[clap(long, value_parser=maybe_hex::<u128>)]
    pub imm: Vec<u128>,

    /// Fallback prototype
    /// Only apply to IOp with unspecified prototype
    /// Used for custom IOp testing when prototype isn't known
    /// Syntax example: "<N B> <- <N N> <0>"
    /// Each entry options are (case incensitive):
    /// * N, Nat, Native -> Full size integer;
    /// * H, Half -> Half size integer;
    /// * B, Bool -> boolean value;
    #[clap(long, value_parser)]
    pub user_proto: Option<hpu_asm::IOpProto>,

    /// Seed used for some rngs
    #[clap(long, value_parser)]
    pub seed: Option<u128>,

    // Debug option ----------------------------------------------------------
    #[cfg(feature = "hpu-debug")]
    /// Hpu io dump path
    #[clap(long, value_parser)]
    pub io_dump: Option<String>,

    /// Use trivial encrypt ciphertext
    #[clap(long, value_parser)]
    pub trivial: bool,

    /// Override the firmware implementation used
    #[clap(long, value_parser)]
    pub fw_impl: Option<String>,
}

#[derive(Debug)]
pub struct BenchReport(HashMap<String, Duration>);

impl Default for BenchReport {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchReport {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
}

impl std::ops::Deref for BenchReport {
    type Target = HashMap<String, Duration>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for BenchReport {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Display for BenchReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for op in self.keys().sorted() {
            writeln!(f, " {op} -> {:?}", self[op])?;
        }
        Ok(())
    }
}

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
    #[cfg(feature = "hpu-debug")]
    if let Some(dump_path) = args.io_dump.as_ref() {
        set_hpu_io_dump(dump_path);
    }

    // Override some configuration settings
    let mut hpu_config = HpuConfig::from_toml(args.config.expand().as_str());
    if let Some(name) = args.fw_impl {
        hpu_config.firmware.implementation = name;
    }

    // Instantiate HpuDevice --------------------------------------------------
    let hpu_device = HpuDevice::new(hpu_config);

    // Force key seeder if seed specified by user
    if let Some(seed) = args.seed {
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        let shortint_engine = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder);
        crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            std::mem::replace(engine, shortint_engine)
        });
    }

    // Extract pbs_configuration from Hpu and create Client/Server Key
    let cks = ClientKey::new(KeySwitch32PBSParameters::from(hpu_device.params()));
    let sks = ServerKey::new_radix_server_key(&cks);
    let sks_compressed = CompressedServerKey::new_radix_compressed_server_key(&cks);

    // Init Hpu device with server key and firmware
    tfhe::integer::hpu::init_device(&hpu_device, sks_compressed).expect("Invalid key");

    // Create IOps/Width list ------------------------------------------------
    let bench_iop = if !args.iop.is_empty() {
        args.iop.clone()
    } else {
        hpu_asm::iop::IOP_LIST.to_vec()
    };

    let bench_w = if !args.integer_w.is_empty() {
        HashSet::from_iter(args.integer_w.iter().cloned())
    } else {
        hpu_device.config().firmware.integer_w.clone()
    };

    assert!(
        bench_w.is_subset(&hpu_device.config().firmware.integer_w),
        "Requested integer width {:?} isn't enabled [Hpu: {:?}] and could lead to Undefined Behavior.",
        bench_w,
        hpu_device.config().firmware.integer_w
    );

    // Execute based on required integer_w ------------------------------------
    let mut report = Vec::with_capacity(bench_w.len());
    for width in bench_w.iter() {
        let num_block = width / hpu_device.params().pbs_params.message_width;

        let mut width_report = BenchReport::new();
        for iop in bench_iop.iter() {
            let proto = if let Some(format) = iop.format() {
                format.proto.clone()
            } else {
                args.user_proto.clone().expect(
                    "Use of user defined IOp required a explicit prototype -> C.f. --user-proto",
                )
            };

            let (srcs_clear, srcs_enc): (Vec<_>, Vec<_>) = proto
                .src
                .iter()
                .enumerate()
                .map(|(pos, mode)| {
                    let (bw, block) = match mode {
                        hpu_asm::iop::VarMode::Native => (*width, num_block),
                        hpu_asm::iop::VarMode::Half => (width / 2, num_block / 2),
                        hpu_asm::iop::VarMode::Bool => (1, 1),
                    };

                    let clear = *args
                        .src
                        .get(pos)
                        .unwrap_or(&rng.gen_range(0..=u128::MAX >> (u128::BITS - (bw as u32))));
                    let fhe = if args.trivial {
                        sks.create_trivial_radix(clear, block)
                    } else {
                        cks.encrypt_radix(clear, block)
                    };
                    let hpu_fhe = HpuRadixCiphertext::from_radix_ciphertext(&fhe, &hpu_device);
                    (clear, hpu_fhe)
                })
                .unzip();

            let imms = (0..proto.imm)
                .map(|pos| {
                    *args
                        .imm
                        .get(pos)
                        .unwrap_or(&rng.gen_range(0..u128::MAX >> (u128::BITS - (*width as u32))))
                })
                .collect::<Vec<_>>();

            println!(
                "{}:: Start test loop for IOp {iop} ...",
                stringify!($fhe_type)
            );
            let roi_start = Instant::now();

            let res_hpu = (0..args.iter)
                .filter_map(|i| {
                    let res = HpuRadixCiphertext::exec(&proto, iop.opcode(), &srcs_enc, &imms);
                    if i == (args.iter - 1) {
                        Some(res)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            let res_fhe = res_hpu
                .last()
                .expect("Iteration must be greater than 0")
                .iter()
                .map(|x| x.to_radix_ciphertext())
                .collect::<Vec<_>>();
            let roi_duration = roi_start.elapsed();
            let op_duration = roi_duration / (args.iter as u32);
            let res = res_fhe
                .iter()
                .map(|x| cks.decrypt_radix(x))
                .collect::<Vec<u128>>();
            println!("Integer_{width}b:: Execution report: {iop}");
            println!(
                "Behavior         : {res:?}  <- {iop} <{:?}> <{:?}> {{{}}}",
                srcs_clear, imms, args.iter
            );
            println!(
                "Behavior (in hex): {res:x?}  <- {iop} <{:x?}> <{:x?}> {{{}}}",
                srcs_clear, imms, args.iter
            );
            println!("Performance: {iop} -> {op_duration:?} [{roi_duration:?}]");
            width_report.insert(iop.to_string(), op_duration);
        }
        report.push((format!("Integer_{width}"), width_report));

        // Prevent potential performance dropdown due to memory fragrmentation
        hpu_device.mem_sanitizer();
    }

    // Display summary report ----------------------------------------------------------
    println!("--------------------------------------------------------------------------------");
    for (name, perf) in report {
        println!("________________________________________");
        println!("Benchmark report for {name}:");
        println!("{perf}");
        println!("________________________________________");
    }
    println!("--------------------------------------------------------------------------------");
    #[cfg(feature = "hpu-debug")]
    if let Some(io_dump) = args.io_dump {
        println!("Stimulus generated in {io_dump}");
    } else {
        println!("No stimulus generated. C.f. `--iop-dump` for more information");
    }
}
