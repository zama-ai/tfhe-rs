//! Application dedicated to RTL stimulus generation
//! This should be used in tandem with `mockups/tfhe-hpu-mockup/src/mockup.rs
//!
//! With the `dump-out` option it enable to generate bit-accurate stimulus
//! for RTL simulation

use std::collections::HashMap;
pub use std::time::{Duration, Instant};

use itertools::Itertools;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::prelude::*;
use tfhe::*;
use tfhe_hpu_backend::prelude::*;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const AVAILABLE_INTEGER_W: [usize; 11] = [2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128];

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
    /// Select integer-width from a set of available one.
    /// C.f. `AVAILABLE_INTEGER_W` for available option
    /// WARN: Used configuration should have the selected integer in the Firmware section
    /// If None default to All available one
    #[clap(long, value_parser)]
    pub integer_w: Vec<usize>,

    /// Iop to expand and simulate
    /// If None default to All IOp
    #[clap(long, value_parser)]
    pub iop: Vec<hpu_asm::AsmIOpcode>,

    /// Number of iteration for each IOp
    #[clap(long, value_parser, default_value_t = 1)]
    pub iter: usize,

    /// Force input value for A operand
    #[clap(long, value_parser=maybe_hex::<u128>)]
    pub src_a: Option<u128>,

    /// Force input value for B operand
    #[clap(long, value_parser=maybe_hex::<u128>)]
    pub src_b: Option<u128>,

    /// Force immediat mode
    /// Use for custom IOp testing
    /// Currently there is no way for the SW to know the expected format of the custom IOp
    /// Warn: Currently force all IOp input B, there is no way to force only some of them
    #[clap(long, value_parser)]
    pub force_imm: bool,

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
}

#[derive(Debug)]
pub struct BenchReport(HashMap<String, Duration>);

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

    // Instanciate HpuDevice --------------------------------------------------
    let hpu_device = HpuDevice::from_config(&args.config.expand());

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
    let (integer_sks_compressed, ..) = sks_compressed.into_raw_parts();
    tfhe::integer::hpu::init_device(&hpu_device, integer_sks_compressed);

    // Create IOps/Width list ------------------------------------------------
    let bench_iop = if !args.iop.is_empty() {
        args.iop.clone()
    } else {
        hpu_asm::iop::IOP_LIST.to_vec()
    };

    let bench_w = if !args.integer_w.is_empty() {
        args.integer_w.clone()
    } else {
        Vec::from(AVAILABLE_INTEGER_W.as_slice())
    };

    // Execute based on required integer_w ------------------------------------
    let mut report = Vec::with_capacity(bench_w.len());
    for width in bench_w.iter() {
        // Stimulus generation body -----------------------------------------------
        // Generate clear value
        let a = if let Some(val) = args.src_a {
            val
        } else {
            rng.gen_range(0..(u128::max_value() >> (u128::BITS - (*width as u32))))
        };

        let b = if let Some(val) = args.src_b {
            val
        } else {
            rng.gen_range(0..(u128::max_value() >> (u128::BITS - (*width as u32))))
        };

        let rep = match width {
            2 => {
                impl_bench_body!(FheUint2, u8);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            4 => {
                impl_bench_body!(FheUint4, u8);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            6 => {
                impl_bench_body!(FheUint6, u8);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            8 => {
                impl_bench_body!(FheUint8, u8);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            10 => {
                impl_bench_body!(FheUint10, u16);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            12 => {
                impl_bench_body!(FheUint12, u16);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            14 => {
                impl_bench_body!(FheUint14, u16);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            16 => {
                impl_bench_body!(FheUint16, u16);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            32 => {
                impl_bench_body!(FheUint32, u32);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            64 => {
                impl_bench_body!(FheUint64, u64);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            128 => {
                impl_bench_body!(FheUint128, u128);
                bench_body(
                    &hpu_device,
                    &cks,
                    &bench_iop,
                    args.iter,
                    a,
                    b,
                    args.force_imm,
                    args.trivial,
                )
            }
            _ => panic!(
                "Unsupported integer_w {width}. Supported values are {AVAILABLE_INTEGER_W:?}",
            ),
        };
        report.push((format!("FheUint{width}"), rep));
    }

    // Display summary report ----------------------------------------------------------
    println!("--------------------------------------------------------------------------------");
    for (width, perf) in report {
        println!("________________________________________");
        println!("Benchmark report for {width}bit integer:");
        println!("{perf}");
        println!("________________________________________");
    }
    println!("--------------------------------------------------------------------------------");
    if let Some(io_dump) = args.io_dump {
        println!("Stimulus generated in {io_dump}");
    } else {
        println!("No stimulus generated. C.f. `--iop-dump` for more information");
    }
}

#[macro_export]
macro_rules! impl_bench_body {
    ($fhe_type: ty, $user_type: ty) => {
        ::paste::paste! {
        fn bench_body(
            hpu_device: &HpuDevice,
            cks: &ClientKey,
            iops: &[hpu_asm::AsmIOpcode],
            iter: usize,
            src_a: u128,
            src_b: u128,
            force_imm: bool,
            trivial: bool
        ) -> BenchReport  {
            let mut bench_report = BenchReport::new();
            for iop in iops {
                let imm_fmt = iop.has_imm() || force_imm;

                // Encrypt on cpu side
                let (a_fhe, b_fhe) = if trivial {
                    ($fhe_type::encrypt_trivial(src_a as $user_type), $fhe_type::encrypt_trivial(src_b as $user_type))
                } else {
                    ($fhe_type::encrypt(src_a as $user_type, cks), $fhe_type::encrypt(src_b as $user_type, cks))
                };

                // Copy value in Hpu world
                let a_hpu = a_fhe.clone_on(&hpu_device);
                let b_hpu = b_fhe.clone_on(&hpu_device);

                // Iteration over same operation reuse previous result
                // in the following manner: res_{i} = res_{i-1} OP src_b
                println!("{}:: Start test loop for IOp {iop} ...", stringify!($fhe_type));
                let roi_start = Instant::now();

                let res_hpu = if imm_fmt {
                    (1..iter).fold(a_hpu.iop_imm(iop.opcode(), src_b as usize), |acc, _val| {
                        acc.iop_imm(iop.opcode(), src_b as usize)
                    })
                } else {
                    (1..iter).fold(a_hpu.iop_ct(iop.opcode(), b_hpu.clone()), |acc, _val| {
                        acc.iop_ct(iop.opcode(), b_hpu.clone())
                    })
                };
                let res_fhe = $fhe_type::from(res_hpu);
                let roi_duration = roi_start.elapsed();
                let op_duration = roi_duration / (iter as u32);
                let res: $user_type = res_fhe.decrypt(&cks);
                println!("{}:: Execution report: {iop}", stringify!($fhe_type));
                println!("Behavior         : {res} <- {src_a} [{iop} {src_b}]{{{iter}}}");
                println!("Behavior (in hex): {res:x} <- {src_a:x} [{iop} {src_b:x}]{{{iter}}}");
                println!("Performance: {iop} -> {op_duration:?} [{roi_duration:?}]");
                bench_report.insert(iop.to_string(), op_duration);
            }
            bench_report
        }
        };
    };
}
