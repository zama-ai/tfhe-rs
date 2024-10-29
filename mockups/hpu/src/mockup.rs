//! Hpu Simulation mockup
//! Emulate Hpu behavior for simulation
//! Enable to test tfhe-rs application that required tfhe-hpu-backend without the real hardware.
//! It rely on the `ffi-sim` interface of `tfhe-hpu-backend` and on ipc-channel for communication
//!
//! WARN: User must start the HpuSim mockup before tfhe-rs application

use rand::rngs::StdRng;
use rand::SeedableRng;

use hpu_sim::{HpuSim, MockupParameters};
use tfhe::tfhe_hpu_backend::prelude::*;

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "Hpu Simulation mockup.")]
pub struct Args {
    // Configuration ----------------------------------------------------
    /// Fpga fake configuration
    /// Enable to retrieved ipc_name, register_file and board definition
    #[clap(
        long,
        value_parser,
        default_value = "backends/tfhe-hpu-backend/config/hpu_config.toml"
    )]
    pub config: String,

    /// Hpu inner parameters
    // Parameters are gather in a file to easily switch between predefined
    // configuration.
    #[clap(
        long,
        value_parser,
        default_value = "mockups/hpu/params/tfhers_64b.ron"
    )]
    pub params: String,

    // Arch configuration ----------------------------------------------------
    // Used to override some parameters at runtime
    /// Integer bit width
    #[clap(long, value_parser)]
    integer_w: Option<usize>,

    /// Frequency in HZ
    /// Only use for report display
    #[clap(long, value_parser)]
    freq_hz: Option<usize>,

    /// Number of Register
    #[clap(long, value_parser)]
    register: Option<usize>,

    /// HPU lookahead buffer depth
    /// Number of instruction that are considered in advance
    #[clap(long, value_parser)]
    isc_depth: Option<usize>,

    /// ALUs configuration file path
    /// Cf. config folder or cfg_gen bin for generation
    #[clap(long, value_parser)]
    alu_cfg: Option<String>,

    // Exec configuration ----------------------------------------------------
    /// Seed used for some rngs
    #[clap(long, value_parser)]
    seed: Option<u128>,

    // Reports configuration -------------------------------------------------
    /// log output file
    #[clap(long, value_parser, default_value = "output/sim.log")]
    out_log: String,

    /// dump output dir
    #[clap(long, value_parser)]
    out_dump: Option<String>,

    /// dump intermediate register value
    #[clap(long, value_parser)]
    dump_reg: bool,

    /// JsonLine output file
    #[clap(long, value_parser, default_value = "output/sim.jsonl")]
    out_jsonl: String,
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

    // Load parameters from configuration file ------------------------------------
    let config = HpuConfig::read_from(&args.config);
    let params = {
        let mut params = MockupParameters::from_ron(&args.params);
        // TODO enable back CLI override
        // // Override some parameters if required
        // if let Some(integer_w) = args.integer_w.as_ref() {
        //     params.integer_w = *integer_w;
        // }
        // if let Some(register) = args.register.as_ref() {
        //     params.core_params.register = *register;
        // }
        // if let Some(isc_depth) = args.isc_depth.as_ref() {
        //     params.core_params.isc_depth = *isc_depth;
        // }
        // if let Some(alu_cfg) = args.alu_cfg.as_ref() {
        //     params.core_params.alu_cfg = alu_cfg.clone();
        // }
        params
    };
    println!("Mockup parameters after override with CLI: {params:?}");

    // Manual seeder -----------------------------------------------------------
    let rng: StdRng = if let Some(seed) = args.seed {
        SeedableRng::seed_from_u64((seed & u64::MAX as u128) as u64)
    } else {
        SeedableRng::from_entropy()
    };

    let mut hpu_sim = HpuSim::new(config, params);
    hpu_sim.ipc_poll();
}
