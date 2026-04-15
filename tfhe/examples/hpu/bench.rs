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
use tfhe_hpu_backend::asm::IOpcode;
use tfhe_hpu_backend::prelude::*;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Define CLI arguments
pub use clap::Parser;
pub use clap_num::maybe_hex;
#[derive(clap::Parser, Debug, Clone, serde::Serialize)]
#[command(
    long_about = "HPU stimulus generation application: Start operation on HPU for RTL test purpose."
)]
pub struct Args {
    // Fpga configuration ------------------------------------------------------
    /// Toml top-level configuration file
    #[arg(
        long,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
    )]
    pub config: ShellString,

    #[arg(long)]
    pub force_reload: bool,

    // Exec configuration ----------------------------------------------------
    /// Select integer width to bench
    /// If None default to All available one (c.f. Firmware configuration)
    #[arg(long)]
    pub integer_w: Vec<usize>,

    /// Iop to expand and simulate
    /// If None default to All IOp
    #[arg(long)]
    pub iop: Vec<hpu_asm::AsmIOpcode>,

    /// Number of iteration for each IOp
    #[arg(long, default_value_t = 1)]
    pub iter: usize,

    /// Throughput dedicated mode.
    /// Operation are duplicated for each nodes to load HpuCluster.
    /// WARN: Do not used with native `multi-hpu` IOp
    #[arg(long)]
    pub tput: bool,

    #[arg(long)]
    pub check_res: bool,

    #[arg(long)]
    pub chain_iop: bool,

    /// Force ct input values
    #[arg(long, value_parser = maybe_hex::<u128>)]
    pub src: Vec<u128>,

    /// Force immediate input values
    #[arg(long, value_parser = maybe_hex::<u128>)]
    pub imm: Vec<u128>,

    /// Fallback prototype
    /// Only apply to IOp with unspecified prototype
    /// Used for custom IOp testing when prototype isn't known
    /// Syntax example: "<N B> <- <N N> <0>"
    /// Each entry options are (case incensitive):
    /// * N, Nat, Native -> Full size integer;
    /// * H, Half -> Half size integer;
    /// * B, Bool -> boolean value;
    #[arg(long)]
    pub user_proto: Option<hpu_asm::IOpProto>,

    /// Seed used for some rngs
    #[arg(long)]
    pub seed: Option<u128>,

    // Debug option ----------------------------------------------------------
    #[cfg(feature = "hpu-debug")]
    /// Hpu io dump path
    #[arg(long)]
    pub io_dump: Option<String>,

    /// Use trivial encrypt ciphertext
    #[arg(long)]
    pub trivial: bool,

    /// Override the firmware implementation used
    #[arg(long)]
    pub fw_impl: Option<String>,
}

#[derive(Debug)]
pub struct Throughput(f64);

impl Throughput {
    pub fn new(op: usize, dur: Duration) -> Self {
        Self(op as f64 / dur.as_secs_f64())
    }
}
impl std::fmt::Display for Throughput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Op/s", self.0)
    }
}

#[derive(Debug)]
pub struct BenchReport(HashMap<String, (Duration, Throughput)>);

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
    type Target = HashMap<String, (Duration, Throughput)>;

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
            writeln!(f, " {op} -> Lat: {:?}, Tput: {}", self[op].0, self[op].1)?;
        }
        Ok(())
    }
}

pub fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
    let hpu_device = HpuDevice::new(hpu_config, args.force_reload)?;

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

            let mut err_cnt = 0;
            let hpu_nodes = if args.tput {
                &hpu_device.config().fpga.node_id
            } else {
                // Otherwise, create inputs on first node only
                &hpu_device.config().fpga.node_id[0..=0]
            };
            let bench_inputs = (0..args.iter)
                .map(|_| {
                    hpu_nodes
                        .iter()
                        .map(|node| {
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

                                    let clear = *args.src.get(pos).unwrap_or(
                                        &rng.gen_range(0..=u128::MAX >> (u128::BITS - (bw as u32))),
                                    );
                                    let fhe = if args.trivial {
                                        sks.create_trivial_radix(clear, block)
                                    } else {
                                        cks.encrypt_radix(clear, block)
                                    };
                                    let hpu_fhe = HpuRadixCiphertext::from_radix_ciphertext(
                                        &fhe,
                                        &hpu_device,
                                        Some(hpu_asm::PhysId(*node)),
                                    );
                                    (clear, hpu_fhe)
                                })
                                .unzip();

                            let imms =
                                (0..proto.imm)
                                    .map(|pos| {
                                        *args.imm.get(pos).unwrap_or(&rng.gen_range(
                                            0..u128::MAX >> (u128::BITS - (*width as u32)),
                                        ))
                                    })
                                    .collect::<Vec<_>>();
                            (srcs_clear, srcs_enc, imms)
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            let roi_start = Instant::now();

            let bench_res_hpu = (0..args.iter)
                .filter_map(|i| {
                    let bench_res = bench_inputs[i]
                        .iter()
                        .map(|(srcs_clear, srcs_enc, imms)| {
                            let hpu_enc_res_0 = match args.chain_iop {
                                false => {
                                    HpuRadixCiphertext::exec(&proto, iop.opcode(), srcs_enc, imms)
                                }
                                true => {
                                    let local_proto = "[2]<N>::<N><0>".parse::<hpu_asm::IOpProto>().unwrap();
                                    let lsrcs_enc = srcs_enc.split_at(1);
                                    let hpu_enc_res_1 = HpuRadixCiphertext::exec(&local_proto, IOpcode(33), &lsrcs_enc.0, imms);
                                    let hpu_enc_res_2 = HpuRadixCiphertext::exec(&local_proto, IOpcode(33), &lsrcs_enc.1, imms);
                                    let combined_inputs = [hpu_enc_res_1[0].clone(),hpu_enc_res_2[0].clone()];
                                    let hpu_enc_res_3 = HpuRadixCiphertext::exec(&proto, iop.opcode(), &combined_inputs, imms);
                                    let local_proto2 = "[2]<H>::<H><0>".parse::<hpu_asm::IOpProto>().unwrap();
                                    let hpu_enc_res_4 = HpuRadixCiphertext::exec(&local_proto2, IOpcode(33), &[hpu_enc_res_3[0].clone()], imms);
                                    let hpu_enc_res_5 = HpuRadixCiphertext::exec(&local_proto2, IOpcode(33), &[hpu_enc_res_3[1].clone()], imms);
                                    vec![hpu_enc_res_4[0].clone(), hpu_enc_res_5[0].clone()]
                                }
                            };
                            if args.check_res {
                                let clear_res = hpu_enc_res_0
                                    .iter()
                                    .map(|x| {
                                        let y = x.to_radix_ciphertext();
                                        cks.decrypt_radix::<u128>(&y)
                                    })
                                    .collect::<Vec<_>>();
                                println!("step {i}: src {:?}", srcs_clear);
                                println!("step {i}: res {:?}", clear_res);
                                if iop.opcode() == IOpcode(33) || iop.opcode() == IOpcode(35) {
                                    if clear_res[0] != srcs_clear[0] {
                                        println!(
                                            "ERROR {i}: {:?} /= {:?}",
                                            clear_res[0], srcs_clear[0]
                                        );
                                        err_cnt += 1;
                                    }
                                }
                                if iop.opcode() == IOpcode(32) {
                                    if clear_res[0]
                                        != ((srcs_clear[0] & 0xF) + ((srcs_clear[1] & 0xF) << 4))
                                    {
                                        println!(
                                            "ERROR {i}: {:x} /= {:x}",
                                            clear_res[0],
                                            ((srcs_clear[0] & 0xF) + ((srcs_clear[1] & 0xF) << 4))
                                        );
                                        err_cnt += 1;
                                    }
                                    if clear_res[1]
                                        != (((srcs_clear[0] & 0xF0) >> 4) + (srcs_clear[1] & 0xF0))
                                    {
                                        println!(
                                            "ERROR {i}: {:x} /= {:x}",
                                            clear_res[1],
                                            (((srcs_clear[0] & 0xF0) >> 4)
                                                + (srcs_clear[1] & 0xF0))
                                        );
                                        err_cnt += 1;
                                    }
                                }
                                if iop.opcode() == IOpcode(36) {
                                    println!(
                                        "{i}: {:x} ?= ({:x} * {:x})%256 = {:?}",
                                        clear_res[0],
                                        srcs_clear[0],
                                        srcs_clear[1],
                                        (srcs_clear[0] * srcs_clear[1]) % 256
                                    );
                                    if clear_res[0] != (srcs_clear[0] * srcs_clear[1]) % 256 {
                                        println!(
                                            "ERROR {i}: {:x} /= ({:x} * {:x})%256",
                                            clear_res[0], srcs_clear[0], srcs_clear[1]
                                        );
                                        err_cnt += 1;
                                    }
                                }
                                if iop.opcode() == IOpcode(40) {
                                    let res = clear_res[0] + (clear_res[1] << width / 2);
                                    let expected = (srcs_clear[0] * srcs_clear[1]) % (1 << width);
                                    println!(
                                        "{i}: {:x} ?= ({:x} * {:x})%2**{width:?} = {:?}",
                                        res, srcs_clear[0], srcs_clear[1], expected
                                    );
                                    if res != expected {
                                        println!(
                                            "ERROR {i}: {:x} /= ({:x} * {:x})%2**{width:?}",
                                            res, srcs_clear[0], srcs_clear[1]
                                        );
                                        err_cnt += 1;
                                    }
                                }
                                if iop.opcode() == IOpcode(34) {
                                    println!(
                                        "{i}: {:x} ?= ({:x} + {:x})%256 = {:?}",
                                        clear_res[0],
                                        srcs_clear[0],
                                        srcs_clear[1],
                                        (srcs_clear[0] + srcs_clear[1]) % 256
                                    );
                                    if clear_res[0] != (srcs_clear[0] + srcs_clear[1]) % 256 {
                                        println!(
                                            "ERROR {i}: {:x} /= ({:x} + {:x})%256",
                                            clear_res[0], srcs_clear[0], srcs_clear[1]
                                        );
                                        err_cnt += 1;
                                    }
                                }
                            }
                            hpu_enc_res_0
                        })
                        .collect::<Vec<_>>();
                    if i == (args.iter - 1) {
                        Some(bench_res)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            let bench_res_fhe = bench_res_hpu
                .iter()
                .last()
                .expect("Iteration must be greater than 0")
                .iter()
                .map(|node_res| {
                    node_res
                        .iter()
                        .map(|x| x.to_radix_ciphertext())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            let roi_duration = roi_start.elapsed();
            let op_duration = roi_duration / (args.iter as u32);
            let op_tput = Throughput::new(args.iter * bench_res_fhe.len(), roi_duration);

            let bench_res = bench_res_fhe
                .iter()
                .map(|node_res| {
                    node_res
                        .iter()
                        .map(|x| cks.decrypt_radix(x))
                        .collect::<Vec<u128>>()
                })
                .collect::<Vec<_>>();
            println!("Integer_{width}b:: Execution report: {iop}");
            for (node, (res, inputs)) in
                std::iter::zip(bench_res.iter(), bench_inputs[args.iter - 1].iter()).enumerate()
            {
                let (srcs_clear, _, imms) = inputs;
                println!(
                    "Node {node} ------------------------------------------------------------"
                );
                println!("Score {:?}/{:?}", err_cnt, args.iter);
                println!(
                    "Behavior         : {res:?}  <- {iop} <{:?}> <{:?}> {{{}}}",
                    srcs_clear, imms, args.iter
                );
                println!(
                    "Behavior (in hex): {res:x?}  <- {iop} <{:x?}> <{:x?}> {{{}}}",
                    srcs_clear, imms, args.iter
                );
            }
            println!("-------------------------------------------------------------------");
            println!("Performance {iop}: [{roi_duration:?}]");
            println!(" -> Latency    {op_duration:?}");
            println!(" -> Throughput {op_tput}");
            println!("-------------------------------------------------------------------");
            width_report.insert(iop.to_string(), (op_duration, op_tput));
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

    Ok(())
}
