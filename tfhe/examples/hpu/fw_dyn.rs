//! This examples load fw from zhc at runtime.
//! It show how we could leverage the use of ApiGraph at runtime
//!
//! Operations (`--zhc-ops`, `<n>` = number of Hpu, 1 to 8):
//!  * `MhMulF<n>`: multiplication with hand-grouped partitions (n = 2, 4 or 8)
//!  * `MhDivF<n>`, `AddF<n>`, `CmpGtF<n>`, `ShiftRF<n>`, `Erc7984F<n>`: zhc automatic
//!    partitioning. `Erc7984F<n>` is the latency-optimised (non-SIMD) ERC7984 transfer
//!
//! With `--check`, every iteration uses new inputs and its result is checked against the clear
//! computation.
use std::str::FromStr;

use crate::tfhe_hpu_backend::prelude::*;
use integer::hpu::ciphertext::HpuRadixCiphertext;
use std::path::PathBuf;
pub use std::time::{Duration, Instant};
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::integer::{ClientKey, CompressedServerKey, ServerKey};
use tfhe::shortint::parameters::KeySwitch32PBSParameters;
use tfhe::*;
use tfhe_csprng::generators::DefaultRandomGenerator;

use std::collections::HashMap;
use zhc::config::multi_hpu::MultiHpuConfig;
use zhc::ir::partitioning::{PartitionAnnotation, PartitionId, PartitionPlacement};
use zhc::ir::OpMap;
use zhc::PipelineExt;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Define CLI arguments
pub use clap::Parser;
pub use clap_num::maybe_hex;
#[derive(clap::Parser, Debug, Clone)]
#[command(long_about = "HPU example that shows the dynamic fw loading.")]
pub struct Args {
    #[arg(
        long,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
    )]
    pub config: ShellString,

    #[arg(long)]
    pub force_reload: bool,

    /// List of operation to tests
    // #[arg(long, default_values_t = ["MhMulF2", "MhMulF4", "MhMulF8", ])]
    #[arg(long, required=true, num_args = 1..)]
    pub zhc_ops: Vec<ZhcDynOp>,

    /// Select integer width to tests on
    #[arg(long, required=true, num_args = 1..)]
    pub integer_w: Vec<usize>,

    /// Seed used for some rngs
    #[arg(long)]
    pub seed: Option<u128>,

    /// Number of iteration for each IOp
    #[arg(long, default_value_t = 2)]
    pub iter: usize,

    /// Force ct input values
    #[arg(long, value_parser = maybe_hex::<u128>)]
    pub src: Vec<u128>,

    /// Force immediate input values
    #[arg(long, value_parser = maybe_hex::<u128>)]
    pub imm: Vec<u128>,

    /// Use trivial encrypt ciphertext
    #[arg(long)]
    pub trivial: bool,

    /// Use trivial encrypt ciphertext
    #[arg(long)]
    pub dump_asm: Option<PathBuf>,

    /// Draw new inputs at each iteration and check the result against the clear computation
    #[arg(long)]
    pub check: bool,
}

/// Simple enum that let user select the desired operation
#[derive(Debug, Clone, Copy)]
pub enum ZhcDynOp {
    MhMul(usize),
    MhDiv(usize),
    Add(usize),
    CmpGt(usize),
    ShiftR(usize),
    Erc7984(usize),
    ShAdd,
}

/// Associated Error for CliParsing
#[derive(Debug)]
pub struct ParseZhcDynOpError(String);

impl std::fmt::Display for ParseZhcDynOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid ZhcDynOp: '{}'", self.0)
    }
}
impl std::error::Error for ParseZhcDynOpError {}

impl FromStr for ZhcDynOp {
    type Err = ParseZhcDynOpError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let err = || ParseZhcDynOpError(s.to_string());
        if s == "sh_add" || s == "ShAdd" {
            return Ok(ZhcDynOp::ShAdd);
        }
        // `<Name>F<n>` or `<name>_f<n>`, with n the number of Hpu
        type OpCtor = fn(usize) -> ZhcDynOp;
        let ops: [(&str, &str, OpCtor); 6] = [
            ("MhMulF", "mh_mul_f", ZhcDynOp::MhMul),
            ("MhDivF", "mh_div_f", ZhcDynOp::MhDiv),
            ("AddF", "add_f", ZhcDynOp::Add),
            ("CmpGtF", "cmp_gt_f", ZhcDynOp::CmpGt),
            ("ShiftRF", "shift_r_f", ZhcDynOp::ShiftR),
            ("Erc7984F", "erc7984_f", ZhcDynOp::Erc7984),
        ];
        let (n, op) = ops
            .iter()
            .find_map(|(camel, snake, op)| {
                s.strip_prefix(camel)
                    .or_else(|| s.strip_prefix(snake))
                    .map(|n| (n, op))
            })
            .ok_or_else(err)?;
        let n = n.parse::<usize>().map_err(|_| err())?;
        if !(1..=hpu_asm::MAX_HPU_IN_CLUSTER).contains(&n) {
            return Err(err());
        }
        Ok(op(n))
    }
}

impl ZhcDynOp {
    /// Number of Hpu requested for the operation
    fn n_hpus(&self) -> usize {
        match self {
            ZhcDynOp::MhMul(n)
            | ZhcDynOp::MhDiv(n)
            | ZhcDynOp::Add(n)
            | ZhcDynOp::CmpGt(n)
            | ZhcDynOp::ShiftR(n)
            | ZhcDynOp::Erc7984(n) => *n,
            ZhcDynOp::ShAdd => 1,
        }
    }

    /// Corner-case inputs, played first by `--check` (`bws` is the width of each source)
    fn edge_cases(&self, bws: &[usize]) -> Vec<Vec<u128>> {
        let w = bws[0];
        let m = mask(w);
        let half = 1u128 << (w / 2);
        // ERC7984 (from, to, amount): the transfer happens iff from >= amount, and to + amount
        // wraps around
        if let ZhcDynOp::Erc7984(_) = self {
            return vec![
                vec![0, 0, 0],
                vec![m, 0, m],
                vec![m, m, m],
                vec![half, 0, half],
                vec![half, 0, half + 1],
                vec![half - 1, half, half],
                vec![0, m, 1],
                vec![m, m, 1],
                vec![1, m, m],
                vec![m - 1, 0, m],
            ];
        }
        let pairs: Vec<(u128, u128)> = match self {
            ZhcDynOp::Add(_) => vec![(0, 0), (m, 0), (m, 1), (m, m), (m / 2 + 1, m / 2 + 1)],
            ZhcDynOp::MhMul(_) => vec![(0, m), (m, 1), (m, m), (half, half), (half - 1, half + 1)],
            // Equal values never show up randomly but are the boundary of a > b
            ZhcDynOp::CmpGt(_) => vec![
                (0, 0),
                (m, m),
                (half, half),
                (m, m - 1),
                (m - 1, m),
                (0, m),
                (m, 0),
                (half, half - 1),
                (half - 1, half),
            ],
            ZhcDynOp::ShiftR(_) => {
                let amounts = [
                    0,
                    1,
                    w as u128 / 2,
                    w as u128 - 1,
                    w as u128,
                    w as u128 + 1,
                    mask(bws[1]),
                ];
                amounts.iter().map(|&b| (m, b)).collect()
            }
            // As zhc's div_check: small, power-of-2 +-1 and near-max divisors, each with a
            // dividend giving q = 0 (n < d), q = 1 (n = d), and the largest ones
            ZhcDynOp::MhDiv(_) => {
                let dmax = mask(bws[1]);
                let dens = [
                    1,
                    2,
                    3,
                    half - 1,
                    half,
                    half + 1,
                    dmax / 2 + 1,
                    dmax - 1,
                    dmax,
                ];
                let mut cases = Vec::new();
                for d in dens {
                    for n in [0, d - 1, d, m / 2, m - 1, m] {
                        if n <= m && !cases.contains(&(n, d)) {
                            cases.push((n, d));
                        }
                    }
                }
                cases
            }
            ZhcDynOp::Erc7984(_) | ZhcDynOp::ShAdd => vec![],
        };
        pairs.into_iter().map(|(a, b)| vec![a, b]).collect()
    }

    /// Random clear sources (`bws` is the width of each source), in a range that exercises the
    /// operation
    fn gen_srcs(&self, bws: &[usize], rng: &mut StdRng) -> Vec<u128> {
        let full = |rng: &mut StdRng, bw: usize| rng.gen::<u128>() & mask(bw);
        match self {
            // Shift amount: mostly in range, sometimes at or above the width (result is 0)
            ZhcDynOp::ShiftR(_) => vec![
                full(rng, bws[0]),
                rng.gen_range(0..=(bws[0] as u128 + 2).min(mask(bws[1]))),
            ],
            // b equal or next to a 2 times out of 3: a > b flips around there
            ZhcDynOp::CmpGt(_) => {
                let a = full(rng, bws[0]);
                let b = match rng.gen_range(0..3) {
                    0 => a,
                    1 => a.wrapping_add(rng.gen_range(0..=2)).wrapping_sub(1) & mask(bws[1]),
                    _ => full(rng, bws[1]),
                };
                vec![a, b]
            }
            // As zhc's div_check: a uniform divisor would almost always give a quotient of 0 or
            // 1, so its bit length is drawn uniformly (never 0), and the dividend has a random
            // length or the full width
            ZhcDynOp::MhDiv(_) => {
                let d = rand_len(rng, bws[1]);
                let n = if rng.gen() {
                    rand_len(rng, bws[0])
                } else {
                    full(rng, bws[0])
                };
                vec![n, d]
            }
            // Amount below the balance half the time (transfer done), above it otherwise
            // (transfer refused), with balances of random length
            ZhcDynOp::Erc7984(_) => {
                let from = rand_len(rng, bws[0]) - rng.gen_range(0..=1);
                let amount = if rng.gen() {
                    rng.gen_range(0..=from)
                } else {
                    rng.gen_range(from..=mask(bws[2]))
                };
                vec![from, full(rng, bws[1]), amount]
            }
            _ => bws.iter().map(|&bw| full(rng, bw)).collect(),
        }
    }

    /// Expected clear results, None when there is no reference for these inputs
    fn expected(&self, width: usize, srcs: &[u128]) -> Option<Vec<u128>> {
        let mask = mask(width);
        let (a, b) = (srcs[0], srcs[1]);
        match self {
            ZhcDynOp::Add(_) => Some(vec![a.wrapping_add(b) & mask]),
            ZhcDynOp::MhMul(_) => Some(vec![a.wrapping_mul(b) & mask]),
            ZhcDynOp::CmpGt(_) => Some(vec![(a > b) as u128]),
            ZhcDynOp::ShiftR(_) => Some(vec![if b >= width as u128 { 0 } else { a >> b }]),
            ZhcDynOp::MhDiv(_) if b != 0 => Some(vec![a / b, a % b]),
            // (new_from, new_to)
            ZhcDynOp::Erc7984(_) => {
                let amount = if a >= srcs[2] { srcs[2] } else { 0 };
                Some(vec![a - amount, b.wrapping_add(amount) & mask])
            }
            _ => None,
        }
    }
}

/// All ones on `bw` bits
fn mask(bw: usize) -> u128 {
    u128::MAX >> (u128::BITS - bw as u32)
}

/// Random value whose bit length is uniform in 1..=bw (top bit set)
fn rand_len(rng: &mut StdRng, bw: usize) -> u128 {
    let len = rng.gen_range(1..=bw);
    (rng.gen::<u128>() & mask(len)) | (1u128 << (len - 1))
}

impl std::fmt::Display for ZhcDynOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
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

/// MhMul builder with its hand-grouped partitions, one group per Hpu.
/// NB: zhc 0.12.0 `compat::Iop::MhMul` groups still use the 0.10 partition ids (shifted by one
/// since `Inputs` is no longer a partition) and the multi-Hpu flow uses partition ids as Hpu ids.
/// Both are fixed here until a zhc release does it: corrected groups, numbered by first appearance.
fn mh_mul_hand_partitioned(
    spec: zhc::builder::SpecInteger,
    n_hpus: usize,
) -> (zhc::builder::Builder, OpMap<PartitionAnnotation>) {
    let groups: &[&[u16]] = match n_hpus {
        2 => &[&[0, 1, 8], &[2, 3, 5, 6]],
        4 => &[&[3, 5, 6, 8], &[1], &[2], &[0]],
        8 => &[
            &[0, 7, 23, 35],
            &[1, 2, 22],
            &[3, 4, 24, 26, 27],
            &[5, 6, 28],
            &[8, 9, 25],
            &[10, 11, 29, 31, 33],
            &[13, 18],
            &[14, 15, 30, 32],
        ],
        _ => panic!("MhMul supports 2, 4 or 8 Hpu, not {n_hpus}"),
    };
    let builder = zhc::builder::mh_mul(spec, std::cmp::max(2, n_hpus / 2));
    for group in groups {
        builder.group_partitions_id(group);
    }

    let parts = builder.partitions();
    // Since zhc 0.12.3 the pipeline gets the raw IR and optimizes it itself: number only the
    // partitions of the ops that survive the optimization, the others are dead code.
    let optimized = zhc::pipeline::passes::optimize_iop(&builder.ir());
    let mut hpu_of: HashMap<PartitionId, PartitionId> = HashMap::new();
    for (_, ann) in parts.iter().filter(|(op, _)| optimized.has_opid(*op)) {
        for pid in ann.placement.iter_pids() {
            let next = PartitionId(hpu_of.len() as u16);
            hpu_of.entry(pid).or_insert(next);
        }
    }
    assert_eq!(
        hpu_of.len(),
        n_hpus,
        "MhMul partitions don't match the Hpu count"
    );
    let parts = parts.map(|ann| PartitionAnnotation {
        placement: ann
            .placement
            .iter_pids()
            .map(|pid| hpu_of.get(&pid).copied())
            .collect::<Option<PartitionPlacement>>()
            // Dead op, removed by the optimization
            .unwrap_or(PartitionPlacement::Irrelevant),
        metadata: ann.metadata,
    });
    (builder, parts)
}

pub fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
    let args = Args::parse();

    println!("\n----------------------------------------------");
    println!("- hpu zhc demo: Load fw at runtime-");
    println!("----------------------------------------------");

    // Seeder for args randomization ------------------------------------------
    let mut rng: StdRng = if let Some(seed) = args.seed {
        SeedableRng::seed_from_u64((seed & u64::MAX as u128) as u64)
    } else {
        SeedableRng::from_entropy()
    };

    // Instantiate HpuDevice --------------------------------------------------
    println!("\n A.0. Hpu backend default configuration");
    println!("   Open hardware with given configuration...");
    let hpu_config = HpuConfig::from_toml(args.config.expand().as_str());
    let hpu_device = HpuDevice::new(
        hpu_config.clone(),
        args.force_reload,
        &tfhe::core_crypto::hpu::create_hpu_lookuptable,
    )
    .expect("Hpu device init failed");

    println!("   Generate client and server keys...");
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
    println!("   Upload keys-material and default fw on HPU...");
    tfhe::integer::hpu::init_device(&hpu_device, sks_compressed).expect("Invalid key");

    let mut total_failures = 0;
    for width in args.integer_w {
        // Define associated config and spec for Zhc
        let zhc_config = new_zhc_config(&hpu_config, hpu_device.params());
        let zhc_spec = zhc::builder::SpecInteger::new(width as u16, 2, 2);

        for zhc_op in args.zhc_ops.iter() {
            // Build custom IOp Ir ----------------------------------------------------
            println!("FwDyn_{width}b:: Start fw generation for {zhc_op} ...");
            let build = |n_hpus: usize| match zhc_op {
                ZhcDynOp::MhMul(_) => {
                    let mh_config = MultiHpuConfig {
                        n_hpus: n_hpus as u8,
                        hpu_config: zhc_config.clone(),
                    };
                    // Keep the hand-grouped MhMul partitions, zhc auto-partitions otherwise
                    let (builder, partitions) = mh_mul_hand_partitioned(zhc_spec, n_hpus);
                    zhc::prelude::Pipeline::new()
                        .with_builder(builder)
                        .with_partitions(partitions)
                        .with_multi_hpu_config(mh_config)
                        .with_builder_partitions(true)
                }
                ZhcDynOp::MhDiv(_) => {
                    let mh_config = MultiHpuConfig {
                        n_hpus: n_hpus as u8,
                        hpu_config: zhc_config.clone(),
                    };
                    // No hand partitions for the division: zhc partitions it automatically
                    zhc::prelude::Pipeline::new()
                        .with_builder(zhc::compat::Iop::Div.to_builder(zhc_spec))
                        .with_multi_hpu_config(mh_config)
                }
                ZhcDynOp::Add(_)
                | ZhcDynOp::CmpGt(_)
                | ZhcDynOp::ShiftR(_)
                | ZhcDynOp::Erc7984(_) => {
                    let mh_config = MultiHpuConfig {
                        n_hpus: n_hpus as u8,
                        hpu_config: zhc_config.clone(),
                    };
                    let iop = match zhc_op {
                        ZhcDynOp::Add(_) => zhc::compat::Iop::Add,
                        ZhcDynOp::CmpGt(_) => zhc::compat::Iop::CmpGt,
                        ZhcDynOp::Erc7984(_) => zhc::compat::Iop::Erc7984,
                        _ => zhc::compat::Iop::RightShift,
                    };
                    zhc::prelude::Pipeline::new()
                        .with_builder(iop.to_builder(zhc_spec))
                        .with_multi_hpu_config(mh_config)
                }
                _ => unimplemented!("Current op not defined"),
            };
            // zhc may leave boards without any work (e.g. Add on more than 3 boards). The
            // firmware rejects an empty DOp stream: it stalls ~1.8 s, then stops consuming IOps
            // on that board until reload. Compile for the boards actually used instead.
            let mut n_hpus = zhc_op.n_hpus();
            let mut mh_pipeline = build(n_hpus);
            loop {
                let empty = mh_pipeline
                    .get_multi_doplang()
                    .iter()
                    .filter(|ir| ir.n_ops() <= 2) // only _START/_END
                    .count();
                if empty == 0 {
                    break;
                }
                println!(
                    " WARNING: zhc leaves {empty} / {n_hpus} boards empty for {zhc_op}, compiling for {} boards",
                    n_hpus - empty
                );
                n_hpus -= empty;
                mh_pipeline = build(n_hpus);
            }

            // Dump assembly if required
            if let Some(asm_p) = args.dump_asm.as_ref() {
                // Create folder if needed
                if asm_p.exists() {
                    if asm_p.is_file() {
                        panic!("ASM_DUMP: given path is a file. Directory expected");
                    }
                } else {
                    // Create it
                    std::fs::create_dir_all(asm_p).unwrap();
                }
                // generate assembly
                let asm_v = mh_pipeline.get_multi_hpu_assembly().clone();

                for (hid, mut asm) in asm_v.into_iter().enumerate() {
                    let filename = format!("{zhc_op}_v{hid}.asm");
                    let asm_f = asm_p.join(filename);
                    asm.move_to(asm_f).expect("Issue with asm generation");
                }
            }

            // Register fw on Hpu -----------------------------------------------------
            let fw_entry = hpu_device
                .fw_dyn_init(mh_pipeline, &tfhe::core_crypto::hpu::create_hpu_lookuptable)?;
            let (signature, _used_nodes) = fw_entry.sig();

            // Execution ROI ----------------------------------------------------------
            // Generate inputs
            let bws = signature
                .get_args()
                .iter()
                .filter_map(hpu_asm::ct_spec)
                .map(|spec| spec.int_size() as usize)
                .collect::<Vec<_>>();
            // Corner cases are only played by `--check`, the timed loop uses random inputs
            let edge_cases = if args.check {
                zhc_op.edge_cases(&bws)
            } else {
                Vec::new()
            };
            // Inputs of iteration `i`: corner case `i`, then random. `--src` overrides both
            let gen_inputs = |i: usize, rng: &mut StdRng| -> (Vec<u128>, Vec<HpuRadixCiphertext>) {
                let mut clears = match edge_cases.get(i) {
                    Some(case) => case.clone(),
                    None => zhc_op.gen_srcs(&bws, rng),
                };
                for (clear, src) in clears.iter_mut().zip(args.src.iter()) {
                    *clear = *src;
                }
                clears
                    .into_iter()
                    .zip(bws.iter())
                    .map(|(clear, bw)| {
                        let block = bw / hpu_device.params().pbs_params.message_width;
                        let fhe = if args.trivial {
                            sks.create_trivial_radix(clear, block)
                        } else {
                            cks.encrypt_radix(clear, block)
                        };
                        let hpu_fhe =
                            HpuRadixCiphertext::from_radix_ciphertext(&fhe, &hpu_device, None);
                        (clear, hpu_fhe)
                    })
                    .unzip()
            };
            let (srcs_clear, srcs_enc) = gen_inputs(usize::MAX, &mut rng);

            let imm_count = signature
                .get_args()
                .iter()
                .filter(|ty| matches!(ty, zhc::builder::Type::PlaintextInteger(_)))
                .count();
            let imms = (0..imm_count)
                .map(|pos| {
                    *args
                        .imm
                        .get(pos)
                        .unwrap_or(&rng.gen_range(0..u128::MAX >> (u128::BITS - (width as u32))))
                })
                .collect::<Vec<_>>();

            if args.check {
                println!(
                    "FwDyn_{width}b:: Start checked loop for {zhc_op}: {} corner cases then random inputs ...",
                    edge_cases.len().min(args.iter)
                );
                if args.iter < edge_cases.len() {
                    println!(
                        " WARNING: only {} / {} corner cases played, use --iter >= {}",
                        args.iter,
                        edge_cases.len(),
                        edge_cases.len()
                    );
                }
                let (mut failures, mut unchecked) = (0, 0);
                let mut lat = Vec::with_capacity(args.iter);
                // Bit lengths of the expected first result (e.g. quotient), to show coverage
                let mut res_len = std::collections::BTreeSet::new();
                for i in 0..args.iter {
                    let (clear, enc) = gen_inputs(i, &mut rng);
                    // Latency: from issue to the result back on the host
                    let start = Instant::now();
                    let res_fhe = HpuRadixCiphertext::exec(
                        hpu_asm::FwMode::Dynamic,
                        fw_entry.iop(),
                        &enc,
                        &imms,
                        None,
                    )
                    .iter()
                    .map(|x| x.to_radix_ciphertext())
                    .collect::<Vec<_>>();
                    lat.push(start.elapsed());

                    let res = res_fhe
                        .iter()
                        .map(|x| cks.decrypt_radix(x))
                        .collect::<Vec<u128>>();
                    let exp = zhc_op.expected(width, &clear);
                    if let Some(exp) = &exp {
                        res_len.insert(u128::BITS - exp[0].leading_zeros());
                    }
                    match exp {
                        None => unchecked += 1,
                        Some(exp) if exp != res => {
                            failures += 1;
                            if failures <= 10 {
                                println!(
                                    "  MISMATCH iter {i}: {zhc_op} <{clear:x?}> -> {res:x?}, expected {exp:x?}"
                                );
                            }
                        }
                        Some(_) => {}
                    }
                }
                lat.sort();
                total_failures += failures;
                println!("FwDyn_{width}b:: Check report: {zhc_op}");
                println!(
                    " -> {} / {} correct, {failures} wrong, {unchecked} without reference",
                    args.iter - failures - unchecked,
                    args.iter
                );
                println!(
                    " -> {} distinct bit lengths of the first result: {res_len:?}",
                    res_len.len()
                );
                println!(
                    " -> Latency min {:?} / median {:?} / max {:?} (incl. host transfers)",
                    lat[0],
                    lat[lat.len() / 2],
                    lat[lat.len() - 1]
                );
                println!("-------------------------------------------------------------------");
                continue;
            }

            println!("FwDyn_{width}b:: Start test loop for {zhc_op} ...");
            let roi_start = Instant::now();

            let res_hpu = (0..args.iter)
                .filter_map(|i| {
                    let res = HpuRadixCiphertext::exec(
                        hpu_asm::FwMode::Dynamic,
                        fw_entry.iop(),
                        &srcs_enc,
                        &imms,
                        None,
                    );
                    if i == (args.iter - 1) {
                        Some(res)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            let res_fhe = res_hpu
                .iter()
                .last()
                .expect("Iteration must be greater than 0")
                .iter()
                .map(|x| x.to_radix_ciphertext())
                .collect::<Vec<_>>();

            let roi_duration = roi_start.elapsed();
            let op_duration = roi_duration / (args.iter as u32);
            let op_tput = Throughput::new(args.iter * res_fhe.len(), roi_duration);

            let res = res_fhe
                .iter()
                .map(|x| cks.decrypt_radix(x))
                .collect::<Vec<u128>>();
            println!("FwDyn_{width}b:: Execution report: {zhc_op}");
            println!(
                "Behavior         : {res:?}  <- {zhc_op} <{:?}> <{:?}> {{{}}}",
                srcs_clear, imms, args.iter
            );
            println!(
                "Behavior (in hex): {res:x?}  <- {zhc_op} <{:x?}> <{:x?}> {{{}}}",
                srcs_clear, imms, args.iter
            );
            println!("-------------------------------------------------------------------");
            println!("Performance {zhc_op}: [{roi_duration:?}]");
            println!(" -> Latency    {op_duration:?}");
            println!(" -> Throughput {op_tput}");
            println!("-------------------------------------------------------------------");
        }
    }
    if total_failures > 0 {
        return Err(format!("{total_failures} wrong results").into());
    }
    Ok(())
}
