//! This examples load fw from zhc at runtime.
//! It show how we could leverage the use of ApiGraph at runtime
use std::str::FromStr;

use crate::tfhe_hpu_backend::prelude::*;
use std::collections::{HashMap, HashSet};
pub use std::time::{Duration, Instant};
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::prelude::*;
use tfhe::{set_server_key, FheUint64, *};
use tfhe_csprng::generators::DefaultRandomGenerator;

use integer::hpu::ciphertext::HpuRadixCiphertext;
use tfhe::integer::{ClientKey, CompressedServerKey, ServerKey};

use itertools::Itertools;
use tfhe::shortint::parameters::KeySwitch32PBSParameters;
use tfhe::*;

use zhc::builder::CiphertextSpec;
use zhc::config::hpu::HpuConfig;
use zhc::config::multi_hpu::MultiHpuConfig;
use zhc::prelude::Dumpable;

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
}

/// Simple enum that let user select the desired operation
#[derive(Debug, Clone, Copy)]
pub enum ZhcDynOp {
    MhMul(usize),
    MhDiv(usize),
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
        let parse_usize = |suffix: &str| {
            suffix
                .parse::<usize>()
                .map_err(|_| ParseZhcDynOpError(s.to_string()))
        };

        if let Some(n) = s
            .strip_prefix("mh_mul_f")
            .or_else(|| s.strip_prefix("MhMulF"))
        {
            Ok(ZhcDynOp::MhMul(parse_usize(n)?))
        } else if let Some(n) = s
            .strip_prefix("mh_div_f")
            .or_else(|| s.strip_prefix("MhDivF"))
        {
            Ok(ZhcDynOp::MhDiv(parse_usize(n)?))
        } else if s == "sh_add" || s == "ShAdd" {
            Ok(ZhcDynOp::ShAdd)
        } else {
            Err(ParseZhcDynOpError(s.to_string()))
        }
    }
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
    let hpu_device = HpuDevice::from_config(&args.config.expand(), args.force_reload)
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

    for width in args.integer_w {
        // Define associated config and spec for Zhc
        let zhc_config = new_zhc_config(&hpu_device.params());
        let zhc_spec = zhc::builder::CiphertextSpec::new(width as u16, 2, 2);

        for zhc_op in args.zhc_ops.iter() {
            // Build custom IOp Ir ----------------------------------------------------
            println!("FwDyn_{width}b:: Start fw generation for {zhc_op} ...");
            let (mh_factor, mut mh_pipeline) = match zhc_op {
                ZhcDynOp::MhMul(mh_factor) => {
                    let mh_config = MultiHpuConfig {
                        n_hpus: *mh_factor as u8,
                        hpu_config: zhc_config.clone(),
                    };
                    (
                        *mh_factor,
                        zhc::pipeline::compat::mh_mul(zhc_spec, mh_config),
                    )
                }
                _ => unimplemented!("Current op not defined"),
            };

            let proto = zhc_to_native_proto(mh_factor, &zhc_spec, mh_pipeline.get_prototype());
            let stream = ZhcStream::new(None, mh_pipeline.into_multi_hpu_stream());
            let hash = ZhcStreamHash::from(&stream);

            // Register fw on Hpu -----------------------------------------------------
            let iopcode = hpu_device.fw_dyn(hash, stream, proto.clone())?;

            // Execution ROI ----------------------------------------------------------
            let num_block = width / hpu_device.params().pbs_params.message_width;

            // Generate inputs
            let (srcs_clear, srcs_enc): (Vec<_>, Vec<_>) = proto
                .src
                .iter()
                .enumerate()
                .map(|(pos, mode)| {
                    let (bw, block) = match mode {
                        hpu_asm::iop::VarMode::Native => (width, num_block),
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
                    let hpu_fhe =
                        HpuRadixCiphertext::from_radix_ciphertext(&fhe, &hpu_device, None);
                    (clear, hpu_fhe)
                })
                .unzip();

            let imms = (0..proto.imm)
                .map(|pos| {
                    *args
                        .imm
                        .get(pos)
                        .unwrap_or(&rng.gen_range(0..u128::MAX >> (u128::BITS - (width as u32))))
                })
                .collect::<Vec<_>>();

            println!("FwDyn_{width}b:: Start test loop for {zhc_op} ...");
            let roi_start = Instant::now();

            let res_hpu = (0..args.iter)
                .filter_map(|i| {
                    let res = HpuRadixCiphertext::exec(
                        &proto,
                        hpu_asm::FwMode::Dynamic,
                        iopcode,
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
    Ok(())
}

/// Utility function to convert Zhc Operation signature in IOpPrototype
/// Generate a set of DOpStream for multi-hpu multiplication
fn zhc_to_native_proto(
    mh_factor: usize,
    ct_spec: &CiphertextSpec,
    zhc_sig: &zhc::ir::Signature<zhc::builder::Type>,
) -> hpu_asm::IOpProto {
    use zhc::builder::Type;
    use zhc::ir::Signature;

    let native_w = ct_spec.int_size();
    let half_w = native_w / 2;

    let Signature(sig_src, sig_dst) = zhc_sig;
    let dst_mode = sig_dst
        .iter()
        .filter_map(|sig| {
            if let Type::Ciphertext(spec) = sig {
                Some(spec)
            } else {
                None
            }
        })
        .map(|spec| {
            if spec.int_size() == native_w {
                hpu_asm::iop::VarMode::Native
            } else if spec.int_size() == half_w {
                hpu_asm::iop::VarMode::Half
            } else if spec.int_size() == 1 {
                hpu_asm::iop::VarMode::Bool
            } else {
                panic!("Unexpected Ciphertext Type");
            }
        })
        .collect::<Vec<_>>();
    let src_mode = sig_src
        .iter()
        .filter_map(|sig| {
            if let Type::Ciphertext(spec) = sig {
                Some(spec)
            } else {
                None
            }
        })
        .map(|spec| {
            if spec.int_size() == native_w {
                hpu_asm::iop::VarMode::Native
            } else if spec.int_size() == half_w {
                hpu_asm::iop::VarMode::Half
            } else if spec.int_size() == 1 {
                hpu_asm::iop::VarMode::Bool
            } else {
                panic!("Unexpected Ciphertext Type");
            }
        })
        .collect::<Vec<_>>();
    let imm = sig_src
        .iter()
        .filter_map(|sig| {
            if let Type::Plaintext(_) = sig {
                Some(())
            } else {
                None
            }
        })
        .count();
    hpu_asm::IOpProto {
        used_nodes: hpu_asm::iop::NodesMap::new(&[mh_factor as u8]),
        dst: dst_mode,
        src: src_mode,
        imm,
    }
}
