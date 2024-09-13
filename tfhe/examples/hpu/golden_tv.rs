//! Application dedicated to RTL stimulus generation
//! This should be used in tandem with `mockups/tfhe-hpu-mockup/src/mockup.rs
//!
//! With the `dump-out` option it enable to generate bit-accurate stimulus
//! for RTL simulation

use hpu_asm::Asm;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::prelude::*;
use tfhe::*;
use tfhe_hpu_backend::prelude::*;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const AVAILABLE_INTEGER_W: [usize; 10] = [2, 4, 6, 8, 10, 12, 14, 16, 32, 64];

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
        default_value = "backends/tfhe-hpu-backend/config/hpu_config.toml"
    )]
    pub config: String,

    // Exec configuration ----------------------------------------------------
    /// Select integer-width from a set of available one.
    /// C.f. `AVAILABLE_INTEGER_W` for available option
    #[clap(long, value_parser)]
    pub integer_width: usize,

    /// Iop to expand and simulate
    /// If None default to All IOp
    #[clap(long, value_parser)]
    pub iop: hpu_asm::IOpName,

    /// Force input value for A operand
    #[clap(long, value_parser=maybe_hex::<u64>)]
    pub src_a: Option<u64>,

    /// Force input value for B operand
    #[clap(long, value_parser=maybe_hex::<u64>)]
    pub src_b: Option<u64>,

    /// Check that result match expected one
    #[clap(long, value_parser)]
    pub check: Option<u64>,

    /// Seed used for some rngs
    #[clap(long, value_parser)]
    pub seed: Option<u128>,

    // Debug option ----------------------------------------------------------
    #[cfg(feature = "hpu-debug")]
    /// Hpu io dump path
    #[clap(long, value_parser)]
    pub io_dump: Option<String>,
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
    let hpu_device = {
        let mut config = HpuConfig::read_from(&args.config);
        config.firmware.integer_w = vec![args.integer_width];
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
    let (integer_sks_compressed, ..) = sks_compressed.into_raw_parts();
    tfhe::integer::hpu::init_device(&hpu_device, integer_sks_compressed);

    // Stimulus generation body -----------------------------------------------
    // Generate clear value
    let a = if let Some(val) = args.src_a {
        val
    } else {
        rng.gen_range(0..((1 << args.integer_width) - 1))
    };

    let b = if let Some(val) = args.src_b {
        val
    } else {
        rng.gen_range(0..((1 << args.integer_width) - 1))
    };

    // Execute based on required integer_w ------------------------------------
    let res = match args.integer_width {
        2 => {
            impl_gtv_exec!(FheUint2, u8);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        4 => {
            impl_gtv_exec!(FheUint4, u8);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        6 => {
            impl_gtv_exec!(FheUint6, u8);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        8 => {
            impl_gtv_exec!(FheUint8, u8);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        10 => {
            impl_gtv_exec!(FheUint10, u16);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        12 => {
            impl_gtv_exec!(FheUint12, u16);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        14 => {
            impl_gtv_exec!(FheUint14, u16);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        16 => {
            impl_gtv_exec!(FheUint16, u16);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        32 => {
            impl_gtv_exec!(FheUint32, u32);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        64 => {
            impl_gtv_exec!(FheUint64, u64);
            gtv_exec(&hpu_device, &cks, &args.iop, a, b)
        }
        _ => panic!(
            "Unsupported integer_w {}. Supported values are {AVAILABLE_INTEGER_W:?}",
            args.integer_width
        ),
    };

    // Display report ----------------------------------------------------------
    println!("Execution report: {}", args.iop);
    println!("Behavior         : {res} <- {a} [{} {b}]", args.iop);
    println!("Behavior (in hex): {res:x} <- {a:x} [{} {b:x}]", args.iop);
    if let Some(io_dump) = args.io_dump {
        println!("Stimulus generated in {io_dump}");
    } else {
        println!("No stimulus generated. C.f. `--iop-dump` for more information");
    }

    if let Some(check) = args.check {
        assert_eq!(
            check, res,
            "Obtain result {res} doesn't match with expected one {check}"
        );
        println!("Result match expected one");
    }
}

#[macro_export]
macro_rules! impl_gtv_exec {
    ($fhe_type: ty, $user_type: ty) => {
        ::paste::paste! {
        fn gtv_exec(
            hpu_device: &HpuDevice,
            cks: &ClientKey,
            iop_name: &hpu_asm::IOpName,
            src_a: u64,
            src_b: u64,
        ) -> u64 {
            let iop = hpu_asm::IOp::from(*iop_name);

            // Encrypt on cpu side and clone value in Hpu world
            let a_fhe = $fhe_type::encrypt(src_a as $user_type, cks);
            let a_hpu = a_fhe.clone_on(&hpu_device);

            // Iteration over same operation reuse previous result
            // in the following manner: res_{i} = res_{i-1} OP src_b
            println!("Start IOp {iop_name} ...");

            let res_hpu = if iop.has_imm(){
                a_hpu.iop_imm(*iop_name, src_b as usize)
            } else {
                // Encrypt on cpu side and clone value in Hpu world
                let b_fhe = $fhe_type::encrypt(src_b as $user_type, cks);
                let b_hpu = b_fhe.clone_on(&hpu_device);

                a_hpu.iop_ct(*iop_name, b_hpu.clone())
            };

            let res_fhe = $fhe_type::from(res_hpu);
            res_fhe.decrypt(&cks)
        }
        };
    };
}
