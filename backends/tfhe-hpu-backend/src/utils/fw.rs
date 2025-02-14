//!
//! Application used to handle Iop/Dop translation
//! It could be used to convert a single IOp or a list of them

use std::path::Path;
use tfhe_hpu_backend::asm;
use tfhe_hpu_backend::fw::isc_sim::PeConfigStore;
use tfhe_hpu_backend::fw::{self, Fw, FwParameters};

/// Define CLI arguments
use clap::Parser;
use tfhe_hpu_backend::prelude::HpuParameters;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "Translate IOp or Stream of IOps in DOps stream")]
pub struct Args {
    // Configuration -----------------------------------------------------
    /// Hpu rtl parameters
    /// Enable to retrieved the associated tfhe-rs parameters and other Rtl parameters
    #[clap(
        long,
        value_parser,
        default_value = "mockups/tfhe-hpu-mockup/params/tfhers_64b_fast.toml"
    )]
    pub params: String,

    /// Supported nu
    /// Number of linear operation supported
    #[clap(long, value_parser, default_value_t = 5)]
    nu: usize,

    /// Fw kind
    #[clap(long, value_parser, default_value = "Ilp")]
    fw_kind: fw::FwName,

    /// Number of Heap slots
    #[clap(long, value_parser, default_value_t = 512)]
    heap: usize,

    /// Kogge configuration file
    #[clap(
        long,
        value_parser,
        default_value = "backends/tfhe-hpu-backend/config/kogge_cfg.toml"
    )]
    kogge_cfg: String,

    /// Use ipip configuration
    #[clap(long, value_parser, default_value = false)]
    use_ipip: bool,

    /// Try to fill the batch fifo
    #[clap(long, value_parser, default_value = false)]
    fill_batch_fifo: bool,

    /// Use the minimum batch size for a PE
    #[clap(long, value_parser, default_value = false)]
    min_batch_size: bool,

    /// Integer bit width
    #[clap(long, value_parser, default_value_t = 8)]
    integer_width: usize,

    // Override params --------------------------------------------------
    // Quick way to override parameters through ClI instead of editing the
    // configuration file
    // Used to override some parameters at runtime
    /// Override Number of Register
    #[clap(long, value_parser)]
    register: Option<usize>,

    /// Override HPU lookahead buffer depth
    /// Number of instruction that are considered in advance
    #[clap(long, value_parser)]
    isc_depth: Option<usize>,

    // Input/Output configuration --------------------------------------------
    /// Expand the given IOpcode
    /// NB: couldn't use `convert_file` and `expand` at the same time
    #[clap(short, long, value_parser)]
    expand: Vec<asm::AsmIOpcode>,

    /// Output folder
    #[clap(long, value_parser, default_value = "output")]
    out_folder: String,
}

fn main() -> Result<(), anyhow::Error> {
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

    // Create output folder/file ---------------------------------------------------
    let dirpath = Path::new(&args.out_folder);
    std::fs::create_dir_all(dirpath).unwrap();

    // Load parameters from configuration file ------------------------------------
    let params = {
        let mut rtl_params = HpuParameters::from_toml(&args.params);

        // Override some parameters if required
        if let Some(register) = args.register.as_ref() {
            rtl_params.regf_params.reg_nb = *register;
        }
        if let Some(isc_depth) = args.isc_depth.as_ref() {
            rtl_params.isc_params.depth = *isc_depth;
        }
        rtl_params
    };
    let pe_cfg = PeConfigStore::from(&params);
    let fw_params = FwParameters {
        register: params.regf_params.reg_nb,
        isc_depth: params.isc_params.depth,
        heap_size: args.heap,
        total_pbs_nb: params.ntt_params.total_pbs_nb,
        pbs_batch_w: params.ntt_params.batch_pbs_nb,
        msg_w: params.pbs_params.message_width,
        carry_w: params.pbs_params.carry_width,
        nu: args.nu,
        integer_w: args.integer_width,
        use_ipip: args.use_ipip,
        fill_batch_fifo: args.fill_batch_fifo,
        min_batch_size: args.min_batch_size,
        kogge_cfg: args.kogge_cfg.clone(),
        pe_cfg,
    };
    println!("Fw parameters after override with CLI: {fw_params:?}");

    let expand_list = if args.expand.is_empty() {
        asm::iop::IOP_LIST.to_vec()
    } else {
        args.expand.clone()
    };

    for iop in expand_list.iter() {
        let base_file = format!("{}_{}b.dop", iop.to_string().trim(), args.integer_width);

        let asm_p = dirpath.join(Path::new(&format!("{base_file}.asm")));
        let hex_p = dirpath.join(Path::new(&format!("{base_file}.hex")));

        // Instanciate Fw and start translation ----------------------------------------
        let mut fw = fw::AvlblFw::new(&args.fw_kind);
        let prog = fw.expand(&fw_params, iop);
        prog.write_asm(&asm_p.as_os_str().to_str().unwrap())?;
        prog.write_hex(&hex_p.as_os_str().to_str().unwrap())?;
    }

    Ok(())
}
