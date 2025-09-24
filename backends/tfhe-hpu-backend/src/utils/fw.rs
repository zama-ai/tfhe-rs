//!
//! Application used to handle Iop/Dop translation
//! It could be used to convert a single IOp or a list of them

use std::path::Path;
use tfhe_hpu_backend::asm;
use tfhe_hpu_backend::fw::isc_sim::PeConfigStore;
use tfhe_hpu_backend::fw::rtl::config::{FlushBehaviour, OpCfg, RtlCfg};
use tfhe_hpu_backend::fw::{self, Fw, FwParameters};

/// Define CLI arguments
use clap::Parser;
use tfhe_hpu_backend::prelude::{HpuConfig, HpuParameters, ShellString};
#[derive(clap::Parser, Debug, Clone)]
#[command(long_about = "Translate IOp or Stream of IOps in DOps stream")]
pub struct Args {
    // Configuration -----------------------------------------------------
    /// Toml top-level configuration file
    /// Enable to retrieved runtime configuration register
    #[arg(
        long,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
    )]
    pub config: ShellString,

    /// Hpu rtl parameters
    /// Enable to retrieved the associated tfhe-rs parameters and other Rtl parameters
    #[arg(
        long,
        default_value = "${HPU_MOCKUP_DIR}/params/gaussian_64b_fast.toml"
    )]
    pub params: ShellString,

    /// Supported nu
    /// Number of linear operation supported
    #[arg(long, default_value_t = 5)]
    nu: usize,

    /// Fw kind
    #[arg(long, default_value = "Ilp")]
    fw_kind: fw::FwName,

    /// Number of Heap slots
    #[arg(long, default_value_t = 512)]
    heap: usize,

    /// Kogge configuration file
    #[arg(
        long,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/kogge_cfg.toml"
    )]
    kogge_cfg: ShellString,

    /// Use ipip configuration
    #[arg(long, default_value_t = false)]
    use_ipip: bool,

    /// Use ipip configuration
    #[arg(long, default_value_t = false)]
    use_bpip_opportunism: bool,

    /// Try to fill the batch fifo
    #[arg(long, default_value_t = true)]
    fill_batch_fifo: bool,

    /// Use the minimum batch size for a PE
    #[arg(long, default_value_t = false)]
    min_batch_size: bool,

    /// Use the minimum batch size for a PE
    #[arg(long, default_value_t = false)]
    use_tiers: bool,

    /// Flush PBS batches to force a specific scheduling
    #[arg(long, default_value_t = true)]
    flush: bool,

    /// Flush PBS batches behaviour
    /// Available options are
    /// Patient,
    /// NoPBS,
    /// Opportunist,
    /// Timeout(usize),
    #[arg(long, default_value = "Patient")]
    flush_behaviour: FlushBehaviour,

    /// Force parallel IOp implementations or not. By default this is derived
    /// from the batch size.
    #[arg(long, default_value = None)]
    parallel: Option<bool>,

    /// Integer bit width
    #[arg(long, default_value_t = 8)]
    integer_w: usize,

    // Override params --------------------------------------------------
    // Quick way to override parameters through ClI instead of editing the
    // configuration file
    // Used to override some parameters at runtime
    /// Override Number of Register
    #[arg(long)]
    register: Option<usize>,

    /// Override HPU lookahead buffer depth
    /// Number of instruction that are considered in advance
    #[arg(long)]
    isc_depth: Option<usize>,

    // Input/Output configuration --------------------------------------------
    /// Expand the given IOpcode
    /// NB: couldn't use `convert_file` and `expand` at the same time
    #[arg(short, long)]
    expand: Vec<asm::AsmIOpcode>,

    /// Output folder
    #[arg(long, default_value = "output")]
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

    // Load config/parameters from configuration file ------------------------------------
    let config = HpuConfig::from_toml(args.config.expand().as_str());
    let params = {
        let mut rtl_params = HpuParameters::from_toml(&args.params.expand());

        // Override some parameters if required
        if let Some(register) = args.register.as_ref() {
            rtl_params.regf_params.reg_nb = *register;
        }
        if let Some(isc_depth) = args.isc_depth.as_ref() {
            rtl_params.isc_params.depth = *isc_depth;
        }
        rtl_params
    };
    let pe_cfg = PeConfigStore::from((&params, &config));
    let fw_params = FwParameters {
        register: params.regf_params.reg_nb,
        isc_depth: params.isc_params.depth,
        heap_size: args.heap,
        min_iop_size: params.isc_params.min_iop_size,
        min_pbs_batch_w: config.firmware.min_batch_size,
        total_pbs_nb: params.ntt_params.total_pbs_nb,
        pbs_batch_w: params.ntt_params.batch_pbs_nb,
        msg_w: params.pbs_params.message_width,
        carry_w: params.pbs_params.carry_width,
        nu: args.nu,
        integer_w: args.integer_w,
        use_ipip: args.use_ipip,
        kogge_cfg: args.kogge_cfg.expand(),
        op_cfg: RtlCfg::from(OpCfg {
            fill_batch_fifo: args.fill_batch_fifo,
            min_batch_size: args.min_batch_size,
            use_tiers: args.use_tiers,
            flush: args.flush,
            flush_behaviour: args.flush_behaviour,
            parallel: None,
        }),
        cur_op_cfg: OpCfg::default(),
        pe_cfg,
        op_name: Default::default(),
    };
    println!("Fw parameters after override with CLI: {fw_params:?}");

    let expand_list = if args.expand.is_empty() {
        asm::iop::IOP_LIST.to_vec()
    } else {
        args.expand.clone()
    };

    for iop in expand_list.iter() {
        let base_file = format!("{}_{}b.dop", iop.to_string().trim(), args.integer_w);

        let asm_p = dirpath.join(Path::new(&format!("{base_file}.asm")));
        let hex_p = dirpath.join(Path::new(&format!("{base_file}.hex")));

        // Instantiate Fw and start translation ----------------------------------------
        let fw = fw::AvlblFw::new(&args.fw_kind);
        let prog = fw.expand(&fw_params, iop);
        prog.write_asm(asm_p.as_os_str().to_str().unwrap())?;
        prog.write_hex(hex_p.as_os_str().to_str().unwrap())?;
    }

    Ok(())
}
