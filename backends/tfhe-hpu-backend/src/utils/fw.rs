//!
//! Application used to handle Iop/Dop translation
//! It could be used to convert a single IOp or a list of them

use std::path::Path;
use tfhe_hpu_backend::asm;
use tfhe_hpu_backend::fw::{self, Fw};

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "Translate IOp or Stream of IOps in DOps stream")]
pub struct Args {
    // Input/Output configuration --------------------------------------------
    /// Fw kind
    #[clap(long, value_parser, default_value = "Ilp")]
    fw_kind: fw::FwName,

    /// Expand the given IOpcode
    /// NB: couldn't use `convert_file` and `expand` at the same time
    #[clap(short, long, value_parser)]
    expand: Vec<asm::AsmIOpcode>,

    /// Output folder
    #[clap(long, value_parser, default_value = "output")]
    out_folder: String,

    // Arch configuration ----------------------------------------------------
    /// Number of Register
    #[clap(long, value_parser, default_value_t = 64)]
    register: usize,

    /// Number of Heap slots
    #[clap(long, value_parser, default_value_t = 512)]
    heap: usize,

    /// Number of Pbs slot in BPIP/IPIP
    #[clap(long, value_parser, default_value_t = 12)]
    pbs_batch_w: usize,

    /// Digit msg width
    #[clap(long, value_parser, default_value_t = 2)]
    msg_w: usize,

    /// Digit carry width
    #[clap(long, value_parser, default_value_t = 2)]
    carry_w: usize,

    /// Supported nu
    /// Number of linear operation supported
    #[clap(long, value_parser, default_value_t = 5)]
    nu: usize,

    /// Integer bit width
    #[clap(long, value_parser, default_value_t = 8)]
    integer_w: usize,
}

/// Extract ArchProperties from CliArgs
impl From<&Args> for fw::FwParameters {
    fn from(args: &Args) -> Self {
        Self {
            regs: args.register,
            heap_size: args.heap,
            pbs_batch_w: args.pbs_batch_w,
            msg_w: args.msg_w,
            carry_w: args.carry_w,
            nu: args.nu,
            integer_w: args.integer_w,
        }
    }
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

    let expand_list = if args.expand.is_empty() {
        asm::iop::IOP_LIST.to_vec()
    } else {
        args.expand.clone()
    };

    for iop in expand_list.iter() {
        let base_file = format!("{}_{}b.dop", iop.to_string().trim(), args.integer_w);

        let asm_p = dirpath.join(Path::new(&format!("{base_file}.asm")));
        let hex_p = dirpath.join(Path::new(&format!("{base_file}.hex")));

        // Instanciate Fw and start translation ----------------------------------------
        let mut fw = fw::AvlblFw::new(&args.fw_kind);
        let props = fw::FwParameters::from(&args);
        let prog = fw.expand(&props, iop);
        prog.write_asm(&asm_p.as_os_str().to_str().unwrap())?;
        prog.write_hex(&hex_p.as_os_str().to_str().unwrap())?;
    }

    Ok(())
}
