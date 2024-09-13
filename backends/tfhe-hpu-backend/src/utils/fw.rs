//!
//! Application used to handle Iop/Dop translation
//! It could be used to convert a single IOp or a list of them

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::path::Path;
use tfhe_hpu_backend::asm::strum::IntoEnumIterator;
use tfhe_hpu_backend::asm::{self, Asm, MemRegion};
use tfhe_hpu_backend::fw::{AvlblFw, Fw, FwName};

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "Translate IOp or Stream of IOps in DOps stream")]
pub struct Args {
    // Input/Output configuration --------------------------------------------
    /// Fw kind
    #[clap(long, value_parser, default_value = "Ilp")]
    fw_kind: FwName,

    // Convert from the given file
    #[clap(long, value_parser)]
    convert_file: Option<String>,

    /// Expand the given IOp
    /// NB: couldn't use `convert_file` and `expand` at the same time
    #[clap(short, long, value_parser)]
    expand: Option<String>,

    /// Output folder
    #[clap(long, value_parser, default_value = "output")]
    out_folder: String,

    /// Output filename, if nothing provided used input one
    #[clap(long, value_parser)]
    out_file: Option<String>,

    // Arch configuration ----------------------------------------------------
    /// Number of Register
    #[clap(long, value_parser, default_value_t = 64)]
    register: usize,

    /// Number of Heap slots for each cid
    // TODO add support for cid
    #[clap(long, value_parser, default_value = "{0:512}")]
    heap: MemRegion,

    /// Number of Pbs slot in IPIP
    #[clap(long, value_parser, default_value_t = 12)]
    pbs_w: usize,

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
impl From<&Args> for asm::ArchProperties {
    fn from(args: &Args) -> Self {
        Self {
            regs: args.register,
            mem: args.heap,
            pbs_w: args.pbs_w,

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

    let base_file = match (&args.out_file, &args.convert_file) {
        (Some(f), _) => f.clone(),
        (None, Some(f)) => Path::new(&f.replace("iop", "dop"))
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
        _ => "expand.dop".to_string(),
    };

    let asm_p = dirpath.join(Path::new(&format!("{base_file}.asm")));
    let hex_p = dirpath.join(Path::new(&format!("{base_file}.hex")));

    // Instanciate Fw and start translation ----------------------------------------
    let mut fw = AvlblFw::new(&args.fw_kind);
    let iops = asm::iop::IOp::iter().collect::<Vec<_>>();
    let mut iop_parser = asm::Parser::new(iops);

    let iops = if args.convert_file.is_some() {
        let conv_p = Path::new(args.convert_file.as_ref().unwrap());
        let conv_f = OpenOptions::new().read(true).open(conv_p).unwrap();
        let reader = BufReader::new(conv_f);

        let mut conv_iops = Vec::new();
        for line in reader.lines() {
            let line = line.unwrap();
            let iop = iop_parser.from_asm(&line)?;
            conv_iops.push(iop);
        }
        conv_iops
    } else if args.expand.is_some() {
        let iop = iop_parser.from_asm(args.expand.as_ref().unwrap())?;
        vec![iop]
    } else {
        panic!("User must select `convert_file` or `expand` option");
    };

    // Create header
    // => Header describe behavior of prog it top-level instructions
    let header = iops
        .iter()
        .map(|op| op.asm_encode(asm::ARG_MIN_WIDTH) + "\n")
        .collect::<String>();

    let props = asm::ArchProperties::from(&args);
    let prog = fw.expand(&props, &iops);
    prog.write_asm(
        &asm_p.as_os_str().to_str().unwrap(),
        &header,
        asm::ARG_MIN_WIDTH,
    );
    prog.write_hex(&hex_p.as_os_str().to_str().unwrap(), &header);

    Ok(())
}
