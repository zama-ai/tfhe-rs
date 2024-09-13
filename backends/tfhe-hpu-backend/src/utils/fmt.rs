//!
//! Application used to handle Asm/Hex translation
//! It could be used to convert a single Op or a list of them

use tfhe_hpu_backend::asm;
use tfhe_hpu_backend::asm::strum::IntoEnumIterator;

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "Translate IOp or Stream of IOps in DOps stream")]
pub struct Args {
    // Input/Output configuration --------------------------------------------
    /// Convert from the given file. If file not available cast String in AsmOp
    #[clap(short, long, value_parser)]
    from: String,

    /// Output file
    #[clap(short, long, value_parser)]
    to: String,

    // Format configuration --------------------------------------------------
    /// Asm field min width
    #[clap(short, long, value_parser, default_value_t = asm::ARG_MIN_WIDTH)]
    asm_w: usize,
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
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        .without_time()
        // Build & register the subscriber
        .init();

    // Create IOp/DOp parser -------------------------------------------------------
    let dops_ref = asm::dop::DOp::iter().collect::<Vec<_>>();
    let mut dop_parser = asm::Parser::new(dops_ref);

    let iops_ref = asm::iop::IOp::iter().collect::<Vec<_>>();
    let mut iop_parser = asm::Parser::new(iops_ref);

    // Create output path and ensure that folder exists ----------------------------
    let out_p = std::path::Path::new(&args.to);
    std::fs::create_dir_all(out_p.parent().unwrap())?;

    // Infer input mode ------------------------------------------------------------
    let op_file = std::path::Path::new(&args.from);
    if op_file.exists() {
        // read op from file
        match (
            dop_parser.read_asm::<asm::Arg>(&args.from),
            iop_parser.read_asm::<asm::Arg>(&args.from),
            dop_parser.read_hex::<asm::FmtDOp>(&args.from),
            iop_parser.read_hex::<asm::FmtIOp>(&args.from),
        ) {
            (Ok((header, ops)), ..) => asm::write_hex(&header, &ops, &args.to)?,
            (Err(_), Ok((header, ops)), ..) => asm::write_hex(&header, &ops, &args.to)?,
            (Err(_), Err(_), Ok((header, ops)), _) => {
                asm::write_asm(&header, &ops, &args.to, args.asm_w)?
            }
            (Err(_), Err(_), Err(_), Ok((header, ops))) => {
                asm::write_asm(&header, &ops, &args.to, args.asm_w)?
            }
            (Err(dop_asm), Err(iop_asm), Err(dop_hex), Err(iop_hex)) => {
                eprintln!("Failed to parse {}:", args.from);
                eprintln!("\t DOp Asm parser => {dop_asm}");
                eprintln!("\t IOp Asm parser => {iop_asm}");
                eprintln!("\t DOp Hex parser => {dop_hex}");
                eprintln!("\t IOp Hex parser => {iop_hex}");
                panic!("Error: Impossible to decode instruction, check file encoding");
            }
        }
    } else {
        //Read from raw string
        match (
            dop_parser.from_asm(&args.from),
            iop_parser.from_asm(&args.from),
        ) {
            (Ok(op), _) => asm::write_hex(&args.from, &[op], &args.to)?,
            (Err(_), Ok(op)) => asm::write_hex(&args.from, &[op], &args.to)?,
            (Err(dop_asm), Err(iop_asm)) => {
                eprintln!("Failed to parse {}:", args.from);
                eprintln!("\t DOp Asm parser => {dop_asm}");
                eprintln!("\t IOp Asm parser => {iop_asm}");
                panic!("Error: Impossible to decode instruction, check Op encoding");
            }
        }
    }
    Ok(())
}
