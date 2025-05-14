//!
//! Application used to handle Asm/Hex translation
//! It could be used to convert a single Op or a list of them

use std::str::FromStr;

use tfhe_hpu_backend::asm;

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "IOp format management")]
pub struct Args {
    // Input/Output configuration --------------------------------------------
    /// Convert from the given file. If file not available cast String in AsmOp
    #[clap(short, long, value_parser)]
    from: String,

    /// Output file
    #[clap(short, long, value_parser)]
    to: String,
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

    // Create output path and ensure that folder exists ----------------------------
    let out_p = std::path::Path::new(&args.to);
    std::fs::create_dir_all(out_p.parent().unwrap())?;

    // Infer input mode ------------------------------------------------------------
    let op_file = std::path::Path::new(&args.from);
    if op_file.exists() {
        // read op from file
        match (
            asm::Program::<asm::iop::IOp>::read_asm(&args.from),
            asm::Program::<asm::iop::IOp>::read_hex(&args.from),
        ) {
            (Ok(p), ..) => p.write_hex(&args.to)?,
            (Err(_), Ok(p)) => p.write_asm(&args.to)?,
            (Err(iop_asm), Err(iop_hex)) => {
                eprintln!("Failed to parse {}:", args.from);
                eprintln!("\t IOp Asm parser => {iop_asm}");
                eprintln!("\t IOp Hex parser => {iop_hex}");
                panic!("Error: Impossible to decode instruction, check file encoding");
            }
        }
    } else {
        let iop = asm::iop::IOp::from_str(&args.from)?;
        println!("iop: {} -> 0x{:0>8x?}", iop, iop.to_words());
    }
    Ok(())
}
