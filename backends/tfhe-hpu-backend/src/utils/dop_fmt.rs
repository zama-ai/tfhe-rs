//!
//! Application used to handle Asm/Hex translation
//! It could be used to convert a single Op or a list of them

use std::str::FromStr;
use tfhe_hpu_backend::asm::dop::ToHex;
use tfhe_hpu_backend::asm::{self};

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[command(long_about = "DOp format management")]
pub struct Args {
    // Input/Output configuration --------------------------------------------
    /// Convert from the given file. If file not available cast String in AsmOp
    #[arg(short, long)]
    from: String,

    /// Output file
    #[arg(short, long)]
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
            asm::Program::<asm::dop::DOp>::read_asm(&args.from),
            asm::Program::<asm::dop::DOp>::read_hex(&args.from),
        ) {
            (Ok(p), ..) => p.write_hex(&args.to)?,
            (Err(_), Ok(p)) => p.write_asm(&args.to)?,
            (Err(dop_asm), Err(dop_hex)) => {
                eprintln!("Failed to parse {}:", args.from);
                eprintln!("\t DOp Asm parser => {dop_asm}");
                eprintln!("\t DOp Hex parser => {dop_hex}");
                panic!("Error: Impossible to decode instruction, check file encoding");
            }
        }
    } else {
        let dop = asm::dop::DOp::from_str(&args.from)?;
        let hex = dop.to_hex();
        println!("dop: {} -> 0x{:x}", dop, hex);
    }
    Ok(())
}
