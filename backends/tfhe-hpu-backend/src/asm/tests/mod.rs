//!
//! Test for DOp/IOp format

use crate::asm::{dop, iop, Program};

#[test]
fn dop_asm_test() -> Result<(), anyhow::Error> {
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

    let input_file = "src/tests/dop.asm";
    let dop_prg = Program::<dop::DOp>::read_asm(input_file)?;
    println!("Parsing results:\n {dop_prg}");

    Ok(())
}

#[test]
fn iop_asm_test() -> Result<(), anyhow::Error> {
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

    let input_file = "src/tests/iop.asm";

    let iop_prg = Program::<iop::IOp>::read_asm(input_file)?;
    println!("Parsing results:\n {iop_prg}");

    Ok(())
}
