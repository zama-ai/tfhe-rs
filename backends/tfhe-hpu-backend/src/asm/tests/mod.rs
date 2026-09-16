//!
//! Test for DOp/IOp format

use crate::asm::Program;

#[test]
fn iop_asm_test() -> Result<(), anyhow::Error> {
    // Register tracing subscriber that use env-filter
    // Select verbosity with env_var: e.g. `RUST_LOG=Alu=trace`
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        // Display source code file paths
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        .without_time()
        // Build & register the subscriber
        .try_init();

    let input_file = "src/asm/tests/iop.asm";

    let iop_prg = Program::read_asm(input_file)?;
    println!("Parsing results:\n {iop_prg}");

    Ok(())
}
