extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = format!("include/{package_name}.h");
    println!("cargo:rerun-if-changed={output_file}");

    cbindgen::generate(crate_dir)
        .unwrap()
        .write_to_file(output_file);
}
