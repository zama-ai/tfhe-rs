//! Generates data for all supported TFHE-rs by calling the corresponding "generate_VERS" utility.
//! Collects the metadata into ron files.

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use tfhe_backward_compat_data::generate::{load_metadata_from_str, store_metadata};

/// Relative dir where the generated crates must be stored from the Cargo.toml of this crate
const RELATIVE_CRATES_PATH: &str = "..";

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    data_path: PathBuf,
}

fn main() {
    let args = Args::parse();

    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = base_dir.join(RELATIVE_CRATES_PATH);

    // Parse the list of versions that we can generate data for
    let all_versions = fs::read_dir(crates_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name();
            if name.to_str()?.starts_with("generate_") {
                Some(entry.path())
            } else {
                None
            }
        });

    // Run the data generation tool for all versions
    let mut handles = vec![];
    for dir in all_versions {
        let data_path = args.data_path.clone();

        let name = dir.file_name().unwrap().display();
        println!("Generating data from {}", dir.display());
        let handle = Command::new("cargo")
            .arg("run")
            .arg("--quiet")
            .arg("--release")
            .arg("--")
            .arg("--data-path")
            .arg(data_path)
            .arg("--stdout")
            .current_dir(&dir)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|_| panic!("{} failed to execute", name));
        handles.push(handle);
    }

    // Collect the metadata
    let mut testcases = vec![];
    for handle in handles {
        match handle.wait_with_output() {
            Ok(ron_output) => testcases.extend(load_metadata_from_str(
                str::from_utf8(&ron_output.stdout).unwrap(),
            )),
            Err(e) => {
                eprintln!("Failed to generate data: {}", e);
            }
        }
    }

    store_metadata(testcases, args.data_path);
}
