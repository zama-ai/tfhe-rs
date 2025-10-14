use std::fs::remove_dir_all;
use std::path::PathBuf;

use clap::Parser;
use generate_0_11::V0_11;
use tfhe_backward_compat_data::dir_for_version;
use tfhe_backward_compat_data::generate::{
    display_metadata, gen_all_data, update_metadata_for_version,
};

#[derive(Parser, Debug)]
struct Args {
    /// The path where the backward data should be stored
    #[arg(long)]
    data_path: PathBuf,

    /// Output metadata to stdout instead of writing them to the ron file
    #[arg(long, action)]
    stdout: bool,
}

fn main() {
    let args = Args::parse();

    let version_dir = dir_for_version(&args.data_path, "0.11");
    // Ignore if directory does not exist
    let _ = remove_dir_all(&version_dir);

    let data = gen_all_data::<V0_11>(&args.data_path);

    if args.stdout {
        display_metadata(&data);
    } else {
        update_metadata_for_version(data, args.data_path);
    }
}
