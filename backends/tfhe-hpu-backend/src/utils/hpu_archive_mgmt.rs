use clap::{Parser, Subcommand};
use std::error::Error;
use tfhe_hpu_backend::ffi::HpuV80Pdi;

#[derive(Parser)]
#[command(name = "Pdi Management. Enable Packing/Unpacking of Hpu Pdi")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pack { from_path: String, to_file: String },
    Unpack { from_file: String, to_path: String },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pack { from_path, to_file } => {
            let hpu_pdi = HpuV80Pdi::from_folder(&from_path)?;
            hpu_pdi.to_bincode(&to_file)?;

            println!("Successfully packed folder {from_path} into {to_file}.");
        }
        Commands::Unpack { from_file, to_path } => {
            let hpu_pdi = HpuV80Pdi::from_bincode(&from_file)?;
            hpu_pdi.to_folder(&to_path)?;
            println!("Successfully unpacked file {from_file} into {to_path} folder.");
        }
    }

    Ok(())
}
