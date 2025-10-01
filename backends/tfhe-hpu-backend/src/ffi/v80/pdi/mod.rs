use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::Path;

pub mod metadata;
use metadata::{Metadata, HPU_METADATA_VERSION};
pub mod uuid;
pub use uuid::V80Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct HpuV80Pdi {
    pub metadata: Metadata,
    pub pdi_stg1_bin: Vec<u8>,
    pub pdi_stg2_bin: Vec<u8>,
    pub xsa_bin: Vec<u8>,
    pub elf_bin: Vec<u8>,
}

impl HpuV80Pdi {
    #[allow(unused)]
    /// Utility function to read stream of data from file with proper error display
    pub(crate) fn read_from_path(path: &str, file: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let file_p = Path::new(path).join(file);
        let rd_f = BufReader::new(OpenOptions::new().read(true).open(&file_p).inspect_err(
            |_e| {
                eprintln!("OpenOptions error with {file_p:?}");
            },
        )?);

        let data = rd_f.bytes().collect::<Result<Vec<_>, _>>()?;
        Ok(data)
    }

    #[allow(unused)]
    /// Utility function to write stream of data into file with proper error display
    pub(crate) fn write_to_path(path: &str, file: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let file_p = Path::new(path).join(file);

        // Enforce that parent folder exist and open file
        if let Some(dir_p) = Path::new(&file_p).parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }
        let mut wr_f = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&file_p)
                .inspect_err(|_e| {
                    eprintln!("OpenOptions error with {file_p:?}");
                })?,
        );
        wr_f.write_all(data)?;
        Ok(())
    }
}

impl HpuV80Pdi {
    #[allow(unused)]
    /// Construct HpuV80Pdi from a folder with discrete files
    pub fn from_folder(folder_path: &str) -> Result<Self, Box<dyn Error>> {
        let metadata_path = Path::new(folder_path).join("metadata.toml");
        let metadata = Metadata::from_toml(
            metadata_path
                .to_str()
                .expect("Invalid unicode path {metadata_path:?}"),
        )?;

        // Read the binary files
        let pdi_stg1_bin = Self::read_from_path(folder_path, &metadata.pdi_stg1_file)?;
        let pdi_stg2_bin = Self::read_from_path(folder_path, &metadata.pdi_stg2_file)?;
        let xsa_bin = Self::read_from_path(folder_path, &metadata.xsa_file)?;
        let elf_bin = Self::read_from_path(folder_path, &metadata.elf_file)?;

        Ok(HpuV80Pdi {
            metadata,
            pdi_stg1_bin,
            pdi_stg2_bin,
            xsa_bin,
            elf_bin,
        })
    }

    #[allow(unused)]
    /// Deconstruct HpuV80Pdi into a folder with discrete files
    pub fn to_folder(&self, folder_path: &str) -> Result<(), Box<dyn Error>> {
        let metadata_path = Path::new(folder_path).join("metadata.toml");
        self.metadata.to_toml(
            metadata_path
                .to_str()
                .expect("Invalid unicode in path {metadata_path:?}"),
        )?;
        // Write the binary data
        Self::write_to_path(
            folder_path,
            &self.metadata.pdi_stg1_file,
            &self.pdi_stg1_bin,
        )?;
        Self::write_to_path(
            folder_path,
            &self.metadata.pdi_stg2_file,
            &self.pdi_stg2_bin,
        )?;
        Self::write_to_path(folder_path, &self.metadata.xsa_file, &self.xsa_bin)?;
        Self::write_to_path(folder_path, &self.metadata.elf_file, &self.elf_bin)?;
        Ok(())
    }

    #[allow(unused)]
    /// Deserialize HpuV80Pdi from a bin file
    pub fn from_bincode(file_path: &str) -> Result<Self, Box<dyn Error>> {
        let mut rd_f = OpenOptions::new()
            .read(true)
            .open(file_path)
            .inspect_err(|_e| {
                eprintln!("OpenOptions error with {file_path}");
            })?;

        let meta_version: metadata::Version = bincode::deserialize_from(&rd_f)?;
        if meta_version != HPU_METADATA_VERSION {
            return Err(format!(
                "Archive use version \"{meta_version}\", Sw expect version \"{HPU_METADATA_VERSION}\""
            )
            .into());
        }

        // Start from beginning and use bufReader for performance
        rd_f.rewind();
        let rd_bfr = BufReader::new(rd_f);
        let hpu_pdi = bincode::deserialize_from(rd_bfr)?;
        Ok(hpu_pdi)
    }

    #[allow(unused)]
    /// Serialize HpuV80Pdi into a bin file
    pub fn to_bincode(&self, file_path: &str) -> Result<(), Box<dyn Error>> {
        // Enforce that parent folder exist and open file
        if let Some(dir_p) = Path::new(&file_path).parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }
        let wr_f = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(file_path)
                .inspect_err(|_e| {
                    eprintln!("OpenOptions error with {file_path}");
                })?,
        );
        bincode::serialize_into(wr_f, self)?;
        Ok(())
    }
}
