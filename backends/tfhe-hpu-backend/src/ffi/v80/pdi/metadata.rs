use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;

use lazy_static::lazy_static;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub flavor: Option<String>,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}", self.major, self.minor)?;
        if let Some(flavor) = &self.flavor {
            write!(f, "-{flavor}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref VER_ARG_RE: regex::Regex =
                regex::Regex::new(r"v(?<major>\d+).(?<minor>\d+)(-(?<flavor>.+))?")
                    .expect("Invalid regex");
        }
        if let Some(caps) = VER_ARG_RE.captures(s) {
            let major = caps["major"]
                .trim_ascii()
                .parse::<u32>()
                .expect("Invalid major format. Must be an integer");
            let minor = caps["minor"]
                .trim_ascii()
                .parse::<u32>()
                .expect("Invalid minor format. Must be an integer");
            let flavor = caps
                .name("flavor")
                .map(|flavor| flavor.as_str().to_string());
            Ok(Self {
                major,
                minor,
                flavor,
            })
        } else {
            Err(
                "Invalid version format, expect v{major}.{minor}[-{flavor}]. Where major/minor are integer and flavor String.".to_string(),
            )
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BitstreamMetadata {
    pub uuid: String,
    pub wns_ps: f64,
    pub tns_ps: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AmcMetadata {
    pub his_version: Version,
}

pub const HPU_METADATA_VERSION: Version = Version {
    major: 1,
    minor: 0,
    flavor: None,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Metadata {
    pub version: Version,
    pub pdi_stg1_file: String,
    pub pdi_stg2_file: String,
    pub xsa_file: String,
    pub elf_file: String,
    pub amc: AmcMetadata,
    pub bitstream: BitstreamMetadata,
}

impl Metadata {
    #[allow(unused)]
    /// Provide Serde mechanisms from TOML file
    pub fn from_toml(file: &str) -> Result<Self, Box<dyn Error>> {
        let file_str = std::fs::read_to_string(file).inspect_err(|_e| {
            eprintln!("Read error with file {file}");
        })?;
        let res = toml::from_str(&file_str)?;
        Ok(res)
    }

    #[allow(unused)]
    /// Provide Serde mechanisms to TOML file
    pub fn to_toml(&self, file: &str) -> Result<(), Box<dyn Error>> {
        // Open file
        // Create path
        let path = Path::new(&file);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }

        // Open file
        let mut wr_f = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .inspect_err(|_e| {
                    eprintln!("Open error with {path:?}");
                })?,
        );

        // Convert in toml str and write into file
        let toml_str = toml::to_string_pretty(&self).inspect_err(|_e| {
            eprintln!("Serialize error with {self:?}");
        })?;

        wr_f.write_all(toml_str.as_bytes()).inspect_err(|_e| {
            eprintln!("Write error with {wr_f:?}");
        })?;
        Ok(())
    }
}
