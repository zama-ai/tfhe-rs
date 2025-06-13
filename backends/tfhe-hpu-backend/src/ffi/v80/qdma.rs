//! Abstraction over the QDMA driver
//!
//! QDMA driver is used for memory xfer in both direction:
//! * H2C: _Host to Card_
//! * C2H: _Card to Host_
//!
//! NB: Currently configuration of QDMA isn't handled. Thus the QDMA queue must be correctly
//! created and started before backend start
//! ``` bash
//! # Select the correct pcie device and physical function.
//! # In the following code snippets the 21:00.0 is selected
//!
//! #1. Configure the maximum number of Qdma queues:
//! echo 100 > /sys/bus/pci/devices/0000\:21\:00.1/qdma/qmax
//!
//! #2. Create and start the host to card queue
//! dma-ctl qdma21001 q add   idx 0 mode mm dir h2c
//! dma-ctl qdma21001 q start idx 0 dir h2c
//!
//! #3. Create and start the card to host queue
//! dma-ctl qdma21001 q add   idx 1 mode mm dir c2h
//! dma-ctl qdma21001 q start idx 1 dir c2h
//! ```

use lazy_static::lazy_static;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Read;

const QDMA_VERSION_FILE: &str = "/sys/module/qdma_pf/version";
const QDMA_VERSION_PATTERN: &str = r"2024\.1\.0\.\d+-zama";

pub(crate) struct QdmaDriver {
    qdma_h2c: File,
    qdma_c2h: File,
}

impl QdmaDriver {
    pub fn new(h2c_path: &str, c2h_path: &str) -> Result<Self, Box<dyn Error>> {
        Self::check_version()?;
        // Open HostToCard xfer file
        let qdma_h2c = OpenOptions::new()
            .read(false)
            .write(true)
            .create(false)
            .open(h2c_path)
            .map_err(|err| format!("Opening file {h2c_path} failed: {err:?}"))?;

        // Open CardToHost xfer file
        let qdma_c2h = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(c2h_path)
            .map_err(|err| format!("Opening file {c2h_path} failed: {err:?}"))?;

        Ok(Self { qdma_h2c, qdma_c2h })
    }

    /// Check if current qdma version is compliant
    ///
    /// For this purpose we use a regex.
    /// it's easy to expressed and understand breaking rules with it
    pub fn check_version() -> Result<(), Box<dyn Error>> {
        lazy_static! {
            static ref QDMA_VERSION_RE: regex::Regex =
                regex::Regex::new(QDMA_VERSION_PATTERN).expect("Invalid regex");
        };

        // Read ami string-version
        let mut qdma_ver_f = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(QDMA_VERSION_FILE)
            .map_err(|err| format!("Opening file {QDMA_VERSION_FILE} failed: {err:?}"))?;

        let qdma_version = {
            let mut ver = String::new();
            qdma_ver_f
                .read_to_string(&mut ver)
                .expect("Invalid QDMA_VERSION string format");

            ver
        };

        if QDMA_VERSION_RE.is_match(&qdma_version) {
            Ok(())
        } else {
            Err(format!(
                "Invalid qdma version. Get {qdma_version} expect something matching pattern {QDMA_VERSION_PATTERN}"
            )
            .into())
        }
    }

    pub fn write_bytes(&self, addr: usize, bytes: &[u8]) {
        let ret = nix::sys::uio::pwrite(&self.qdma_h2c, bytes, addr as i64).unwrap();
        tracing::trace!("QDMA written {ret} bytes to device");
    }

    pub fn read_bytes(&self, addr: usize, bytes: &mut [u8]) {
        let ret = nix::sys::uio::pread(&self.qdma_c2h, bytes, addr as i64).unwrap();
        tracing::trace!("QDMA red {ret} bytes from device");
    }
}
