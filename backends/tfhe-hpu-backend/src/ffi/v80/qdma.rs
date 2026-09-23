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
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};

const QDMA_VERSION_FILE: &str = "/sys/module/qdma_pf/version";
const QDMA_VERSION_PATTERN: &str = r"2024\.1\.0\.\d+-zama";
pub(crate) const QDMA_LANES: usize = 2;

/// Queue indexes of a lane: (h2c, c2h). Index 0: PDI load
pub(crate) fn lane_idx(lane: usize) -> (usize, usize) {
    (1 + 2 * lane, 2 + 2 * lane)
}

pub(crate) fn queue_path(dev: &str, idx: usize) -> String {
    format!("/dev/qdma{dev}001-MM-{idx}")
}

pub(crate) struct QdmaDriver {
    qdma_h2c: Vec<File>,
    qdma_c2h: Vec<File>,
    lane: AtomicUsize,
}

impl QdmaDriver {
    pub fn new(dev: &str) -> Result<Self, Box<dyn Error>> {
        Self::check_version()?;
        let mut qdma_h2c = Vec::with_capacity(QDMA_LANES);
        let mut qdma_c2h = Vec::with_capacity(QDMA_LANES);
        for lane in 0..QDMA_LANES {
            let (h2c_idx, c2h_idx) = lane_idx(lane);
            let h2c_path = queue_path(dev, h2c_idx);
            let c2h_path = queue_path(dev, c2h_idx);

            // Open HostToCard xfer file
            qdma_h2c.push(
                OpenOptions::new()
                    .read(false)
                    .write(true)
                    .create(false)
                    .open(&h2c_path)
                    .map_err(|err| format!("Opening file {h2c_path} failed: {err:?}"))?,
            );

            // Open CardToHost xfer file
            qdma_c2h.push(
                OpenOptions::new()
                    .read(true)
                    .write(false)
                    .create(false)
                    .open(&c2h_path)
                    .map_err(|err| format!("Opening file {c2h_path} failed: {err:?}"))?,
            );
        }

        Ok(Self {
            qdma_h2c,
            qdma_c2h,
            lane: AtomicUsize::new(0),
        })
    }

    /// Next lane, round robin
    fn next_lane(&self) -> usize {
        self.lane.fetch_add(1, Ordering::Relaxed) % QDMA_LANES
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
        let lane = self.next_lane();
        self.qdma_h2c[lane]
            .write_all_at(bytes, addr as u64)
            .unwrap();
        tracing::trace!("QDMA written {} bytes to device [lane {lane}]", bytes.len());
    }

    pub fn read_bytes(&self, addr: usize, bytes: &mut [u8]) {
        let lane = self.next_lane();
        self.qdma_c2h[lane]
            .read_exact_at(bytes, addr as u64)
            .unwrap();
        tracing::trace!("QDMA red {} bytes from device [lane {lane}]", bytes.len());
    }
}
