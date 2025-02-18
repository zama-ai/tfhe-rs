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

use std::fs::{File, OpenOptions};

pub(crate) struct QdmaDriver {
    qdma_h2c: File,
    qdma_c2h: File,
}

impl QdmaDriver {
    pub fn new(h2c_path: &str, c2h_path: &str) -> Self {
        // Open HostToCard xfer file
        let qdma_h2c = OpenOptions::new()
            .read(false)
            .write(true)
            .create(false)
            .open(h2c_path)
            .unwrap();

        // Open CardToHost xfer file
        let qdma_c2h = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(c2h_path)
            .unwrap();

        Self { qdma_h2c, qdma_c2h }
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
