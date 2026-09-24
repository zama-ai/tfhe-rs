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
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

const QDMA_VERSION_FILE: &str = "/sys/module/qdma_pf/version";
const QDMA_VERSION_PATTERN: &str = r"2024\.1\.0\.\d+-zama";
pub(crate) const QDMA_LANES: usize = 2;

/// Linux AIO (uapi aio_abi.h)
const AIO_MAX_REQS: usize = QDMA_LANES; //
const IOCB_CMD_PREAD: u16 = 0; // using IOCB_CMD_PREAD

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoEvent {
    data: u64, /* the data field from the iocb */
    obj: u64,  /* what iocb this event came from */
    res: i64,  /* result code for this event */
    res2: i64, /* secondary result */
}

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
    aio_context: Mutex<libc::c_ulong>,
}

impl Drop for QdmaDriver {
    fn drop(&mut self) {
        let aio_context = *self
            .aio_context
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: aio_context comes from io_setup and is destroyed once
        unsafe { libc::syscall(libc::SYS_io_destroy, aio_context) };
    }
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

        let mut aio_context: libc::c_ulong = 0;

        // SAFETY: io_setup writes the new context id in aio_context
        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_setup,
                AIO_MAX_REQS as libc::c_long,
                &mut aio_context,
            )
        };
        if ret != 0 {
            return Err(format!("io_setup failed: {}", std::io::Error::last_os_error()).into());
        }

        Ok(Self {
            qdma_h2c,
            qdma_c2h,
            lane: AtomicUsize::new(0),
            aio_context: Mutex::new(aio_context),
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

    /// Read all data at once with Linux AIO, one request per QDMA lane
    pub fn read_batch(&self, reqs: &mut [(usize, &mut [u8])]) {
        let aio_context = self
            .aio_context
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let pc_number = reqs.len();

        // this assert is guarding unsafe code, today impossible to reach
        assert!(
            pc_number <= AIO_MAX_REQS,
            "read_batch: {pc_number} reqs > {AIO_MAX_REQS}"
        );

        // SAFETY: iocb is plain data, all zero is valid
        let mut aio_requests: [libc::iocb; AIO_MAX_REQS] = unsafe { std::mem::zeroed() };
        for (request, ((addr, bytes), file)) in aio_requests
            .iter_mut()
            .zip(reqs.iter_mut().zip(&self.qdma_c2h))
        {
            request.aio_lio_opcode = IOCB_CMD_PREAD;
            request.aio_fildes = file.as_raw_fd() as u32;
            request.aio_buf = bytes.as_mut_ptr() as u64;
            request.aio_nbytes = bytes.len() as u64;
            request.aio_offset = *addr as i64;
        }
        let mut aio_request_ptrs = aio_requests
            .each_mut()
            .map(|request| request as *mut libc::iocb);

        // SAFETY: requests and buffers outlive the I/O, all completions are collected below
        let submitted = unsafe {
            libc::syscall(
                libc::SYS_io_submit,
                *aio_context,
                pc_number as libc::c_long,
                aio_request_ptrs.as_mut_ptr(),
            )
        };
        assert_eq!(
            submitted,
            pc_number as libc::c_long,
            "io_submit: {}",
            std::io::Error::last_os_error()
        );

        let mut aio_events = [IoEvent::default(); AIO_MAX_REQS];
        let mut done = 0;

        while done < pc_number {
            let pending = &mut aio_events[..pc_number - done];

            // SAFETY: pending holds room for the events asked
            let completed = unsafe {
                libc::syscall(
                    libc::SYS_io_getevents,
                    *aio_context,
                    pending.len() as libc::c_long,
                    pending.len() as libc::c_long,
                    pending.as_mut_ptr(),
                    std::ptr::null::<libc::timespec>(),
                )
            };

            if completed < 0 {
                let err = std::io::Error::last_os_error();
                assert!(
                    err.kind() == std::io::ErrorKind::Interrupted,
                    "io_getevents: {err}"
                );
                continue;
            }
            let failed = pending[..completed as usize]
                .iter()
                .find(|ev| ev.res < 1 || ev.res2 != 0);
            assert!(
                failed.is_none(),
                "QDMA AIO read failed: {:?}",
                failed.map(|ev| (ev.res, ev.res2))
            );
            done += completed as usize;
        }
    }
}
