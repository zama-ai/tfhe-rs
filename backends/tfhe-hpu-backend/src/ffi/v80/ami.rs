//! Abstraction over the AMI driver
//!
//! AMI driver is used to issue gcq command to the RPU
//! Those command are used for configuration and register R/W
use lazy_static::lazy_static;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::time::Duration;

const AMI_VERSION_FILE: &str = "/sys/module/ami/version";
const AMI_VERSION_PATTERN: &str = r"3\.0\.\d+-zama";

const AMI_ID_FILE: &str = "/sys/bus/pci/drivers/ami/devices";
const AMI_ID_PATTERN: &str = r"(?<pci>\d{2}:\d{2}\.\d)\s(?<dev_id>\d+)\s\d+";

const HIS_VERSION_FILE: &str = "/sys/bus/pci/devices/0000:${V80_PCIE_DEV}:00.0/amc_version";
const HIS_VERSION_PATTERN: &str = r".*- zama ucore 2.0";

pub struct AmiDriver {
    ami_dev: File,
    retry_rate: Duration,
}

impl AmiDriver {
    pub fn new(ami_id: usize, retry_rate: Duration) -> Self {
        Self::check_version();

        // Read ami_id_file to get ami device
        let ami_path = {
            // Extract AMI device path
            lazy_static! {
                static ref AMI_ID_RE: regex::Regex =
                    regex::Regex::new(AMI_ID_PATTERN).expect("Invalid regex");
            };

            // Read ami string-id
            let ami_id_f = std::fs::read_to_string(AMI_ID_FILE).expect("Invalid ami_id filepath");
            let id_line = ami_id_f
                .lines()
                .nth(ami_id)
                .unwrap_or_else(|| panic!("Invalid ami id {ami_id}."));

            let id_str = AMI_ID_RE
                .captures(id_line)
                .expect("Invalid AMI_ID_FILE content")
                .name("dev_id")
                .unwrap();
            let dev_id =
                usize::from_str_radix(id_str.as_str(), 10).expect("Invalid AMI_DEV_ID encoding");
            format!("/dev/ami{dev_id}")
        };

        // Open ami device file
        let ami_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&ami_path)
            .unwrap();
        Self {
            ami_dev,
            retry_rate,
        }
    }

    /// Check if current ami version is compliant
    ///
    /// For this purpose we use a regex.
    /// it's easy to expressed and understand breaking rules with it
    pub fn check_version() {
        // Check AMI version
        lazy_static! {
            static ref AMI_VERSION_RE: regex::Regex =
                regex::Regex::new(AMI_VERSION_PATTERN).expect("Invalid regex");
        };

        // Read ami string-version
        let mut ami_ver_f = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(AMI_VERSION_FILE)
            .unwrap();

        let ami_version = {
            let mut ver = String::new();
            ami_ver_f
                .read_to_string(&mut ver)
                .expect("Invalid AMI_VERSION string format");

            ver
        };

        if !AMI_VERSION_RE.is_match(&ami_version) {
            panic!(
                "Invalid ami version. Get {} expect something matching pattern {}",
                ami_version, AMI_VERSION_PATTERN
            )
        }

        // Check HIS version
        // Known through amc version retrieved by ami driver
        lazy_static! {
            static ref HIS_VERSION_RE: regex::Regex =
                regex::Regex::new(HIS_VERSION_PATTERN).expect("Invalid regex");
        };

        // Read ami string-version
        // NB: Rely on shell interpretation to get PCI device
        let his_version_file = crate::prelude::ShellString::new(HIS_VERSION_FILE.to_string());
        let mut his_ver_f = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(his_version_file.expand())
            .unwrap();

        let his_version = {
            let mut ver = String::new();
            his_ver_f
                .read_to_string(&mut ver)
                .expect("Invalid HIS_VERSION string format");

            ver
        };

        if !HIS_VERSION_RE.is_match(&his_version) {
            panic!(
                "Invalid his version. Get {} expect something matching pattern {}",
                his_version, HIS_VERSION_PATTERN
            )
        }
    }

    /// Issue read register request through AMI driver
    pub fn read_reg(&self, addr: u64) -> u32 {
        let ami_fd = self.ami_dev.as_raw_fd();

        // Allocate heap memory for read value
        let data = Box::<u32>::new(0xdeadc0de);
        let data_ptr = Box::into_raw(data);

        // Populate payload
        let payload = AmiPeakPokePayload {
            data_ptr,
            len: 0x1,
            offset: addr as u32,
        };

        tracing::trace!("AMI: Read request with following payload {payload:x?}");
        loop {
            let ret = unsafe { ami_peak(ami_fd, &payload) };
            match ret {
                Err(err) => {
                    tracing::debug!("AMI: Read failed -> {err:?}");
                    std::thread::sleep(self.retry_rate);
                }
                Ok(val) => {
                    tracing::trace!("AMI: Read ack received {payload:x?} -> {val:?}");
                    break;
                }
            }
        }
        unsafe { *Box::from_raw(data_ptr) }
    }

    pub fn write_reg(&self, addr: u64, value: u32) {
        let ami_fd = self.ami_dev.as_raw_fd();

        // Allocate heap memory for read value
        let data = Box::<u32>::new(value);
        let data_ptr = Box::into_raw(data);

        // Populate payload
        let payload = AmiPeakPokePayload {
            data_ptr,
            len: 0x1,
            offset: addr as u32,
        };

        tracing::trace!("AMI: Write request with following payload {payload:x?}");
        loop {
            let ret = unsafe { ami_poke(ami_fd, &payload) };
            match ret {
                Err(err) => {
                    tracing::debug!("AMI: Write failed -> {err:?}");
                    std::thread::sleep(self.retry_rate);
                }
                Ok(val) => {
                    tracing::trace!("AMI: Write ack received {payload:x?} -> {val:?}");
                    break;
                }
            }
        }
    }

    /// Push a stream of DOp in the ISC
    /// This call bypass the IOp->DOp translation in the ucore
    /// NB: There is no automatic SYNC insertion
    #[allow(unused)]
    pub fn dop_push(&self, stream: &[u32]) {
        let ami_fd = self.ami_dev.as_raw_fd();

        // Allocate heap memory for dop stream
        let mut data = Vec::from(stream);
        let len = data.len() as u32;
        let data_ptr = data.as_mut_ptr();

        // Populate payload
        let mut payload = AmiIOpPayload {
            data_ptr,
            len,
            offset: 0x00, // Unused for iop_push
            mode: true,   // Push a stream of DOp
        };

        tracing::trace!("AMI: DOpPush request with following payload {payload:x?}");
        loop {
            let ret = unsafe { ami_iop_push(ami_fd, &payload) };
            match ret {
                Err(err) => {
                    tracing::debug!("AMI: DOpPush failed -> {err:?}");
                    std::thread::sleep(self.retry_rate);
                }
                Ok(val) => {
                    tracing::trace!("AMI: DOpPush ack received {payload:x?} -> {val:?}");
                    break;
                }
            }
        }
    }

    /// Push IOp to ucore
    /// Ucore is in charge of translation to stream of DOp and forward them to ISC
    #[allow(unused)]
    pub fn iop_push(&self, stream: &[u32]) {
        let ami_fd = self.ami_dev.as_raw_fd();

        // Allocate heap memory for stream
        let mut data = Vec::from(stream);
        let len = data.len() as u32;
        let data_ptr = data.as_mut_ptr();

        // Populate payload
        let mut payload = AmiIOpPayload {
            data_ptr,
            len,
            offset: 0x00, // Unused for iop_push
            mode: false,  // Push a stream of IOp
        };

        tracing::trace!("AMI: IOpPush request with following payload {payload:x?}");
        loop {
            let ret = unsafe { ami_iop_push(ami_fd, &payload) };
            match ret {
                Err(err) => {
                    tracing::debug!("AMI: IOpPush failed -> {err:?}");
                    std::thread::sleep(self.retry_rate);
                }
                Ok(val) => {
                    tracing::trace!("AMI: IOpPush ack received {payload:x?} -> {val:?}");
                    break;
                }
            }
        }
    }

    // TODO ugly quick patch
    // Clean this when driver interface is specified
    pub fn iop_ackq_rd(&self) -> u32 {
        let mut iop_ack_f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open("/proc/ami_iop_ack")
            .unwrap();

        // Read a line and extract a 32b integer
        let mut ack_str = String::new();
        iop_ack_f.read_to_string(&mut ack_str).unwrap();
        if ack_str.is_empty() {
            0
        } else {
            let ack_nb = ack_str.as_str().trim_ascii().parse::<u32>().unwrap();
            tracing::trace!("Get value {ack_str} from proc/ami_iop_ack => {ack_nb}",);
            ack_nb
        }
    }
}

// Define driver IOCTL command and associated payload -------------------------
const AMI_IOC_MAGIC: u8 = b'a';

// Peak/Poke command used for Read/Write in registers -------------------------
const AMI_PEAK_CMD: u8 = 15;
const AMI_POKE_CMD: u8 = 16;

/// Payload used for register read/write
#[derive(Debug)]
#[repr(C)]
struct AmiPeakPokePayload {
    data_ptr: *mut u32,
    len: u32,
    offset: u32,
}

nix::ioctl_write_ptr!(ami_peak, AMI_IOC_MAGIC, AMI_PEAK_CMD, AmiPeakPokePayload);
nix::ioctl_write_ptr!(ami_poke, AMI_IOC_MAGIC, AMI_POKE_CMD, AmiPeakPokePayload);

// IOpPush/IOpRead command used for issuing work to HPU ------------------------
const AMI_IOPPUSH_CMD: u8 = 17;
// const AMI_IOPREAD_CMD: u8 = 18;

/// Payload used for IOp push and read back
#[derive(Debug)]
#[repr(C)]
struct AmiIOpPayload {
    data_ptr: *mut u32,
    len: u32,
    offset: u32,
    mode: bool, // false -> IOp, true -> DOp
}

nix::ioctl_write_ptr!(ami_iop_push, AMI_IOC_MAGIC, AMI_IOPPUSH_CMD, AmiIOpPayload);
// nix::ioctl_write_ptr!(ami_iop_read, AMI_IOC_MAGIC, AMI_IOPREAD_CMD, AmiIOpPayload);

// ----------------------------------------------------------------------------
