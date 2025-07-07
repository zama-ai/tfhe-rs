//! Abstraction over the AMI driver
//!
//! AMI driver is used to issue gcq command to the RPU
//! Those command are used for configuration and register R/W
use lazy_static::lazy_static;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::time::Duration;

const AMI_VERSION_FILE: &str = "/sys/module/ami/version";
const AMI_VERSION_PATTERN: &str = r"3\.1\.\d+-zama";

const AMI_ID_FILE: &str = "/sys/bus/pci/drivers/ami/devices";
const AMI_ID_PATTERN: &str = r"(?<bus>[[:xdigit:]]{2}):(?<dev>[[:xdigit:]]{2})\.(?<func>[[:xdigit:]])\s(?<devn>\d+)\s(?<hwmon>\d+)";

const HIS_VERSION_FILE: &str = "/sys/bus/pci/devices/0000:${V80_PCIE_DEV}:00.0/amc_version";
const HIS_VERSION_PATTERN: &str = r".*- zama ucore (?<major>\d+).(?<minor>\d+)";

use crate::ffi::v80::pdi::metadata::Version;
use crate::ffi::v80::pdi::uuid::AMI_UUID_WORDS;

const AMI_UUID_BAR_OFFSET: u64 = 0x1001000;

// NB: Some field available in the driver file were never used
#[allow(dead_code)]
pub struct AmiInfo {
    bus_id: usize,
    dev_id: usize,
    func_id: usize,
    devn: usize,
    hwmon: usize,
}

/// Set of discovery function
/// Enable to probe the device IDs and status
impl AmiInfo {
    pub fn new(ami_id: &str) -> Result<Self, Box<dyn Error>> {
        // First read content of AMI_DEVICES_MAP
        let devices_file = OpenOptions::new()
            .read(true)
            .create(false)
            .open(AMI_ID_FILE)?;

        let devices_rd = BufReader::new(devices_file);
        let line = devices_rd
            .lines()
            .find(|line_result| match line_result {
                Ok(l) => l.starts_with(ami_id),
                Err(_) => false,
            })
            .ok_or("Could not find line starting with {ami_id:?}.")??;

        // Extract AMI device path
        lazy_static! {
            static ref AMI_ID_RE: regex::Regex =
                regex::Regex::new(AMI_ID_PATTERN).expect("Invalid regex");
        };

        let caps = AMI_ID_RE
            .captures(&line)
            .ok_or("Invalid AMI_DEVICES_MAP format")?;
        let bus_id = usize::from_str_radix(&caps["bus"], 16)?;
        let dev_id = usize::from_str_radix(&caps["dev"], 16)?;
        let func_id = usize::from_str_radix(&caps["func"], 16)?;
        let devn = caps["devn"].parse::<usize>()?;
        let hwmon = caps["hwmon"].parse::<usize>()?;
        Ok(Self {
            bus_id,
            dev_id,
            func_id,
            devn,
            hwmon,
        })
    }
}

pub struct AmiDriver {
    ami_dev: File,
    ami_info: AmiInfo,
    retry_rate: Duration,
}

impl AmiDriver {
    pub fn new(
        ami_id: &str,
        amc_ver: &Version,
        retry_rate: Duration,
    ) -> Result<Self, Box<dyn Error>> {
        Self::check_version(amc_ver)?;
        // Read Ami info
        let ami_info = AmiInfo::new(ami_id)?;
        let ami_path = format!("/dev/ami{}", ami_info.devn);

        let ami_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(ami_path)?;

        Ok(Self {
            ami_dev,
            ami_info,
            retry_rate,
        })
    }

    /// Read currently loaded UUID in BAR
    pub fn uuid(&self) -> String {
        let ami_fd = self.ami_dev.as_raw_fd();

        // Allocate heap memory for read value
        let uuid = Box::new([0_u32; AMI_UUID_WORDS]);
        let data_ptr = Box::into_raw(uuid);

        // Populate payload
        let mut payload = AmiBarPayload {
            num: AMI_UUID_WORDS as u32,
            data_ptr: data_ptr as *mut u32,
            bar_idx: 0,
            offset: AMI_UUID_BAR_OFFSET,
            cap_override: true,
        };

        tracing::trace!("AMI: Read request with following payload {payload:x?}");
        loop {
            let ret = unsafe { ami_bar_read(ami_fd, &mut payload) };
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
        let uuid = unsafe { *Box::from_raw(data_ptr) };
        uuid.iter()
            .rev()
            .fold(String::new(), |acc, w| acc + &format!("{w:0>8x}"))
    }

    /// Check if current ami version is compliant
    ///
    /// For this purpose we use a regex.
    /// it's easy to expressed and understand breaking rules with it
    pub fn check_version(amc_ver: &Version) -> Result<(), Box<dyn Error>> {
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
            .map_err(|err| format!("Opening file {AMI_VERSION_FILE} failed: {err:?}"))?;

        let ami_version = {
            let mut ver = String::new();
            ami_ver_f
                .read_to_string(&mut ver)
                .expect("Invalid AMI_VERSION string format");

            ver
        };

        if !AMI_VERSION_RE.is_match(&ami_version) {
            return Err(format!(
                "Invalid ami version. Get {ami_version} expect something matching pattern {AMI_VERSION_PATTERN}")
            .into());
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
            .unwrap_or_else(|err| {
                panic!("Opening file {} failed: {err:?}", his_version_file.expand())
            });

        let his_version = {
            let mut ver = String::new();
            his_ver_f
                .read_to_string(&mut ver)
                .map_err(|e| format!("Invalid HIS_VERSION string format: {e:?}"))?;
            ver
        };

        let caps = HIS_VERSION_RE
            .captures(&his_version)
            .ok_or("Invalid his version format")?;
        let amc_major = caps["major"].parse::<u32>()?;
        let amc_minor = caps["minor"].parse::<u32>()?;
        if amc_major != amc_ver.major {
            return Err(format!(
                "Invalid his major version. Get {} expect {}",
                amc_major, amc_ver.major
            )
            .into());
        }
        if amc_minor != amc_ver.minor {
            return Err(format!(
                "Invalid his minor version. Get {} expect {}",
                amc_minor, amc_ver.minor
            )
            .into());
        }
        Ok(())
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
        let ami_devn = self.ami_info.devn;
        let ami_proc_path = format!("/proc/ami_iop_ack_{}", ami_devn);
        let mut iop_ack_f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&ami_proc_path)
            .unwrap();

        // Read a line and extract a 32b integer
        let mut ack_str = String::new();
        iop_ack_f.read_to_string(&mut ack_str).unwrap();
        if ack_str.is_empty() {
            0
        } else {
            let ack_nb = ack_str.as_str().trim_ascii().parse::<u32>().unwrap();
            tracing::trace!("Get value {ack_str} from {ami_proc_path} => {ack_nb}",);
            ack_nb
        }
    }
}

// Define driver IOCTL command and associated payload -------------------------
const AMI_IOC_MAGIC: u8 = b'a';

// Bar Read/Write command used for PCIe device probing ------------------------
const AMI_BAR_READ_CMD: u8 = 1;
// const AMI_BAR_WRITE_CMD: u8 = 2;

/// Payload used for PCI BAR registers read/write
/// Args:
/// * num: Number of BAR registers (to read or write).
/// * data_ptr: Userspace address of data payload (read or write).
/// * bar_idx: Bar number.
/// * offset: Offset within BAR.
/// * cap_override: Bypass permission checks. This may not apply to all IOCTL's.
///
/// Note:
/// For reading a BAR, `addr` is the userspace address of a u32 buffer to be
/// populated with data read from the BAR and `num` is the number of values to read.
/// To write to a BAR, `addr` is the userspace address of the u32 buffer to
/// write and `num` is the number of values to write.
#[derive(Debug)]
#[repr(C)]
struct AmiBarPayload {
    num: u32,
    data_ptr: *mut u32,
    bar_idx: u8,
    offset: u64,
    cap_override: bool,
}
nix::ioctl_readwrite!(ami_bar_read, AMI_IOC_MAGIC, AMI_BAR_READ_CMD, AmiBarPayload);
// nix::ioctl_write_ptr!(
//     ami_bar_write,
//     AMI_IOC_MAGIC,
//     AMI_BAR_WRITE_CMD,
//     AmiBarPayload
// );

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
