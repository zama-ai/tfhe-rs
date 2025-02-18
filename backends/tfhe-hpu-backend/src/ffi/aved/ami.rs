//! Abstraction over the AMI driver
//!
//! AMI driver is used to issue gcq command to the RPU
//! Those command are used for configuration and register R/W
//!
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::fd::AsRawFd,
};

pub struct AmiDriver {
    ami_dev: File,
}

impl AmiDriver {
    pub fn new(ami_path: &str) -> Self {
        let ami_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(ami_path)
            .unwrap();
        Self { ami_dev }
    }

    /// Issue read register request through AMI driver
    pub fn read_reg(&self, addr: u64) -> u32 {
        let ami_fd = self.ami_dev.as_raw_fd();

        // Allocate heap memory for read value
        let data = Box::<u32>::new(0xdeadc0de);
        let data_ptr = Box::into_raw(data);

        // Populate payload
        let mut payload = AmiPeakPokePayload {
            data_ptr,
            len: 0x1,
            offset: addr as u32,
        };

        tracing::trace!("AMI: Read request with following payload {payload:x?}");
        let ret = unsafe { ami_peak(ami_fd.into(), &mut payload) };
        tracing::trace!("AMI: Read ack received {payload:x?} -> {ret:?}");

        let data = unsafe { Box::from_raw(data_ptr) };
        data.as_ref().clone()
    }

    pub fn write_reg(&self, addr: u64, value: u32) {
        let ami_fd = self.ami_dev.as_raw_fd();

        // Allocate heap memory for read value
        let data = Box::<u32>::new(value);
        let data_ptr = Box::into_raw(data);

        // Populate payload
        let mut payload = AmiPeakPokePayload {
            data_ptr,
            len: 0x1,
            offset: addr as u32,
        };

        tracing::trace!("AMI: Write request with following payload {payload:x?}");
        let ret = unsafe { ami_poke(ami_fd.into(), &mut payload) };
        tracing::trace!("AMI: Write ack received {payload:x?} -> {ret:?}");
    }

    /// Push a stream of DOp in the ISC
    /// This call bypass the IOp->DOp translation in the ucore
    /// NB: There is no automtic SYNC insertion
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

        tracing::trace!("AMI: IOpPush request with following payload {payload:x?}");
        let ret = unsafe { ami_iop_push(ami_fd.into(), &mut payload) };
        tracing::trace!("AMI: IOpPush ack received {payload:x?} -> {ret:?}");
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
        let ret = unsafe { ami_iop_push(ami_fd.into(), &mut payload) };
        tracing::trace!("AMI: IOpPush ack received {payload:x?} -> {ret:?}");
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
            let ack_nb = u32::from_str_radix(ack_str.as_str().trim_ascii(), 10).unwrap();
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
const AMI_IOPREAD_CMD: u8 = 18;

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
nix::ioctl_write_ptr!(ami_iop_read, AMI_IOC_MAGIC, AMI_IOPREAD_CMD, AmiIOpPayload);

// ----------------------------------------------------------------------------
