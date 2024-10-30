//! Implement a simple mockup interface for ffi.
//! It enable to simulate the tfhe-hpu-backend behavior without the real HW
//!
//! Simply provide IPC to communicate with an Hpu simulation mockup

use crate::ffi;

pub mod ipc;
use ipc::{
    IpcFfi, IpcMemZone, MemoryAck, MemoryFfi, MemoryReq, RegisterAck, RegisterFfi, RegisterReq,
};
use ipc_channel::ipc::IpcSharedMemory;

use super::MemZoneProperties;

pub struct HpuHw {
    ipc: IpcFfi,
}

impl HpuHw {
    /// Handle ffi instanciation
    #[inline(always)]
    pub fn new_hpu_hw(ipc_name: &str) -> HpuHw {
        Self {
            ipc: IpcFfi::new_bind_on(ipc_name),
        }
    }

    /// Handle on-board memory allocation
    pub fn alloc(&mut self, props: ffi::MemZoneProperties) -> MemZone {
        let (req, ack) = {
            let IpcFfi { memory, .. } = &self.ipc;
            let MemoryFfi { req, ack } = memory;
            (req, ack)
        };
        // Send request
        let cmd = MemoryReq::Allocate {
            hbm_pc: props.hbm_pc,
            size_b: props.size_b,
        };
        tracing::trace!("Req => {cmd:x?}");
        req.send(cmd).unwrap();

        // Wait for ack
        match ack.recv() {
            Ok(ack) => {
                tracing::trace!("Ack => {ack:x?}");
                match ack {
                    MemoryAck::Allocate { addr, tx, rx } => {
                        let ipc = IpcMemZone::new(req.clone(), tx, rx);
                        MemZone::new(props, addr, ipc)
                    }
                    _ => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        }
    }
    /// Handle on-board memory de-allocation
    pub fn release(&mut self, zone: &mut MemZone) {
        let (req, ack) = {
            let IpcFfi { memory, .. } = &self.ipc;
            let MemoryFfi { req, ack } = memory;
            (req, ack)
        };
        // Send request
        let cmd = MemoryReq::Release {
            hbm_pc: zone.hbm_pc,
            addr: zone.addr,
        };
        tracing::trace!("Req => {cmd:x?}");
        req.send(cmd).unwrap();

        // Wait for ack
        match ack.recv() {
            Ok(ack) => {
                tracing::trace!("Ack => {ack:x?}");
                match ack {
                    MemoryAck::Release => {}
                    _ => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        }
    }

    /// Handle register read
    pub fn read_reg(&self, addr: u64) -> u32 {
        let (req, ack) = {
            let IpcFfi { register, .. } = &self.ipc;
            let RegisterFfi { req, ack } = register;
            (req, ack)
        };
        // Send request
        let cmd = RegisterReq::Read { addr };
        tracing::trace!("Req => {cmd:x?}");
        req.send(cmd).unwrap();

        // Wait for ack
        let val = match ack.recv() {
            Ok(ack) => {
                tracing::trace!("Ack => {ack:x?}");
                match ack {
                    RegisterAck::Read(val) => val,
                    RegisterAck::Write => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        };
        val
    }

    pub fn write_reg(&mut self, addr: u64, value: u32) {
        let (req, ack) = {
            let IpcFfi { register, .. } = &self.ipc;
            let RegisterFfi { req, ack } = register;
            (req, ack)
        };

        // Send request
        let cmd = RegisterReq::Write { addr, value };
        tracing::trace!("Req => {cmd:x?}");
        req.send(cmd).unwrap();

        // Wait for ack
        match ack.recv() {
            Ok(ack) => {
                tracing::trace!("Ack => {ack:x?}");
                match ack {
                    RegisterAck::Write => {}
                    RegisterAck::Read(_) => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        }
    }
}

pub struct MemZone {
    // Link properties
    hbm_pc: usize,
    addr: u64,
    ipc: IpcMemZone,

    // Host version of the memory
    data: Vec<u8>,
}

impl MemZone {
    pub fn new(props: MemZoneProperties, addr: u64, ipc: IpcMemZone) -> Self {
        Self {
            hbm_pc: props.hbm_pc,
            addr,
            ipc,
            data: vec![0; props.size_b],
        }
    }
    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        let (start, end) = (ofst, ofst + bytes.len());
        bytes.copy_from_slice(&self.data[start..end])
    }

    pub fn paddr(&self) -> u64 {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn write_bytes(&mut self, ofst: usize, bytes: &[u8]) {
        let (start, end) = (ofst, ofst + bytes.len());
        self.data.as_mut_slice()[start..end].copy_from_slice(bytes)
    }

    pub fn mmap(&mut self) -> &mut [u64] {
        todo!()
    }

    pub fn sync(&mut self, mode: ffi::SyncMode) {
        let Self {
            hbm_pc,
            addr,
            ipc,
            data,
        } = self;

        match mode {
            ffi::SyncMode::Host2Device => {
                // Post bytes to device and notify
                let hw_data = IpcSharedMemory::from_bytes(data.as_slice());
                ipc.tx.send(hw_data).unwrap();
                // And notify
                let cmd = MemoryReq::Sync {
                    hbm_pc: *hbm_pc,
                    addr: *addr,
                    mode,
                };
                tracing::trace!("Req => {cmd:x?}");
                ipc.notify_req.send(cmd).unwrap();
            }
            ffi::SyncMode::Device2Host => {
                // Notify
                let cmd = MemoryReq::Sync {
                    hbm_pc: *hbm_pc,
                    addr: *addr,
                    mode,
                };
                tracing::trace!("Req => {cmd:x?}");
                ipc.notify_req.send(cmd).unwrap();
                // Read bytes from Device
                let hw_data = ipc.rx.recv().unwrap();
                data.copy_from_slice(&*hw_data);
            }
        }
    }
}
