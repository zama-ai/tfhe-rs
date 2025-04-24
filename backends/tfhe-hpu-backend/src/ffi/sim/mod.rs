//! Implement a simple mockup interface for ffi.
//! It enables to simulate the tfhe-hpu-backend behavior without the real HW
//!
//! Simply provide IPC to communicate with an Hpu simulation mockup

use crate::ffi;

pub mod ipc;
use ipc::{IpcFfi, MemoryAck, MemoryFfiWrapped, MemoryReq, RegisterAck, RegisterFfi, RegisterReq};
use ipc_channel::ipc::IpcSharedMemory;

use super::MemZoneProperties;

pub struct HpuHw {
    ipc: IpcFfi,
}

impl HpuHw {
    /// Handle ffi instantiation
    #[inline(always)]
    pub fn new_hpu_hw(ipc_name: &str) -> HpuHw {
        Self {
            ipc: IpcFfi::new_bind_on(ipc_name),
        }
    }

    /// Handle on-board memory allocation
    pub fn alloc(&mut self, props: ffi::MemZoneProperties) -> MemZone {
        // Duplicate Memory handle for future memzone and take lock for xfer
        let mem_cloned = self.ipc.memory.clone();
        let mem_locked = self.ipc.memory.0.lock().unwrap();

        // Send request
        let cmd = MemoryReq::Allocate {
            mem_kind: props.mem_kind,
            size_b: props.size_b,
        };
        tracing::trace!("Req => {cmd:x?}");
        mem_locked.req.send(cmd).unwrap();

        // Wait for ack
        match mem_locked.ack.recv() {
            Ok(ack) => {
                tracing::trace!("Ack => {ack:x?}");
                match ack {
                    MemoryAck::Allocate { addr } => MemZone::new(props, addr, mem_cloned),
                    _ => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        }
    }
    /// Handle on-board memory de-allocation
    pub fn release(&mut self, zone: &mut MemZone) {
        // Take memory handle lock for xfer
        let mem_locked = self.ipc.memory.0.lock().unwrap();

        // Send request
        let cmd = MemoryReq::Release {
            mem_kind: zone.mem_kind,
            addr: zone.addr,
        };
        tracing::trace!("Req => {cmd:x?}");
        mem_locked.req.send(cmd).unwrap();

        // Wait for ack
        match mem_locked.ack.recv() {
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

        match ack.recv() {
            Ok(ack) => {
                tracing::trace!("Ack => {ack:x?}");
                match ack {
                    RegisterAck::Read(val) => val,
                    _ => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        }
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
                    _ => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        }
    }

    pub fn get_pbs_parameters(&mut self) -> crate::entities::HpuPBSParameters {
        let (req, ack) = {
            let IpcFfi { register, .. } = &self.ipc;
            let RegisterFfi { req, ack } = register;
            (req, ack)
        };

        // Send request
        let cmd = RegisterReq::PbsParams;
        tracing::trace!("Req => {cmd:x?}");
        req.send(cmd).unwrap();

        // Wait for ack
        match ack.recv() {
            Ok(ack) => {
                tracing::trace!("Ack => {ack:x?}");
                match ack {
                    RegisterAck::PbsParams(params) => params,
                    _ => panic!("Ack mismatch with sent request"),
                }
            }
            Err(err) => panic!("Ipc recv {err:?}"),
        }
    }
}

pub struct MemZone {
    // Link properties
    mem_kind: ffi::MemKind,
    addr: u64,
    ipc: MemoryFfiWrapped,

    // Host version of the memory
    data: Vec<u8>,
}

impl MemZone {
    pub fn new(props: MemZoneProperties, addr: u64, ipc: MemoryFfiWrapped) -> Self {
        Self {
            mem_kind: props.mem_kind,
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
            mem_kind,
            addr,
            ipc,
            data,
        } = self;

        match mode {
            ffi::SyncMode::Host2Device => {
                // Wrap bytes in Shm and send request
                let hw_data = IpcSharedMemory::from_bytes(data.as_slice());

                // Take ipc lock and do req/ack sequence
                let ipc_lock = ipc.0.lock().unwrap();

                let req = MemoryReq::Sync {
                    mem_kind: *mem_kind,
                    addr: *addr,
                    mode,
                    data: Some(hw_data),
                };
                tracing::trace!("Req => {req:x?}");
                ipc_lock.req.send(req).unwrap();

                // Wait for ack
                match ipc_lock.ack.recv() {
                    Ok(ack) => {
                        tracing::trace!("Ack => {ack:x?}");
                        match ack {
                            MemoryAck::Sync { data } => {
                                assert!(data.is_none(), "Received data on Host2Device sync")
                            }
                            _ => panic!("Ack mismatch with sent request"),
                        }
                    }
                    Err(err) => panic!("Ipc recv {err:?}"),
                }
            }
            ffi::SyncMode::Device2Host => {
                // Take ipc lock and do req/ack sequence
                let ipc_lock = ipc.0.lock().unwrap();

                let req = MemoryReq::Sync {
                    mem_kind: *mem_kind,
                    addr: *addr,
                    mode,
                    data: None,
                };
                tracing::trace!("Req => {req:x?}");
                ipc_lock.req.send(req).unwrap();

                // Wait for ack
                match ipc_lock.ack.recv() {
                    Ok(ack) => {
                        tracing::trace!("Ack => {ack:x?}");
                        match ack {
                            MemoryAck::Sync { data } => {
                                let hw_data = data.expect("No data received on Device2Host sync");
                                self.data.copy_from_slice(&hw_data);
                            }
                            _ => panic!("Ack mismatch with sent request"),
                        }
                    }
                    Err(err) => panic!("Ipc recv {err:?}"),
                }
            }
        }
    }
}
