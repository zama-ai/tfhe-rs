//! Implement Ra2m simulation driver abstraction
//!
//! Ra2m simulation rely on 1 ipc link for communication

use super::{MemAlloc, MemChunk};
use crate::ffi::{self, BoardProperties, MemZoneProperties};
use crate::prelude::QueueConfig;
use ra2m_ffi::ipc::prelude::*;
use std::sync::{Arc, Mutex};

pub struct HpuHw {
    pub(super) ipc: Arc<Mutex<IpcMaster>>,
    allocator: Option<MemAlloc>,

    iopq_config: QueueConfig,
    iopq: Option<MemZone>,
    ackq_config: QueueConfig,
    ackq: Option<MemZone>,
}

impl HpuHw {
    /// Handle ffi instantiation
    /// Instantiate current HW and check uuid. If it match with targeted one continue,
    /// otherwise reload Pdi
    #[inline(always)]
    pub fn open_hpu_hw(
        id: u8,
        ipc_path: &str,
        iopq_config: &QueueConfig,
        ackq_config: &QueueConfig,
    ) -> HpuHw {
        let ipc_path = format!("{ipc_path}_{id}");
        Self {
            ipc: Arc::new(Mutex::new(IpcMaster::new_bind_on(&ipc_path))),
            allocator: None,
            iopq_config: iopq_config.clone(),
            iopq: None,
            ackq_config: ackq_config.clone(),
            ackq: None,
        }
    }

    pub fn init_mem(
        &mut self,
        config: &crate::interface::HpuConfig,
        params: &crate::entities::HpuParameters,
    ) {
        assert!(
            self.allocator.is_none(),
            "Error: Double request of HpuHw memory initialisation"
        );
        self.allocator = Some(MemAlloc::new(config, params));

        self.iopq = Some(self.alloc(MemZoneProperties {
            mem_kind: self.iopq_config.mem,
            size_b: self.iopq_config.size_w * std::mem::size_of::<u32>(),
        }));
        self.ackq = Some(self.alloc(MemZoneProperties {
            mem_kind: self.ackq_config.mem,
            size_b: self.ackq_config.size_w * std::mem::size_of::<u32>(),
        }));
    }

    pub fn read_abs_bytes(&self, addr: u64, bytes: &mut [u8]) {
        let mut ipc = self.ipc.lock().unwrap();
        let rd_ack = ipc
            .b_req_ack(IpcReq::Read {
                addr,
                size_b: bytes.len(),
            })
            .expect("Error with IpcMaster Read request");

        if let IpcAck::Read { data } = rd_ack {
            bytes.copy_from_slice(&data);
        } else {
            panic!("Received unmatch IpcAck, expect IpcAck::Read, get {rd_ack:?}.");
        }
    }

    pub fn write_abs_bytes(&mut self, addr: u64, bytes: &[u8]) {
        let mut ipc = self.ipc.lock().unwrap();
        let wr_ack = ipc
            .b_req_ack(IpcReq::Write {
                addr,
                data: ipc_channel::ipc::IpcSharedMemory::from_bytes(bytes),
            })
            .expect("Error with IpcMaster Read request");

        if let IpcAck::Write() = wr_ack {
        } else {
            panic!("Received unmatch IpcAck, expect IpcAck::Write, get {wr_ack:?}.");
        }
    }

    /// Handle on-board memory allocation
    pub fn alloc(&mut self, props: ffi::MemZoneProperties) -> MemZone {
        let chunks = self
            .allocator
            .as_mut()
            .expect("Error: V80 backend memory must be explicitly init (c.f. init_mem)")
            .alloc(&props);
        MemZone::new(props.mem_kind, chunks[0].paddr, chunks, self.ipc.clone())
    }
    /// Handle on-board memory de-allocation
    pub fn release(&mut self, zone: &mut MemZone) {
        let MemZone { kind, chunks, .. } = zone;
        self.allocator
            .as_mut()
            .expect("Error: V80 backend memory must be explicitly init (c.f. init_mem)")
            .release(kind, chunks)
    }
}

impl HpuHw {
    /// Handle register read
    pub fn read_reg(&self, addr: u64) -> u32 {
        let mut ipc = self.ipc.lock().unwrap();
        let rd_ack = ipc
            .b_req_ack(IpcReq::Read {
                addr,
                size_b: std::mem::size_of::<u32>(),
            })
            .expect("Error with IpcMaster Read request");

        if let IpcAck::Read { data } = rd_ack {
            u32::from_ne_bytes((&*data).try_into().unwrap())
        } else {
            panic!("Received unmatch IpcAck, expect IpcAck::Read, get {rd_ack:?}.");
        }
    }

    pub fn write_reg(&mut self, addr: u64, value: u32) {
        let mut ipc = self.ipc.lock().unwrap();
        let wr_ack = ipc
            .b_req_ack(IpcReq::Write {
                addr,
                data: ipc_channel::ipc::IpcSharedMemory::from_bytes(&value.to_ne_bytes()),
            })
            .expect("Error with IpcMaster Read request");

        if let IpcAck::Write() = wr_ack {
        } else {
            panic!("Received unmatch IpcAck, expect IpcAck::Write, get {wr_ack:?}.");
        }
    }
}

impl HpuHw {
    /// Push IOp to ucore
    /// Ucore is in charge of translation to stream of DOp and forward them to ISC
    /// Exchange was done through queue in ddr
    #[allow(unused)]
    pub fn iop_push(&mut self, stream: &[u32]) -> Result<(), String> {
        // Hardcoded queue layout
        // TODO let this configurable and properly exchange through config file
        let QueueConfig {
            head_ofst,
            tail_ofst,
            data_ofst,
            size_w,
            ..
        } = &self.iopq_config;

        let iopq = self
            .iopq
            .as_mut()
            .expect("Error: backend memory must be explicitly init (c.f. init_mem)");

        // Check for room in the iop queue
        let iop_head = {
            let mut head_var = 0;
            iopq.read(*head_ofst, &mut head_var);
            head_var
        };
        let iop_tail = {
            let mut tail_var = 0;
            iopq.read(*tail_ofst, &mut tail_var);
            tail_var
        };
        let word_free = *size_w as u32 - ((iop_head - iop_tail) % *size_w as u32);
        let chunk_start = data_ofst + ((iop_head as usize % size_w) * std::mem::size_of::<u32>());
        if word_free != 0 {
            // write body
            let stream_u8 = bytemuck::cast_slice::<u32, u8>(stream);
            iopq.write_bytes(chunk_start, stream_u8);

            // update queue descriptor
            iopq.write(*head_ofst, &(iop_head + stream.len() as u32));
            Ok(())
        } else {
            Err("QueueFull".to_string())
        }
    }

    /// Check for IOp Ack
    /// Ucore forward IOpAck to host through a queue in ddr
    // Clean this when driver interface is specified
    pub fn iop_ackq_rd(&mut self) -> u32 {
        // Hardcoded queue layout
        // TODO let this configurable and properly exchange through config file
        let head = 0;
        let tail = 8;
        let data = 0x10;
        let size = 256;

        let ackq = self
            .ackq
            .as_mut()
            .expect("Error: backend memory must be explicitly init (c.f. init_mem)");

        // Check for room in the iop queue
        let ack_head = {
            let mut head_var = 0;
            ackq.read(head, &mut head_var);
            head_var
        };
        let ack_tail = {
            let mut tail_var = 0;
            ackq.read(tail, &mut tail_var);
            tail_var
        };

        let word_avail = (ack_head - ack_tail) % size as u32;
        let _chunk_start = data + ((ack_tail as usize % size) * std::mem::size_of::<u32>());
        if word_avail != 0 {
            // TODO read body
            // Currently ack content is dropped only the number of received ack is used
            // update queue descriptor
            ackq.write(tail, &ack_head);
            word_avail
        } else {
            0
        }
    }
}

pub struct MemZone {
    // Link properties
    kind: ffi::MemKind,
    addr: u64,
    chunks: Vec<MemChunk>,

    // Ref to ipc link
    ipc: Arc<Mutex<IpcMaster>>,
}

impl MemZone {
    pub fn new(
        kind: ffi::MemKind,
        addr: u64,
        chunks: Vec<MemChunk>,
        ipc: Arc<Mutex<IpcMaster>>,
    ) -> Self {
        Self {
            kind,
            addr,
            chunks,
            ipc,
        }
    }

    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        let mut ipc = self.ipc.lock().unwrap();
        let rd_ack = ipc
            .b_req_ack(IpcReq::Read {
                addr: (ofst + self.addr as usize) as u64,
                size_b: bytes.len(),
            })
            .expect("Error with IpcMaster Read request");

        if let IpcAck::Read { data } = rd_ack {
            bytes.copy_from_slice(&data);
        } else {
            panic!("Received unmatch IpcAck, expect IpcAck::Read, get {rd_ack:?}.");
        }
    }

    pub fn paddr(&self) -> u64 {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.size_b).sum()
    }

    pub fn write_bytes(&mut self, ofst: usize, bytes: &[u8]) {
        let mut ipc = self.ipc.lock().unwrap();
        let wr_ack = ipc
            .b_req_ack(IpcReq::Write {
                addr: (ofst + self.addr as usize) as u64,
                data: ipc_channel::ipc::IpcSharedMemory::from_bytes(bytes),
            })
            .expect("Error with IpcMaster Read request");

        if let IpcAck::Write() = wr_ack {
        } else {
            panic!("Received unmatch IpcAck, expect IpcAck::Write, get {wr_ack:?}.");
        }
    }

    pub fn write<T>(&mut self, ofst: usize, data: &T) {
        let sliced_data = unsafe {
            std::slice::from_raw_parts(data as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.write_bytes(ofst, sliced_data)
    }

    pub fn read<T: Sized>(&self, ofst: usize, data: &mut T) {
        let sliced_data = unsafe {
            std::slice::from_raw_parts_mut(data as *mut T as *mut u8, std::mem::size_of::<T>())
        };
        self.read_bytes(ofst, sliced_data);
    }
}

/// Utility function to extract board device_id and serial_number from env
pub(super) fn get_board_properties() -> Result<Vec<BoardProperties>, String> {
    // Not currently needed for simulation
    Ok(vec![])
}
