//!
//! Hpu simulation model

mod hbm;
use std::array::from_fn;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;

use crate::asm::{self, Asm, AsmBin};

pub(crate) use hbm::{HbmBank, HbmChunk};
use strum::IntoEnumIterator;

use crate::entities::HpuParameters;
use crate::ffi::{HpuConfig, MemZoneProperties};

pub(crate) struct HpuSimHandle {
    // workq interface
    pub(crate) workq_tx: Sender<u32>,
    pub(crate) ackq_rx: Receiver<u32>,

    // Memory allocation interface
    pub(crate) mem_req_tx: Sender<MemZoneProperties>,
    pub(crate) mem_resp_rx: Receiver<Arc<HbmChunk>>,
}

pub(crate) struct HpuSim {
    config: HpuConfig,

    /// On-board memory
    hbm_bank: [HbmBank; hbm::HBM_BANK_NB],

    /// WorkAckQ interface
    workq_rx: Receiver<u32>,
    workq_stream: Vec<u8>,
    ackq_tx: Sender<u32>,

    /// Memory allocation interface
    mem_req_rx: Receiver<MemZoneProperties>,
    mem_resp_tx: Sender<Arc<HbmChunk>>,

    /// Parser for workq_stream
    iop_parser: asm::Parser<asm::IOp>,
}

impl HpuSim {
    pub(crate) fn new(config: HpuConfig) -> (Self, HpuSimHandle) {
        // Allocate on-board memory emulation
        let hbm_bank: [HbmBank; hbm::HBM_BANK_NB] = from_fn(|i| HbmBank::new(i));

        // Allocate channel for communication with ffi
        let (workq_tx, workq_rx) = mpsc::channel();
        let (ackq_tx, ackq_rx) = mpsc::channel();
        let (mem_req_tx, mem_req_rx) = mpsc::channel();
        let (mem_resp_tx, mem_resp_rx) = mpsc::channel();

        // Allocate IOp parser for workq_stream
        let iops_ref = asm::IOp::iter().collect::<Vec<_>>();
        let iop_parser = asm::Parser::new(iops_ref);

        (
            Self {
                config,
                hbm_bank,
                workq_rx,
                workq_stream: Vec::new(),
                ackq_tx,
                mem_req_rx,
                mem_resp_tx,
                iop_parser,
            },
            HpuSimHandle {
                workq_tx,
                ackq_rx,
                mem_req_tx,
                mem_resp_rx,
            },
        )
    }

    /// Simulate allocation in on-board memory
    pub fn alloc(&mut self, props: MemZoneProperties) -> Arc<HbmChunk> {
        let trgt_bank = &mut self.hbm_bank[props.hbm_pc];
        trgt_bank.alloc(props.size_b as usize)
    }

    /// Spawn background simulation thread
    /// Poll on workq, do associated work and send response on ackq
    pub fn spawn(mut self) {
        std::thread::spawn(move || {
            loop {
                // Probe memory request
                match self.mem_req_rx.try_recv() {
                    Ok(req) => {
                        let chunk = self.alloc(req);
                        self.mem_resp_tx.send(chunk).unwrap();
                    }
                    Err(TryRecvError::Empty) => { /*Do nothing*/ }
                    Err(TryRecvError::Disconnected) => {
                        // SimHandle were closed by host. Stop simulation
                        break;
                    }
                }

                // Probe workq request
                match self.workq_rx.try_recv() {
                    Ok(word) => {
                        let word_b = word.to_be_bytes();
                        self.workq_stream.extend_from_slice(&word_b);
                        match self
                            .iop_parser
                            .from_be_bytes::<asm::FmtIOp>(self.workq_stream.as_slice())
                        {
                            Ok(iop) => {
                                // Iop properly parsed, consume the stream
                                self.workq_stream.clear();
                                self.simulate(iop)
                            }
                            Err(_) => {
                                // not enough data to match
                                continue;
                            }
                        }
                    }
                    Err(TryRecvError::Empty) => { /*Do nothing*/ }
                    Err(TryRecvError::Disconnected) => {
                        // SimHandle were closed by host. Stop simulation
                        break;
                    }
                }
            }
        });
    }
}

impl HpuSim {
    fn simulate(&mut self, iop: asm::IOp) {
        println!("Simulation start for {iop:?}");
        self.ucore_translate(&iop);

        // Push ack in stream
        // Bytes are in little-endian but written from first to last line
        // To keep correct endianness -> reverse the chunked vector
        let bytes = iop.bin_encode_le().unwrap();
        for bytes_chunks in bytes.chunks(std::mem::size_of::<u32>()).rev().take(1) {
            let word_b = bytes_chunks.try_into().expect("Invalid slice length");
            let word_u32 = u32::from_le_bytes(word_b);
            self.ackq_tx.send(word_u32).unwrap()
        }
    }

    /// Retrieve DOp stream from memory and patch template DOp
    fn ucore_translate(&self, iop: &asm::IOp) -> Vec<asm::DOp> {
        // Retrieved DOp stream in memory
        let dops = {
            let iop_code = {
                let mut bytes = iop.bin_encode_le().unwrap();
                bytes.reverse();
                bytes[0] as u32
            };

            // Bypass fw_ofst register value
            // Expect to have only one memzone in fw bank allocated in 0
            // TODO correctly read associated register value
            let fw_bank = &self.hbm_bank[self.config.board.fw_pc];
            let fw_chunk = fw_bank.get_chunk(0);
            let fw_view = fw_chunk.hw_view();
            let fw_view_u32 = bytemuck::cast_slice::<u8, u32>(fw_view.as_slice());

            // WARN: fw ofst are in byte addr and we addr the fw array as 32b word
            let dop_ofst = fw_view_u32[iop_code as usize] as usize / std::mem::size_of::<u32>();
            let dop_len = fw_view_u32[dop_ofst] as usize;
            let (start, end) = (dop_ofst + 1, dop_ofst + 1 + dop_len);
            let dop_stream = &fw_view_u32[start..end];

            let dops = {
                // Allocate DOp parser
                let dops_ref = asm::DOp::iter().collect::<Vec<_>>();
                let mut dop_parser = asm::Parser::new(dops_ref);
                dop_stream
                    .iter()
                    .map(|bin| {
                        let be_bytes = bin.to_be_bytes();
                        dop_parser.from_be_bytes::<asm::FmtDOp>(&be_bytes).unwrap()
                    })
                    .collect::<Vec<asm::DOp>>()
            };
            dops
        };

        // Rtl ucore emulation
        // Ucore is in charge of patching DOp stream in-flight and to replace Templated LD/ST with
        // explicit one
        // NB: Currently heap is always the last defined bid
        let heap = asm::MemRegion {
            bid: self.config.board.ct_bank.len() - 1,
            size: *self.config.board.ct_bank.last().unwrap(),
        };

        let iop_args = iop.args();
        let dops_patch = dops
            .iter()
            .map(|dop| {
                fn fuse_tmem_user(dop_ms: &asm::MemSlot, iop_arg: &asm::Arg) -> asm::MemSlot {
                    if let asm::Arg::MemId(iop_ms) = iop_arg {
                        asm::MemSlot::new_uncheck(
                            iop_ms.bid(),
                            iop_ms.cid() + dop_ms.cid(),
                        asm::MemMode::Raw,
                        None,
                        )
                    } else {
                        panic!("Dop template arg patching only work on MemId")
                    }
                }

                fn fuse_tmem_heap(dop_ms: &asm::MemSlot, heap: &asm::MemRegion) -> asm::MemSlot {
                    assert!(heap.size >= dop_ms.cid(),
                    "Asm heap overflow, request more heap than the one allocated for simulation. Check fw/simulation parameters");
                    asm::MemSlot::new_uncheck(
                        heap.bid,
                        dop_ms.cid(),
                        asm::MemMode::Raw,
                        None,
                    )
                }
                match dop {
                    // NB: Templated Load are patch with LD
                    asm::DOp::TLDA(op) => {
                        let mut patch_op = asm::DOpLd::default();
                        patch_op.src = fuse_tmem_user(&op.src, &iop_args[1]);
                        patch_op.dst = op.dst;
                        asm::DOp::LD(patch_op)
                    }
                    asm::DOp::TLDB(op) => {
                        let mut patch_op = asm::DOpLd::default();
                        patch_op.src = fuse_tmem_user(&op.src, &iop_args[2]);
                        patch_op.dst = op.dst;
                        asm::DOp::LD(patch_op)
                    }
                    asm::DOp::TLDH(op) => {
                        let mut patch_op = asm::DOpLd::default();
                        patch_op.src = fuse_tmem_heap(&op.src, &heap);
                        patch_op.dst = op.dst;
                        asm::DOp::LD(patch_op)
                    }
                    // NB: Templated Store are patch with ST
                    asm::DOp::TSTD(op) => {
                        let mut patch_op = asm::DOpSt::default();
                        patch_op.dst = fuse_tmem_user(&op.dst, &iop_args[0]);
                        patch_op.src = op.src;
                        asm::DOp::ST(patch_op)
                    }
                    asm::DOp::TSTH(op) => {
                        let mut patch_op = asm::DOpSt::default();
                        patch_op.dst = fuse_tmem_heap(&op.dst, &heap);
                        patch_op.src = op.src;
                        asm::DOp::ST(patch_op)
                    }
                    _ => dop.clone(),
                }
            })
            .collect::<Vec<_>>();
        tracing::debug!("Patch DOp stream => {dops_patch:?}");
        dops_patch
    }
}
