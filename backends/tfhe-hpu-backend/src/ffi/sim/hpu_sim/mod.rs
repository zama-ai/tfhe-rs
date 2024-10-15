//!
//! Hpu simulation model
//! Simulate Hpu execution, communication with the ffi-model is made through channel
//! HpuSim use it's own thread

mod hbm;
pub mod hpu_ops;
pub use hpu_ops::HpuOps;

use std::array::from_fn;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;

use crate::asm::{self, Asm, AsmBin};
use crate::interface::HpuSimParameters;

pub(crate) use hbm::{HbmBank, HbmChunk};
use strum::IntoEnumIterator;

use crate::entities::{hpu_big_lwe_ciphertext_size, HpuParameters};
use crate::ffi::{HpuConfig, MemZoneProperties};

/// Hpu communication channels
pub(crate) struct HpuChannel {
    pub(crate) host: HpuChannelHost,
    pub(crate) sim: HpuChannelSim,
}

/// Hpu communication channels Simulation side
pub(crate) struct HpuChannelSim {
    // WorkAckQ interface
    workq_rx: Receiver<u32>,
    ackq_tx: Sender<u32>,
    // Memory allocation interface
    mem_req_rx: Receiver<MemZoneProperties>,
    mem_resp_tx: Sender<Arc<HbmChunk>>,
}

/// Hpu communication channels Host side (i.e. ffi)
pub(crate) struct HpuChannelHost {
    // WorkAckQ interface
    pub(crate) workq_tx: Sender<u32>,
    pub(crate) ackq_rx: Receiver<u32>,

    // Memory allocation interface
    pub(crate) mem_req_tx: Sender<MemZoneProperties>,
    pub(crate) mem_resp_rx: Receiver<Arc<HbmChunk>>,
}

impl HpuChannel {
    pub(crate) fn new() -> Self {
        // Allocate channel for communication with ffi
        let (workq_tx, workq_rx) = mpsc::channel();
        let (ackq_tx, ackq_rx) = mpsc::channel();
        let (mem_req_tx, mem_req_rx) = mpsc::channel();
        let (mem_resp_tx, mem_resp_rx) = mpsc::channel();

        Self {
            host: HpuChannelHost {
                workq_tx,
                ackq_rx,
                mem_req_tx,
                mem_resp_rx,
            },
            sim: HpuChannelSim {
                workq_rx,
                ackq_tx,
                mem_req_rx,
                mem_resp_tx,
            },
        }
    }
}

pub(crate) struct HpuSim<T> {
    config: HpuConfig,
    rtl_params: HpuParameters,
    sim_params: HpuSimParameters,

    // Internal simulation components -----------------------------------------
    // cycle_keeper: usize,
    /// On-board memory
    hbm_bank: [HbmBank; hbm::HBM_BANK_NB],
    /// On-chip regfile
    regfile: Vec<T>,
    // ldst_q: ldst_queue::LdStQueue,
    // alu_store: alu::AluStore,
    workq_stream: Vec<u8>,
    // ------------------------------------------------------------------------
    /// Communication channel with associated Host
    channel: HpuChannelSim,

    /// Parser for workq_stream
    iop_parser: asm::Parser<asm::IOp>,
}

impl<T> HpuSim<T>
where
    T: Default + Clone + HpuOps + Send + 'static,
{
    pub(crate) fn new(config: HpuConfig) -> (Self, HpuChannelHost) {
        // Allocate communication channels
        let HpuChannel { host, sim } = HpuChannel::new();

        // Allocate Simulation ressources
        let (rtl_params, sim_params) = match &config.fpga.ffi {
            crate::interface::FFIMode::Sim { rtl, sim } => (rtl.clone(), sim.clone()),
            _ => panic!("Unsupported ffi config"),
        };

        // Allocate on-board memory emulation
        let hbm_bank: [HbmBank; hbm::HBM_BANK_NB] = from_fn(|i| HbmBank::new(i));
        // Allocate inner regfile and lock abstraction
        let regfile = (0..sim_params.register)
            .map(|_| T::default())
            .collect::<Vec<_>>();

        // Allocate IOp parser for workq_stream
        let iops_ref = asm::IOp::iter().collect::<Vec<_>>();
        let iop_parser = asm::Parser::new(iops_ref);

        (
            Self {
                config,
                rtl_params,
                sim_params,
                hbm_bank,
                regfile,
                channel: sim,
                workq_stream: Vec::new(),
                iop_parser,
            },
            host,
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
                match self.channel.mem_req_rx.try_recv() {
                    Ok(req) => {
                        let chunk = self.alloc(req);
                        self.channel.mem_resp_tx.send(chunk).unwrap();
                    }
                    Err(TryRecvError::Empty) => { /*Do nothing*/ }
                    Err(TryRecvError::Disconnected) => {
                        // SimHandle were closed by host. Stop simulation
                        break;
                    }
                }

                // Probe workq request
                match self.channel.workq_rx.try_recv() {
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

impl<T> HpuSim<T>
where
    T: HpuOps + Clone,
{
    fn simulate(&mut self, iop: asm::IOp) {
        tracing::debug!("Simulation start for {iop:?}");

        // Retrived Fw and emulate RTL ucore translation
        let dops = self.ucore_translate(&iop);
        for dop in dops {
            // Read operands
            match dop {
                asm::DOp::LD(op_impl) => {
                    let mut dst = &mut self.regfile[op_impl.dst];
                    let asm::MemSlot{ bid, cid_ofst,..} = op_impl.src;
                    // TODO error on meaning of ct_pc
                    let ct_bank = &self.hbm_bank[self.config.board.ct_pc[bid]];
                    let ct_ofst = cid_ofst * hpu_big_lwe_ciphertext_size(&self.rtl_params); // TODO fixme use correct ct_size => alignement
                    let ct_chunk = ct_bank.get_chunk(ct_ofst);

                    dst.load(&ct_chunk.hw_view());
                },
                asm::DOp::TLDA(_) |
                asm::DOp::TLDB(_) |
                asm::DOp::TLDH(_) => panic!("Templated operation mustn't reach the Hpu execution unit. Check ucore translation"),

                asm::DOp::ST(op_impl) => {
                    let src = & self.regfile[op_impl.src];
                    let asm::MemSlot{ bid, cid_ofst,..} = op_impl.dst;
                    let ct_bank = &self.hbm_bank[self.config.board.ct_pc[bid]];
                    let ct_ofst = cid_ofst * hpu_big_lwe_ciphertext_size(&self.rtl_params); // TODO fixme use correct ct_size => alignement
                    let ct_chunk = ct_bank.get_chunk(ct_ofst);
                    src.store(&mut ct_chunk.hw_view());
                },
                asm::DOp::TSTD(_) |
                asm::DOp::TSTH(_) => panic!("Templated operation mustn't reach the Hpu execution unit. Check ucore translation"),

                asm::DOp::ADD(op_impl) => {
                    let (dst, a, b) = self.get_3regs(op_impl.dst, op_impl.src.0, op_impl.src.1);
                    dst.add_assign(a,b);
                },
                asm::DOp::SUB(op_impl) => {
                    let (dst, a, b) = self.get_3regs(op_impl.dst, op_impl.src.0, op_impl.src.1);
                    dst.sub_assign(a,b);
                },
                asm::DOp::MAC(op_impl) => {
                    let (dst, a, b) = self.get_3regs(op_impl.dst, op_impl.src.0, op_impl.src.1);
                    dst.mac_assign(a,b, op_impl.mul_factor);
                },
                asm::DOp::ADDS(op_impl) => {
                    let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                    dst.adds_assign(src,op_impl.msg_cst);
                },
                asm::DOp::SUBS(op_impl) => {
                    let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                    dst.subs_assign(src,op_impl.msg_cst);
                },
                asm::DOp::SSUB(op_impl) => {
                    let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                    dst.ssub_assign(src,op_impl.msg_cst);
                },
                asm::DOp::MULS(op_impl) => {
                    let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                    dst.muls_assign(src,op_impl.msg_cst);
                },
                asm::DOp::PBS(op_impl) => {
                    let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                    dst.pbs_assign(src);
                },
                asm::DOp::PBS_F(op_impl) => {
                    let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                    dst.pbs_assign(src);
                },

                asm::DOp::SYNC(_) => {
                    // Push ack in stream
                    // Bytes are in little-endian but written from first to last line
                    // To keep correct endianness -> reverse the chunked vector
                    let bytes = iop.bin_encode_le().unwrap();
                    for bytes_chunks in bytes.chunks(std::mem::size_of::<u32>()).rev().take(1) {
                        let word_b = bytes_chunks.try_into().expect("Invalid slice length");
                        let word_u32 = u32::from_le_bytes(word_b);
                        self.channel.ackq_tx.send(word_u32).unwrap()
                    }
                },
            }
        }
    }

    /// Extract values from register file
    /// Currently clone the source to prevent issue with borrow checker and custom case
    /// TODO: Rework with id check and split_at_mut()
    fn get_2regs(&mut self, id_dst: usize, id_src: usize) -> (&mut T, T) {
        let src = self.regfile[id_src].clone();
        let dst = &mut self.regfile[id_dst];
        (dst, src)
    }

    /// Extract values from register file
    /// Currently clone the source to prevent issue with borrow checker and custom case
    /// TODO: Rework with id check and split_at_mut()
    fn get_3regs(&mut self, id_dst: usize, id_src_a: usize, id_src_b: usize) -> (&mut T, T, T) {
        let src_a = self.regfile[id_src_a].clone();
        let src_b = self.regfile[id_src_b].clone();
        let dst = &mut self.regfile[id_dst];
        (dst, src_a, src_b)
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
