use lwe_ciphertext::HpuLweCiphertext;
use std::array::from_fn;
use std::sync::mpsc;
use strum::IntoEnumIterator;

mod ipc;
use ipc::Ipc;

mod mockup_params;
pub use mockup_params::MockupParameters;

mod modules;
use modules::{HbmBank, RegisterMap, HBM_BANK_NB};

use asm::{Asm, AsmBin};
use tfhe::tfhe_hpu_backend::asm;
use tfhe::tfhe_hpu_backend::prelude::*;

pub struct HpuSim {
    config: HpuConfig,
    params: MockupParameters,
    ipc: Ipc,
    regmap: RegisterMap,

    /// On-board memory
    hbm_bank: [HbmBank; HBM_BANK_NB],
    /// On-chip regfile
    regfile: Vec<HpuLweCiphertextOwned<u64>>,

    // WorkAckq interface -----------------------------------------------------
    workq_rx: mpsc::Receiver<u32>,
    ackq_tx: mpsc::Sender<u32>,
    workq_stream: Vec<u8>,
    /// Parser for workq_stream
    iop_parser: asm::Parser<asm::IOp>,
}

impl HpuSim {
    pub fn new(config: HpuConfig, params: MockupParameters) -> Self {
        // Allocate communication channels
        let ipc = {
            let name = match config.fpga.ffi {
                FFIMode::Sim { ref ipc_name } => ipc_name.to_string(),
                _ => panic!("Unsupported config type with ffi::sim"),
            };
            Ipc::new(&name)
        };

        // Allocate register map emulation
        let (regmap, (workq_rx, ackq_tx)) =
            RegisterMap::new(params.rtl_params.clone(), &config.fpga.regmap);

        // Allocate IOp parser for workq_stream
        let iops_ref = asm::IOp::iter().collect::<Vec<_>>();
        let iop_parser = asm::Parser::new(iops_ref);

        // Allocate on-board memory emulation
        let hbm_bank: [HbmBank; HBM_BANK_NB] = from_fn(|i| HbmBank::new(i));

        // Allocate inner regfile and lock abstraction
        let regfile = (0..params.isc_sim_params.register)
            .map(|_| HpuLweCiphertextOwned::new(0, params.rtl_params.clone()))
            .collect::<Vec<_>>();

        Self {
            config,
            params,
            ipc,
            regmap,
            hbm_bank,
            regfile,
            workq_rx,
            ackq_tx,
            workq_stream: Vec::new(),
            iop_parser,
        }
    }

    pub fn ipc_poll(&mut self) {
        loop {
            // Flush register requests
            while let Some(req) = self.ipc.register_req() {
                match req {
                    RegisterReq::Read { addr } => {
                        let val = self.regmap.read_reg(addr);
                        self.ipc.register_ack(RegisterAck::Read(val));
                    }
                    RegisterReq::Write { addr, value } => {
                        self.regmap.write_reg(addr, value);
                        self.ipc.register_ack(RegisterAck::Write);
                    }
                }
            }

            // Flush memory requests
            while let Some(req) = self.ipc.memory_req() {
                match req {
                    MemoryReq::Allocate { hbm_pc, size_b } => {
                        let (addr, (tx, rx)) = self.hbm_bank[hbm_pc].alloc(size_b);
                        self.ipc.memory_ack(MemoryAck::Allocate { addr, tx, rx });
                    }
                    MemoryReq::Sync { hbm_pc, addr, mode } => {
                        // Triggered Sync event in the inner bank
                        // NB: Sync has no ack over Memory channel, instead rely on raw data ipc to
                        // synced
                        self.hbm_bank[hbm_pc].get_mut_chunk(addr).sync(mode);
                    }
                    MemoryReq::Release { hbm_pc, addr } => {
                        self.hbm_bank[hbm_pc].rm_chunk(addr);
                        self.ipc.memory_ack(MemoryAck::Release);
                    }
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
                Err(mpsc::TryRecvError::Empty) => { /*Do nothing*/ }
                Err(mpsc::TryRecvError::Disconnected) => panic!("HpuSim inner channel closed"),
            }
        }
    }
}

impl HpuSim {
    fn simulate(&mut self, iop: asm::IOp) {
        tracing::debug!("Simulation start for {iop:?}");

        // Retrived Fw and emulate RTL ucore translation
        let dops = self.ucore_translate(&iop);

        for dop in dops {
            // Read operands
            match dop {
                asm::DOp::LD(op_impl) => {
                    let mut dst = &mut self.regfile[op_impl.dst];
                    let asm::MemSlot { bid, cid_ofst, .. } = op_impl.src;

                    let ct_ofst = cid_ofst
                        * page_align(
                            hpu_big_lwe_ciphertext_size(&self.params.rtl_params)
                                .div_ceil(self.params.rtl_params.pc_params.pem_pc)
                                * std::mem::size_of::<u64>(),
                        );
                    let ct_chunk = self
                        .config
                        .board
                        .ct_pc
                        .iter()
                        .map(|pc| self.hbm_bank[*pc].get_chunk(ct_ofst as u64))
                        .collect::<Vec<_>>();

                    let ct_slice_u64 = ct_chunk
                        .iter()
                        .map(|chunk| {
                            bytemuck::cast_slice::<u8, u64>(&chunk.data.as_slice()[0..8 * 1025])
                        })
                        .collect::<Vec<_>>();

                    dst.copy_from_hw_slice(ct_slice_u64.as_slice());
                }
                asm::DOp::TLDA(_) | asm::DOp::TLDB(_) | asm::DOp::TLDH(_) => panic!(
                    "Templated operation mustn't reach the Hpu execution
                unit. Check ucore translation"
                ),

                asm::DOp::ST(op_impl) => {
                    let src = &self.regfile[op_impl.src];
                    let asm::MemSlot { bid, cid_ofst, .. } = op_impl.dst;

                    let ct_ofst = cid_ofst
                        * page_align(
                            hpu_big_lwe_ciphertext_size(&self.params.rtl_params)
                                .div_ceil(self.params.rtl_params.pc_params.pem_pc)
                                * std::mem::size_of::<u64>(),
                        );
                    for (i, slice) in src.hw_slice().iter().enumerate() {
                        let ct_chunk =
                            self.hbm_bank[self.config.board.ct_pc[i]].get_mut_chunk(ct_ofst as u64);

                        let ct_chunk_u64 = bytemuck::cast_slice_mut::<u8, u64>(
                            &mut ct_chunk.data.as_mut_slice()[0..8 * 1025],
                        );
                        println!("@{i} -> {}", slice.len());
                        // ct_chunk_u64.copy_from_slice(slice.as_slice());
                    }
                }
                asm::DOp::TSTD(_) | asm::DOp::TSTH(_) => panic!(
                    "Templated operation mustn't reach the Hpu execution
                unit. Check ucore translation"
                ),

                // asm::DOp::ADD(op_impl) => {
                //     let (dst, a, b) = self.get_3regs(op_impl.dst, op_impl.src.0, op_impl.src.1);
                //     dst.add_assign(a,b);
                // },
                // asm::DOp::SUB(op_impl) => {
                //     let (dst, a, b) = self.get_3regs(op_impl.dst, op_impl.src.0, op_impl.src.1);
                //     dst.sub_assign(a,b);
                // },
                // asm::DOp::MAC(op_impl) => {
                //     let (dst, a, b) = self.get_3regs(op_impl.dst, op_impl.src.0, op_impl.src.1);
                //     dst.mac_assign(a,b, op_impl.mul_factor);
                // },
                // asm::DOp::ADDS(op_impl) => {
                //     let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                //     dst.adds_assign(src,op_impl.msg_cst);
                // },
                // asm::DOp::SUBS(op_impl) => {
                //     let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                //     dst.subs_assign(src,op_impl.msg_cst);
                // },
                // asm::DOp::SSUB(op_impl) => {
                //     let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                //     dst.ssub_assign(src,op_impl.msg_cst);
                // },
                // asm::DOp::MULS(op_impl) => {
                //     let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                //     dst.muls_assign(src,op_impl.msg_cst);
                // },
                // asm::DOp::PBS(op_impl) => {
                //     let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                //     dst.pbs_assign(src);
                // },
                // asm::DOp::PBS_F(op_impl) => {
                //     let (dst, src) = self.get_2regs(op_impl.dst, op_impl.src);
                //     dst.pbs_assign(src);
                // },
                asm::DOp::SYNC(_) => {
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
                _ => {
                    /* Not implemented yet ->NOP */
                    tracing::debug!("Skip {dop:?}");
                }
            }
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
            let fw_view = &fw_chunk.data;
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
        let mut dops_patch = dops
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

        // Ucore is in charge of Sync insertion
        dops_patch.push(asm::DOp::SYNC(Default::default()));
        tracing::debug!("Patch DOp stream => {dops_patch:?}");
        dops_patch
    }
}
