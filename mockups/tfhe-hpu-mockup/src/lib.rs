// Should be removed when we raise MSRV above 1.87
#![allow(clippy::manual_is_multiple_of)]

#[cfg(feature = "isc-order-check")]
use hpu_asm::dop::ToAsm;
use hpu_asm::PbsLut;
use std::array::from_fn;
use std::collections::VecDeque;
use std::io::Write;
use tfhe::core_crypto::algorithms::{
    lwe_ciphertext_add_assign, lwe_ciphertext_cleartext_mul_assign, lwe_ciphertext_opposite_assign,
    lwe_ciphertext_plaintext_add_assign, lwe_ciphertext_plaintext_sub_assign,
    lwe_ciphertext_sub_assign,
};
use tfhe::core_crypto::entities::{
    Cleartext, LweCiphertextOwned, LweCiphertextView, LweKeyswitchKey, NttLweBootstrapKey,
    Plaintext,
};
use tfhe::core_crypto::hpu::glwe_lookuptable::create_hpu_lookuptable;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::KeySwitch32PBSParameters;
use tfhe::tfhe_hpu_backend::fw::isc_sim::PeConfigStore;

mod ipc;
use ipc::Ipc;

mod modules;
pub use modules::isc;
pub use modules::params::{MockupOptions, MockupParameters};
use modules::{DdrMem, HbmBank, RegisterEvent, RegisterMap, UCore, HBM_BANK_NB};

use tfhe::tfhe_hpu_backend::interface::io_dump::HexMem;
use tfhe::tfhe_hpu_backend::prelude::*;

pub struct HpuSim {
    config: HpuConfig,
    params: MockupParameters,
    options: MockupOptions,

    ipc: Ipc,
    regmap: RegisterMap,

    /// On-board memory
    hbm_bank: [HbmBank; HBM_BANK_NB],
    ddr: DdrMem,
    /// On-chip regfile
    regfile: Vec<HpuLweCiphertextOwned<u64>>,
    /// Program counter
    pc: usize,

    /// UCore model
    ucore: UCore,

    /// Instruction scheduler
    isc: isc::Scheduler,

    // WorkAckq interface -----------------------------------------------------
    workq_stream: VecDeque<hpu_asm::iop::IOpWordRepr>,
    /// Pending Iop
    iop_req: VecDeque<hpu_asm::IOp>,
    iop_nb: usize,
    iop_pdg: VecDeque<hpu_asm::IOp>,

    /// Tfhe server keys
    /// Read from memory after bsk_avail/ksk_avail register are set
    /// Conversion from Hpu->Cpu is costly. Thuse store it in the object to prevent extra
    /// computation
    /// Also store buffer for ks-pbs computation
    sks: Option<(
        LweKeyswitchKeyOwned<u32>,
        LweCiphertextOwned<u32>,
        NttLweBootstrapKeyOwned<u64>,
    )>,

    // Execute history --------------------------------------------------------
    #[cfg(feature = "isc-order-check")]
    dops_exec_order: Vec<hpu_asm::DOp>,
    #[cfg(feature = "isc-order-check")]
    dops_check_order: Vec<hpu_asm::DOp>,
}

impl HpuSim {
    pub fn new(config: HpuConfig, params: MockupParameters, options: MockupOptions) -> Self {
        // Allocate communication channels
        let ipc = {
            let name = match config.fpga.ffi {
                FFIMode::Sim { ref ipc_name } => ipc_name.expand(),
                _ => panic!("Unsupported config type with ffi::sim"),
            };
            Ipc::new(&name)
        };
        // Allocate register map emulation
        let regmap_expanded = config
            .fpga
            .regmap
            .iter()
            .map(|f| f.expand())
            .collect::<Vec<_>>();
        let regmap_str = regmap_expanded
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>();
        let regmap = RegisterMap::new(params.rtl_params.clone(), &regmap_str);

        // Allocate on-board memory emulation
        let hbm_bank: [HbmBank; HBM_BANK_NB] = from_fn(HbmBank::new);
        let ddr = DdrMem::new();

        // Allocate inner regfile and lock abstraction
        let regfile = (0..params.rtl_params.regf_params.reg_nb)
            .map(|_| HpuLweCiphertextOwned::new(0, params.rtl_params.clone()))
            .collect::<Vec<_>>();

        // Allocate Ucore Fw translation
        let ucore = UCore::new(config.board.clone());

        // Allocate InstructionScheduler
        // This module is also in charge of performances estimation
        let pe_config = PeConfigStore::from((&params.rtl_params, &config));
        let isc = isc::Scheduler::new(
            params.freq_mhz,
            params.quantum_us,
            &params.rtl_params.isc_params,
            pe_config,
        );
        Self {
            config,
            params,
            options,
            ipc,
            regmap,
            hbm_bank,
            ddr,
            regfile,
            pc: 0,
            ucore,
            isc,
            workq_stream: VecDeque::new(),
            iop_req: VecDeque::new(),
            iop_nb: 0,
            iop_pdg: VecDeque::new(),
            sks: None,
            #[cfg(feature = "isc-order-check")]
            dops_exec_order: Vec::new(),
            #[cfg(feature = "isc-order-check")]
            dops_check_order: Vec::new(),
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
                        let evt = self.regmap.write_reg(addr, value);
                        match evt {
                            RegisterEvent::None => { /* Nothing to do */ }
                            RegisterEvent::KeyReset => {
                                // Reset associated key option
                                self.sks = None;
                            }
                            RegisterEvent::WorkQ(word) => {
                                // Append to workq_stream and try to extract an iop
                                self.workq_stream.push_back(word);
                                match hpu_asm::IOp::from_words(&mut self.workq_stream) {
                                    Ok(iop) => self.iop_req.push_back(iop),
                                    Err(_) => {
                                        // not enough data to match
                                    }
                                }
                            }
                        }
                        self.ipc.register_ack(RegisterAck::Write);
                    }
                    RegisterReq::PbsParams => {
                        self.ipc.register_ack(RegisterAck::PbsParams(
                            self.params.rtl_params.pbs_params,
                        ));
                    }
                }
            }

            // Flush memory requests
            while let Some(req) = self.ipc.memory_req() {
                match req {
                    MemoryReq::Allocate { mem_kind, size_b } => {
                        let addr = match mem_kind {
                            MemKind::Ddr { offset } => {
                                self.ddr.alloc_at(offset as u64, size_b);
                                offset as u64
                            }
                            MemKind::Hbm { pc } => self.hbm_bank[pc].alloc(size_b),
                        };
                        self.ipc.memory_ack(MemoryAck::Allocate { addr });
                    }
                    MemoryReq::Sync {
                        mem_kind,
                        addr,
                        mode,
                        data,
                    } => match mode {
                        SyncMode::Host2Device => {
                            let sw_data = data.expect("No data received on Host2Device sync");
                            match mem_kind {
                                MemKind::Ddr { .. } => {
                                    self.ddr.get_mut_chunk(addr).ipc_update(sw_data)
                                }
                                MemKind::Hbm { pc } => {
                                    self.hbm_bank[pc].get_mut_chunk(addr).ipc_update(sw_data)
                                }
                            }
                            // Generate ack
                            self.ipc.memory_ack(MemoryAck::Sync { data: None });
                        }
                        SyncMode::Device2Host => {
                            assert!(data.is_none(), "Received data on Device2Host sync");

                            // Read data
                            let hw_data = match mem_kind {
                                MemKind::Ddr { .. } => self.ddr.get_mut_chunk(addr).ipc_wrap(),
                                MemKind::Hbm { pc } => self.hbm_bank[pc].get_chunk(addr).ipc_wrap(),
                            };

                            // Generate ack
                            self.ipc.memory_ack(MemoryAck::Sync {
                                data: Some(hw_data),
                            });
                        }
                    },
                    MemoryReq::Release { mem_kind, addr } => {
                        match mem_kind {
                            MemKind::Ddr { .. } => {
                                let _ = self.ddr.rm_chunk(addr);
                            }
                            MemKind::Hbm { pc } => {
                                let _ = self.hbm_bank[pc].rm_chunk(addr);
                            }
                        };
                        self.ipc.memory_ack(MemoryAck::Release);
                    }
                }
            }

            // Issue IOp requests to isc
            while let Some(iop) = self.iop_req.pop_front() {
                let (dops, dops_patched) =
                    self.ucore
                        .translate(&self.ddr, self.hbm_bank.as_slice(), &iop);

                // Write required input material if needed
                if let Some(dump_path) = self.options.dump_out.as_ref() {
                    let iopcode = iop.opcode().0;

                    // Generate IOp file
                    let asm_p = format!("{dump_path}/iop/iop_{}.asm", self.iop_nb);
                    let hex_p = format!("{dump_path}/iop/iop_{}.hex", self.iop_nb);
                    let mut iop_prog = hpu_asm::Program::default();
                    iop_prog.push_comment(format!("{iop}"));
                    iop_prog.push_stmt(iop.clone());
                    iop_prog.write_asm(&asm_p).unwrap();
                    iop_prog.write_hex(&hex_p).unwrap();
                    self.iop_nb += 1;

                    // Generate DOps file
                    // TODO find a proper way to add the header back
                    let asm_p = format!("{dump_path}/dop/dop_{iopcode:0>2x}.asm");
                    let hex_p = format!("{dump_path}/dop/dop_{iopcode:0>2x}.hex");
                    let dop_prog = hpu_asm::Program::new(
                        dops.iter()
                            .map(|op| hpu_asm::AsmOp::Stmt(op.clone()))
                            .collect::<Vec<_>>(),
                    );
                    dop_prog.write_asm(&asm_p).unwrap();
                    dop_prog.write_hex(&hex_p).unwrap();
                    // Generate patched DOps file
                    let asm_patched_p = format!("{dump_path}/dop/dop_patched_{iopcode:0>2x}.asm");
                    let hex_patched_p = format!("{dump_path}/dop/dop_patched_{iopcode:0>2x}.hex");
                    let dop_patched_prog = hpu_asm::Program::new(
                        dops_patched
                            .iter()
                            .map(|op| hpu_asm::AsmOp::Stmt(op.clone()))
                            .collect::<Vec<_>>(),
                    );
                    dop_patched_prog.write_asm(&asm_patched_p).unwrap();
                    dop_patched_prog.write_hex(&hex_patched_p).unwrap();
                }

                // Use to check correct scheduling at runtime
                #[cfg(feature = "isc-order-check")]
                self.dops_check_order
                    .extend_from_slice(dops_patched.as_slice());

                // Push associated dops to scheduler
                self.isc.insert_dops(dops_patched);
                self.iop_pdg.push_back(iop);
            }

            // Advance simulation for quantum_us time
            // Quantum is used here to keep the mockup responsive to IPC
            if !self.iop_pdg.is_empty() {
                let bpip_timeout = if self.regmap.bpip_state().used {
                    Some(self.regmap.bpip_state().timeout)
                } else {
                    None
                };
                let dops_exec = self.isc.schedule(bpip_timeout);
                for dop in dops_exec {
                    self.exec(&dop);
                    #[cfg(feature = "isc-order-check")]
                    {
                        self.check_order(&dop);
                        self.dops_exec_order.push(dop);
                    }
                }
            }
        }
    }
}

impl HpuSim {
    fn trivial_decode<T: UnsignedInteger>(&self, body: T) -> T {
        let pbs_p = self.params.rtl_params.pbs_params;
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        (body >> (T::BITS - cleartext_and_padding_width))
            & ((T::ONE << cleartext_and_padding_width) - T::ONE)
    }
    #[allow(dead_code)]
    fn trivial_encode<T: UnsignedInteger>(&self, clear: T) -> T {
        let pbs_p = self.params.rtl_params.pbs_params;
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        clear << (T::BITS - cleartext_and_padding_width)
    }

    fn as_trivial<T: UnsignedInteger>(&self, hpu_ct: &HpuLweCiphertextView<T>) -> T {
        let body = hpu_ct[hpu_big_lwe_ciphertext_size(&self.params.rtl_params) - 1];
        self.trivial_decode(body)
    }

    fn show_trivial_reg(&self, reg_id: hpu_asm::RegId) {
        if self.options.trivial {
            let ct = &self.regfile[reg_id.0 as usize].as_view();
            tracing::debug!("{reg_id} -> {}", self.as_trivial::<u64>(ct))
        }
    }
}

impl HpuSim {
    fn exec(&mut self, dop: &hpu_asm::DOp) {
        tracing::debug!("DOp execution @{}:: {dop}", self.pc);

        // Read operands
        match dop {
            hpu_asm::DOp::SYNC(_) => {
                // Push ack in stream
                let iop = self
                    .iop_pdg
                    .pop_front()
                    .expect("SYNC received but no pending IOp to acknowledge");
                // Answer with IOp header
                let iop_header_u32 = iop.to_words()[0];
                self.regmap.ack_pdg(iop_header_u32);

                // Generate executed DOp order
                #[cfg(feature = "isc-order-check")]
                if let Some(dump_path) = self.options.dump_out.as_ref() {
                    let iopcode = iop.opcode().0;

                    let asm_p = format!("{dump_path}/dop/dop_executed_{iopcode:0>2x}.asm");
                    let hex_p = format!("{dump_path}/dop/dop_executed_{iopcode:0>2x}.hex");
                    let dop_prog = hpu_asm::Program::new(
                        self.dops_exec_order
                            .iter()
                            .map(|op| hpu_asm::AsmOp::Stmt(op.clone()))
                            .collect::<Vec<_>>(),
                    );
                    dop_prog.write_asm(&asm_p).unwrap();
                    dop_prog.write_hex(&hex_p).unwrap();
                }

                // Generate report
                let time_rpt = self.isc.time_report();
                let dop_rpt = self.isc.dop_report();
                let pe_rpt = self.isc.pe_report();
                tracing::info!("Report for IOp: {}", iop);
                tracing::info!("{time_rpt:?}");
                tracing::info!("{dop_rpt}");
                tracing::info!("{pe_rpt}");

                if let Some(mut rpt_file) = self.options.report_file((&iop).into()) {
                    writeln!(rpt_file, "Report for IOp: {iop}").unwrap();
                    writeln!(rpt_file, "{time_rpt:?}").unwrap();
                    writeln!(rpt_file, "{dop_rpt}").unwrap();
                    writeln!(rpt_file, "{pe_rpt}").unwrap();
                }

                let trace = self.isc.reset_trace();
                trace.iter().for_each(|pt| tracing::trace!("{pt}"));
                if let Some(mut trace_file) = self.options.report_trace((&iop).into()) {
                    let json_string =
                        serde_json::to_string(&trace).expect("Could not serialize trace");
                    writeln!(trace_file, "{json_string}").unwrap();
                }
            }
            hpu_asm::DOp::LD(op_impl) => {
                let dst = &mut self.regfile[op_impl.0.rid.0 as usize];
                let cid_ofst = match op_impl.0.slot {
                    hpu_asm::MemId::Addr(ct_id) => ct_id.0 as usize,
                    _ => panic!("Template must have been resolved before execution"),
                };

                // Ct_ofst is equal over PC
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
                    .enumerate()
                    .map(|(id, mem_kind)| {
                        let ldst_ofst = {
                            let (msb, lsb) = self.regmap.addr_offset().ldst[id];
                            ((msb as u64) << 32) + lsb as u64
                        };
                        match mem_kind {
                            MemKind::Ddr { .. } => {
                                self.ddr.get_chunk(ldst_ofst + ct_ofst as u64).data()
                            }
                            MemKind::Hbm { pc } => self.hbm_bank[*pc]
                                .get_chunk(ldst_ofst + ct_ofst as u64)
                                .data(),
                        }
                        // self.hbm_bank[*pc].get_chunk(ldst_ofst + ct_ofst as u64)
                    })
                    .collect::<Vec<_>>();

                let hw_slice = dst.as_mut_view().into_container();
                std::iter::zip(hw_slice, ct_chunk).for_each(|(hpu, mem)| {
                    // NB: Chunk are extended to enforce page align buffer
                    // -> To prevent error during copy, with shrink the mem buffer to
                    // the real   size before-hand
                    let size_b = std::mem::size_of_val(hpu);
                    let hbm_u64 = bytemuck::cast_slice::<u8, u64>(&mem[0..size_b]);
                    hpu.clone_from_slice(hbm_u64);
                });
                self.show_trivial_reg(op_impl.0.rid);
            }

            hpu_asm::DOp::ST(op_impl) => {
                let src = &self.regfile[op_impl.0.rid.0 as usize];
                let cid_ofst = match op_impl.0.slot {
                    hpu_asm::MemId::Addr(ct_id) => ct_id.0 as usize,
                    _ => panic!("Template must have been resolved before execution"),
                };

                // Ct_ofst is equal over PC
                let ct_ofst = cid_ofst
                    * page_align(
                        hpu_big_lwe_ciphertext_size(&self.params.rtl_params)
                            .div_ceil(self.params.rtl_params.pc_params.pem_pc)
                            * std::mem::size_of::<u64>(),
                    );
                src.as_view()
                    .into_container()
                    .into_iter()
                    .enumerate()
                    .for_each(|(id, hpu)| {
                        let ldst_ofst = {
                            let (msb, lsb) = self.regmap.addr_offset().ldst[id];
                            ((msb as u64) << 32) + lsb as u64
                        };
                        let ct_chunk_mut_view = match self.config.board.ct_pc[id] {
                            MemKind::Ddr { .. } => self
                                .ddr
                                .get_mut_chunk(ldst_ofst + ct_ofst as u64)
                                .data_mut(),
                            MemKind::Hbm { pc } => self.hbm_bank[pc]
                                .get_mut_chunk(ldst_ofst + ct_ofst as u64)
                                .data_mut(),
                        };
                        // NB: hbm chunk are extended to enforce page align buffer
                        // -> Shrunk it to slice size to prevent error during copy
                        let size_b = std::mem::size_of_val(hpu);

                        let ct_chunk_u64 =
                            bytemuck::cast_slice_mut::<u8, u64>(&mut ct_chunk_mut_view[0..size_b]);
                        ct_chunk_u64.copy_from_slice(hpu);
                    });
                self.show_trivial_reg(op_impl.0.rid);
            }

            hpu_asm::DOp::ADD(op_impl) => {
                self.show_trivial_reg(op_impl.0.src0_rid);
                self.show_trivial_reg(op_impl.0.src1_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src0_rid);
                let cpu_s1 = self.reg2cpu(op_impl.0.src1_rid);
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
            }
            hpu_asm::DOp::SUB(op_impl) => {
                self.show_trivial_reg(op_impl.0.src0_rid);
                self.show_trivial_reg(op_impl.0.src1_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src0_rid);
                let cpu_s1 = self.reg2cpu(op_impl.0.src1_rid);
                lwe_ciphertext_sub_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
            }
            hpu_asm::DOp::MAC(op_impl) => {
                self.show_trivial_reg(op_impl.0.src0_rid);
                self.show_trivial_reg(op_impl.0.src1_rid);

                // NB: Srcs are used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src0_rid);
                let cpu_s1 = self.reg2cpu(op_impl.0.src1_rid);

                lwe_ciphertext_cleartext_mul_assign(
                    &mut cpu_s0,
                    Cleartext(op_impl.0.mul_factor.0 as u64),
                );
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);

                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
            }
            hpu_asm::DOp::ADDS(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
            }
            hpu_asm::DOp::SUBS(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_sub_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
            }
            hpu_asm::DOp::SSUB(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                lwe_ciphertext_opposite_assign(&mut cpu_s0);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
            }
            hpu_asm::DOp::MULS(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                lwe_ciphertext_cleartext_mul_assign(&mut cpu_s0, Cleartext(msg_cst));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
            }
            hpu_asm::DOp::PBS(op_impl) => {
                self.apply_pbs2reg(1, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
            hpu_asm::DOp::PBS_ML2(op_impl) => {
                self.apply_pbs2reg(2, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
            hpu_asm::DOp::PBS_ML4(op_impl) => {
                self.apply_pbs2reg(4, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
            hpu_asm::DOp::PBS_ML8(op_impl) => {
                self.apply_pbs2reg(8, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
            hpu_asm::DOp::PBS_F(op_impl) => {
                self.apply_pbs2reg(1, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
            hpu_asm::DOp::PBS_ML2_F(op_impl) => {
                self.apply_pbs2reg(2, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
            hpu_asm::DOp::PBS_ML4_F(op_impl) => {
                self.apply_pbs2reg(4, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
            hpu_asm::DOp::PBS_ML8_F(op_impl) => {
                self.apply_pbs2reg(8, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid)
            }
        }

        // Dump operation src/dst in file if required
        self.dump_op_reg(dop);

        // Increment program counter
        self.pc += 1;
    }

    /// Compute dst_rid <- Pbs(src_rid, lut)
    /// Use a function to prevent code duplication in PBS/PBS_F implementation
    /// NB: Current Pbs lookup function arn't reverted from Hbm memory
    /// TODO: Read PbsLut from Hbm instead of online generation based on Pbs Id
    fn apply_pbs2reg(
        &mut self,
        opcode_lut_nb: u8,
        dst_rid: hpu_asm::RegId,
        src_rid: hpu_asm::RegId,
        gid: hpu_asm::PbsGid,
    ) {
        let mut cpu_reg = self.reg2cpu(src_rid);
        let lut = hpu_asm::Pbs::from_hex(gid).expect("Invalid PBS Gid");
        // TODO use an assert or a simple warning
        // In practice, hardware apply the LUT but extract only opcode_lut_nb Ct
        assert_eq!(
            lut.lut_nb(),
            opcode_lut_nb,
            "ERROR: Mismatch between PBS ML configuration and selected Lut."
        );

        assert_eq!(
            dst_rid.0,
            (dst_rid.0 >> lut.lut_lg()) << lut.lut_lg(),
            "Pbs destination register must be aligned with lut size"
        );

        // Generate Lut
        let hpu_lut = create_hpu_lookuptable(self.params.rtl_params.clone(), &lut);
        let tfhe_lut = GlweCiphertext::from(hpu_lut.as_view());

        // Compute Lut properties
        let (modulus_sup, box_size, fn_stride) = {
            let pbs_p = &self.params.rtl_params.pbs_params;
            let modulus_sup = 1_usize << (pbs_p.message_width + pbs_p.carry_width);
            let box_size = pbs_p.polynomial_size / modulus_sup;
            // Max valid degree for a ciphertext when using the LUT we generate
            // If MaxDegree == 1, we can have two input values 0 and 1, so we need MaxDegree + 1
            // boxes
            let max_degree = modulus_sup / lut.lut_nb() as usize;
            let fn_stride = max_degree * box_size;
            (modulus_sup, box_size, fn_stride)
        };

        if self.options.trivial {
            self.show_trivial_reg(src_rid);

            let ct_value = self.trivial_decode(*cpu_reg.get_body().data) as usize;
            let padding_bit_set = ct_value >= modulus_sup;
            let first_index_in_lut = {
                let ct_value = ct_value % modulus_sup;
                ct_value * box_size
            };

            for fn_idx in 0..lut.lut_nb() as usize {
                let (index_in_lut, wrap_around_negation) = {
                    let raw_index = first_index_in_lut + fn_idx * fn_stride;
                    let wrap_around = raw_index / tfhe_lut.polynomial_size().0;
                    (
                        raw_index % tfhe_lut.polynomial_size().0,
                        (wrap_around % 2) == 1,
                    )
                };
                let pbs_out = if padding_bit_set ^ wrap_around_negation {
                    tfhe_lut.get_body().as_ref()[index_in_lut].wrapping_neg()
                } else {
                    tfhe_lut.get_body().as_ref()[index_in_lut]
                };

                *cpu_reg.get_mut_body().data = pbs_out;

                let manylut_rid = hpu_asm::RegId(dst_rid.0 + fn_idx as u8);
                self.cpu2reg(manylut_rid, cpu_reg.as_view());
                self.show_trivial_reg(manylut_rid);
            }
        } else {
            let mut tfhe_lut = tfhe_lut;
            let modulus_switch_type = self.params.rtl_params.pbs_params.modulus_switch_type;
            // Get keys and computation buffer
            let (ksk, ref mut bfr_after_ks, bsk) = self.get_server_key();
            let log_modulus = bsk.polynomial_size().to_blind_rotation_input_modulus_log();

            keyswitch_lwe_ciphertext_with_scalar_change(ksk, &cpu_reg, bfr_after_ks);
            let bfr_after_ms = match modulus_switch_type {
                HpuModulusSwitchType::Standard => {
                    lwe_ciphertext_modulus_switch(bfr_after_ks.as_view(), log_modulus)
                }
                HpuModulusSwitchType::CenteredMeanNoiseReduction => {
                    lwe_ciphertext_centered_binary_modulus_switch(
                        bfr_after_ks.as_view(),
                        log_modulus,
                    )
                }
            };
            blind_rotate_ntt64_bnf_assign(&bfr_after_ms, &mut tfhe_lut, bsk);

            assert_eq!(
                dst_rid.0,
                (dst_rid.0 >> lut.lut_lg()) << lut.lut_lg(),
                "Pbs destination register must be aligned with lut size"
            );

            // Compute ManyLut function stride
            let fn_stride = {
                let pbs_p = &self.params.rtl_params.pbs_params;
                let modulus_sup = 1_usize << (pbs_p.message_width + pbs_p.carry_width);
                let box_size = pbs_p.polynomial_size / modulus_sup;
                // Max valid degree for a ciphertext when using the LUT we generate
                // If MaxDegree == 1, we can have two input values 0 and 1, so we need MaxDegree + 1
                // boxes
                let max_degree = modulus_sup / lut.lut_nb() as usize;
                max_degree * box_size
            };

            for fn_idx in 0..lut.lut_nb() as usize {
                let monomial_degree = MonomialDegree(fn_idx * fn_stride);
                extract_lwe_sample_from_glwe_ciphertext(&tfhe_lut, &mut cpu_reg, monomial_degree);
                let manylut_rid = hpu_asm::RegId(dst_rid.0 + fn_idx as u8);
                self.cpu2reg(manylut_rid, cpu_reg.as_view());
            }
        }
    }

    // NB: to prevent issues with borrow checker we have to clone the value from
    // the regfile. A clone is also required for conversion
    // Thus, directly cast value in Cpu version to prevent extra clone
    /// Extract a cpu value from register file
    fn reg2cpu(&self, reg_id: hpu_asm::RegId) -> LweCiphertextOwned<u64> {
        let reg = self.regfile[reg_id.0 as usize].as_view();
        LweCiphertextOwned::from(reg)
    }

    /// Insert a cpu value into the register file
    fn cpu2reg(&mut self, reg_id: hpu_asm::RegId, cpu: LweCiphertextView<u64>) {
        let hpu = HpuLweCiphertextOwned::<u64>::create_from(cpu, self.params.rtl_params.clone());
        std::iter::zip(
            self.regfile[reg_id.0 as usize]
                .as_mut_view()
                .into_container(),
            hpu.into_container(),
        )
        .for_each(|(reg, hpu)| {
            reg.copy_from_slice(hpu.as_slice());
        });
    }

    /// Get the inner server key used for computation
    /// Check the register state and extract sks from memory if needed
    fn get_server_key(
        &mut self,
    ) -> (
        &LweKeyswitchKeyOwned<u32>,
        &mut LweCiphertextOwned<u32>,
        &NttLweBootstrapKeyOwned<u64>,
    ) {
        if self.sks.is_none() {
            tracing::debug!("Reload Bsk/Ksk from memory");
            assert!(
                self.regmap.bsk_state().is_avail(),
                "Bsk avail bit was not set. Hw will hang on Pbs computation, Mockup panic instead"
            );
            assert!(
                self.regmap.ksk_state().is_avail(),
                "Ksk avail bit was not set. Hw will hang on Pbs computation, Mockup panic instead"
            );

            // Extract HpuBsk /HpuKsk from hbm
            let hpu_bsk = {
                // Create Hpu Bsk container
                let mut bsk = HpuLweBootstrapKeyOwned::new(0, self.params.rtl_params.clone());

                // Copy content from Hbm
                let hw_slice = bsk.as_mut_view().into_container();
                std::iter::zip(hw_slice, self.config.board.bsk_pc.iter())
                    .enumerate()
                    .for_each(|(id, (hpu, mem_kind))| {
                        let bank = match mem_kind {
                            MemKind::Ddr { .. } => panic!(
                                "Error: Key could not be allocated in Dddr for performance reasons"
                            ),
                            MemKind::Hbm { pc } => &self.hbm_bank[*pc],
                        };
                        let ofst = {
                            let (msb, lsb) = self.regmap.addr_offset().bsk[id];
                            ((msb as usize) << 32) + lsb as usize
                        };
                        bank.read_across_chunk(ofst, hpu);
                    });
                bsk
            };
            let hpu_ksk = {
                // Create Hpu ksk container
                let mut ksk = HpuLweKeyswitchKeyOwned::new(0, self.params.rtl_params.clone());

                // Copy content from Hbm
                let hw_slice = ksk.as_mut_view().into_container();
                std::iter::zip(hw_slice, self.config.board.ksk_pc.iter())
                    .enumerate()
                    .for_each(|(id, (hpu, mem_kind))| {
                        let bank = match mem_kind {
                            MemKind::Ddr { .. } => panic!(
                                "Error: Key could not be allocated in Dddr for performance reasons"
                            ),
                            MemKind::Hbm { pc } => &self.hbm_bank[*pc],
                        };
                        let ofst = {
                            let (msb, lsb) = self.regmap.addr_offset().ksk[id];
                            ((msb as usize) << 32) + lsb as usize
                        };
                        bank.read_across_chunk(ofst, hpu);
                    });
                ksk
            };
            // Allocate Pbs intermediate buffer
            let pbs_p = KeySwitch32PBSParameters::from(self.params.rtl_params.clone());
            let bfr_after_ks = LweCiphertext::new(
                0,
                pbs_p.lwe_dimension.to_lwe_size(),
                pbs_p.post_keyswitch_ciphertext_modulus(),
            );

            // Construct Cpu server_key version
            let cpu_bsk = NttLweBootstrapKey::from(hpu_bsk.as_view());
            let cpu_ksk = LweKeyswitchKey::from(hpu_ksk.as_view());
            self.sks = Some((cpu_ksk, bfr_after_ks, cpu_bsk));
        }
        let (ksk, bfr, bsk) = self.sks.as_mut().unwrap();
        (ksk, bfr, bsk)
    }
}

impl HpuSim {
    fn dump_op_reg(&self, op: &hpu_asm::DOp) {
        if self.options.dump_out.is_some() && self.options.dump_reg {
            let dump_out = self.options.dump_out.as_ref().unwrap();

            // Dump register value
            let regid = match op {
                hpu_asm::DOp::LD(op_impl) => op_impl.0.rid.0 as usize,
                hpu_asm::DOp::ST(op_impl) => op_impl.0.rid.0 as usize,
                hpu_asm::DOp::ADDS(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::SUBS(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::SSUB(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::MULS(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::ADD(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::SUB(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::MAC(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS_ML2(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS_ML4(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS_ML8(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS_F(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS_ML2_F(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS_ML4_F(op_impl) => op_impl.0.dst_rid.0 as usize,
                hpu_asm::DOp::PBS_ML8_F(op_impl) => op_impl.0.dst_rid.0 as usize,
                _ => return,
            };
            let regf = self.regfile[regid].as_view();

            // Create base-path
            let base_path = format!("{}/blwe/run/blwe_isc{}_reg", dump_out, self.pc,);
            self.dump_regf(regf, &base_path);
        }
    }

    /// Dump associated regf value in a file
    fn dump_regf(&self, regf: HpuLweCiphertextView<u64>, base_path: &str) {
        // Iterate over slice
        regf.into_container()
            .iter()
            .enumerate()
            .for_each(|(i, slice)| {
                // Create file-path
                let file_path = format!("{base_path}_{i:0>1x}.hex");
                let mut wr_f = MockupOptions::open_wr_file(&file_path);

                writeln!(&mut wr_f, "# LweCiphertext slice #{i}").unwrap();
                // Compact Blwe on 32b if possible
                if self.params.rtl_params.ntt_params.ct_width <= u32::BITS {
                    let slice_32b = slice.iter().map(|x| *x as u32).collect::<Vec<u32>>();
                    slice_32b.as_slice().write_hex(
                        &mut wr_f,
                        self.params.rtl_params.pc_params.pem_bytes_w,
                        Some("XX"),
                    );
                } else {
                    slice.write_hex(
                        &mut wr_f,
                        self.params.rtl_params.pc_params.pem_bytes_w,
                        Some("XX"),
                    );
                }
            });
    }
}

#[cfg(feature = "isc-order-check")]
impl HpuSim {
    /// Check for RAW/WAR violation at runtime
    fn check_order(&mut self, exec_dop: &hpu_asm::DOp) {
        let exec_pos = self
            .dops_check_order
            .iter()
            .enumerate()
            .filter(|(_i, d)| exec_dop == *d)
            .map(|(i, _d)| i)
            .collect::<Vec<_>>()[0];

        // Check collision with all DOp before
        for dop in self.dops_check_order[0..exec_pos].iter() {
            // Read after Write check
            let raw_err = exec_dop
                .dst()
                .into_iter()
                .flat_map(|dst| dop.src().into_iter().map(move |src| dst == src))
                .fold(false, |acc, cur| acc || cur);

            // Write after read check
            // Mainly associated register is read before the expected write
            let war_err = dop
                .dst()
                .into_iter()
                .flat_map(|dst| exec_dop.src().into_iter().map(move |src| dst == src))
                .fold(false, |acc, cur| acc || cur);

            // Write after write check
            let waw_err = dop
                .dst()
                .into_iter()
                .flat_map(|dst| exec_dop.dst().into_iter().map(move |edst| dst == edst))
                .fold(false, |acc, cur| acc || cur);

            if raw_err {
                tracing::warn!("RAW_ERR {} -> {}", exec_dop, dop);
            }
            if war_err {
                tracing::warn!("WAR_ERR {} -> {}", exec_dop, dop);
            }
            if waw_err {
                tracing::warn!("WAW_ERR {} -> {}", exec_dop, dop);
            }
        }

        // Remove exec_dop from the list
        self.dops_check_order.remove(exec_pos);
    }
}
