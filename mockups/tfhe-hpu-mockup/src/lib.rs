use std::array::from_fn;
use std::collections::VecDeque;
use std::io::Write;
use strum::IntoEnumIterator;
use tfhe::core_crypto::algorithms::{
    lwe_ciphertext_add_assign, lwe_ciphertext_cleartext_mul_assign, lwe_ciphertext_opposite_assign,
    lwe_ciphertext_plaintext_add_assign, lwe_ciphertext_plaintext_sub_assign,
    lwe_ciphertext_sub_assign,
};
use tfhe::core_crypto::entities::{
    Cleartext, LweCiphertextOwned, LweCiphertextView, LweKeyswitchKey, NttLweBootstrapKey,
    Plaintext,
};
use tfhe::core_crypto::hpu::from_with::FromWith;
use tfhe::core_crypto::hpu::glwe_lookuptable::create_hpu_lookuptable;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::prelude::ClassicPBSParameters;

mod ipc;
mod report;
use ipc::Ipc;

mod mockup_params;
pub use mockup_params::{MockupOptions, MockupParameters};

mod modules;
pub use modules::isc;
use modules::{HbmBank, RegisterEvent, RegisterMap, UCore, HBM_BANK_NB};

use hpu_asm::{Asm, AsmBin};
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
    /// On-chip regfile
    regfile: Vec<HpuLweCiphertextOwned<u64>>,
    /// Program counter
    pc: usize,

    /// UCore model
    ucore: UCore,

    /// Instruction scheduler
    isc: isc::Scheduler,

    // WorkAckq interface -----------------------------------------------------
    workq_stream: Vec<u8>,
    /// Parser for workq_stream
    iop_parser: hpu_asm::Parser<hpu_asm::IOp>,
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
        LweKeyswitchKeyOwned<u64>,
        LweCiphertextOwned<u64>,
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
                FFIMode::Sim { ref ipc_name } => ipc_name.to_string(),
                _ => panic!("Unsupported config type with ffi::sim"),
            };
            Ipc::new(&name)
        };
        // Allocate register map emulation
        let regmap = RegisterMap::new(params.rtl_params.clone(), &config.fpga.regmap);

        // Allocate IOp parser for workq_stream
        let iops_ref = hpu_asm::IOp::iter().collect::<Vec<_>>();
        let iop_parser = hpu_asm::Parser::new(iops_ref);

        // Allocate on-board memory emulation
        let hbm_bank: [HbmBank; HBM_BANK_NB] = from_fn(HbmBank::new);

        // Allocate inner regfile and lock abstraction
        let regfile = (0..params.isc_sim_params.register)
            .map(|_| HpuLweCiphertextOwned::new(0, params.rtl_params.clone()))
            .collect::<Vec<_>>();

        // Allocate Ucore Fw translation
        let ucore = UCore::new(config.board.clone());

        // Allocate InstructionScheduler
        // This module is also in charge of performances estimation
        let isc = isc::Scheduler::new(params.isc_sim_params.clone());
        Self {
            config,
            params,
            options,
            ipc,
            regmap,
            hbm_bank,
            regfile,
            pc: 0,
            ucore,
            isc,
            workq_stream: Vec::new(),
            iop_parser,
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
                                let word_b = word.to_be_bytes();
                                self.workq_stream.extend_from_slice(&word_b);
                                match self
                                    .iop_parser
                                    .from_be_bytes::<hpu_asm::FmtIOp>(self.workq_stream.as_slice())
                                {
                                    Ok(iop) => {
                                        // Iop properly parsed, consume the stream
                                        self.workq_stream.clear();
                                        self.iop_req.push_back(iop);
                                    }
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
                            self.params.rtl_params.pbs_params.clone(),
                        ));
                    }
                }
            }

            // Flush memory requests
            while let Some(req) = self.ipc.memory_req() {
                match req {
                    MemoryReq::Allocate { hbm_pc, size_b } => {
                        let addr = self.hbm_bank[hbm_pc].alloc(size_b);
                        self.ipc.memory_ack(MemoryAck::Allocate { addr });
                    }
                    MemoryReq::Sync {
                        hbm_pc,
                        addr,
                        mode,
                        data,
                    } => match mode {
                        SyncMode::Host2Device => {
                            let sw_data = data.expect("No data received on Host2Device sync");
                            self.hbm_bank[hbm_pc]
                                .get_mut_chunk(addr)
                                .ipc_update(sw_data);

                            // Generate ack
                            self.ipc.memory_ack(MemoryAck::Sync { data: None });
                        }
                        SyncMode::Device2Host => {
                            assert!(data.is_none(), "Received data on Device2Host sync");

                            // Read data
                            let hw_data = self.hbm_bank[hbm_pc].get_chunk(addr).ipc_wrap();

                            // Generate ack
                            self.ipc.memory_ack(MemoryAck::Sync {
                                data: Some(hw_data),
                            });
                        }
                    },
                    MemoryReq::Release { hbm_pc, addr } => {
                        self.hbm_bank[hbm_pc].rm_chunk(addr);
                        self.ipc.memory_ack(MemoryAck::Release);
                    }
                }
            }

            // Issue IOp requests to isc
            while let Some(iop) = self.iop_req.pop_front() {
                let (dops, dops_patched) = self.ucore.translate(self.hbm_bank.as_slice(), &iop);

                // Write required input material if needed
                if let Some(dump_path) = self.options.dump_out.as_ref() {
                    let iop_hex = iop.bin_encode_le().unwrap();
                    let opcode = iop_hex.last().unwrap();

                    // Generate IOp file
                    let asm_p = format!("{dump_path}/iop/iop_{}.asm", self.iop_nb);
                    hpu_asm::write_asm("", &[iop.clone()], &asm_p, hpu_asm::ARG_MIN_WIDTH).unwrap();
                    let hex_p = format!("{dump_path}/iop/iop_{}.hex", self.iop_nb);
                    hpu_asm::write_hex("", &[iop.clone()], &hex_p).unwrap();
                    self.iop_nb += 1;

                    // Generate DOps file
                    let iop_as_header = format!("# {}", iop.asm_encode(0));
                    let asm_p = format!("{dump_path}/dop/dop_{opcode:x}.asm");
                    hpu_asm::write_asm(&iop_as_header, &dops, &asm_p, hpu_asm::ARG_MIN_WIDTH)
                        .unwrap();
                    let hex_p = format!("{dump_path}/dop/dop_{opcode:x}.hex");
                    hpu_asm::write_hex(&iop_as_header, &dops, &hex_p).unwrap();
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
    fn exec(&mut self, dop: &hpu_asm::DOp) {
        tracing::debug!("Simulate execution of DOp: {dop:?}[@{}]", self.pc);

        // Read operands
        match dop {
            hpu_asm::DOp::LD(op_impl) => {
                let dst = &mut self.regfile[op_impl.dst];
                let hpu_asm::MemSlot { bid, cid_ofst, .. } = op_impl.src;

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
                    .map(|(id, pc)| {
                        let bid_ofst = {
                            let (msb, lsb) = self.regmap.addr_offset().ldst_bid[bid][id];
                            ((msb as u64) << 32) + lsb as u64
                        };
                        self.hbm_bank[*pc].get_chunk(bid_ofst + ct_ofst as u64)
                    })
                    .collect::<Vec<_>>();

                let hw_slice = dst.as_mut_view().into_container();
                std::iter::zip(hw_slice, ct_chunk).for_each(|(hpu, hbm)| {
                    // NB: hbm chunk are extended to enforce page align buffer
                    // -> To prevent error during copy, with shrink the hbm buffer to the
                    // real   size before-hand
                    let size_b = std::mem::size_of_val(hpu);
                    let hbm_u64 = bytemuck::cast_slice::<u8, u64>(&hbm.data.as_slice()[0..size_b]);
                    hpu.clone_from_slice(hbm_u64);
                });
            }
            hpu_asm::DOp::TLDA(_) | hpu_asm::DOp::TLDB(_) | hpu_asm::DOp::TLDH(_) => panic!(
                "Templated operation mustn't reach the Hpu execution
                unit. Check ucore translation"
            ),

            hpu_asm::DOp::ST(op_impl) => {
                let src = &self.regfile[op_impl.src];
                let hpu_asm::MemSlot { bid, cid_ofst, .. } = op_impl.dst;

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
                        let bid_ofst = {
                            let (msb, lsb) = self.regmap.addr_offset().ldst_bid[bid][id];
                            ((msb as u64) << 32) + lsb as u64
                        };
                        let ct_chunk = self.hbm_bank[self.config.board.ct_pc[id]]
                            .get_mut_chunk(bid_ofst + ct_ofst as u64);

                        // NB: hbm chunk are extended to enforce page align buffer
                        // -> Shrinked it to slice size to prevent error during copy
                        let size_b = std::mem::size_of_val(hpu);

                        let ct_chunk_u64 = bytemuck::cast_slice_mut::<u8, u64>(
                            &mut ct_chunk.data.as_mut_slice()[0..size_b],
                        );
                        ct_chunk_u64.copy_from_slice(hpu);
                    });
            }
            hpu_asm::DOp::TSTD(_) | hpu_asm::DOp::TSTH(_) => panic!(
                "Templated operation mustn't reach the Hpu execution
                unit. Check ucore translation"
            ),

            hpu_asm::DOp::ADD(op_impl) => {
                // NB: The first src is used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.src.0);
                let cpu_s1 = self.reg2cpu(op_impl.src.1);
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(op_impl.dst, cpu_s0.as_view());
            }
            hpu_asm::DOp::SUB(op_impl) => {
                // NB: The first src is used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.src.0);
                let cpu_s1 = self.reg2cpu(op_impl.src.1);
                lwe_ciphertext_sub_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(op_impl.dst, cpu_s0.as_view());
            }
            hpu_asm::DOp::MAC(op_impl) => {
                // NB: Srcs are used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.src.0);
                let cpu_s1 = self.reg2cpu(op_impl.src.1);

                lwe_ciphertext_cleartext_mul_assign(
                    &mut cpu_s0,
                    Cleartext(op_impl.mul_factor as u64),
                );
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);

                self.cpu2reg(op_impl.dst, cpu_s0.as_view());
            }
            hpu_asm::DOp::ADDS(op_impl) => {
                // NB: The first src is used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.src);
                let msg_encoded =
                    op_impl.msg_cst as u64 * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.dst, cpu_s0.as_view());
            }
            hpu_asm::DOp::SUBS(op_impl) => {
                // NB: The first src is used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.src);
                let msg_encoded =
                    op_impl.msg_cst as u64 * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_sub_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.dst, cpu_s0.as_view());
            }
            hpu_asm::DOp::SSUB(op_impl) => {
                // NB: The first src is used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.src);
                lwe_ciphertext_opposite_assign(&mut cpu_s0);
                let msg_encoded =
                    op_impl.msg_cst as u64 * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.dst, cpu_s0.as_view());
            }
            hpu_asm::DOp::MULS(op_impl) => {
                // NB: The first src is used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.src);
                lwe_ciphertext_cleartext_mul_assign(&mut cpu_s0, Cleartext(op_impl.msg_cst as u64));
                self.cpu2reg(op_impl.dst, cpu_s0.as_view());
            }
            hpu_asm::DOp::PBS(op_impl) => self.apply_pbs2reg(op_impl.dst, op_impl.src, op_impl.lut),
            hpu_asm::DOp::PBS_F(op_impl) => {
                self.apply_pbs2reg(op_impl.dst, op_impl.src, op_impl.lut)
            }
            hpu_asm::DOp::SYNC(_) => {
                // Push ack in stream
                let iop = self
                    .iop_pdg
                    .pop_front()
                    .expect("SYNC received but no pending IOp to acknowledge");
                // Bytes are in little-endian but written from first to last line
                // To keep correct endianness -> reverse the chunked vector
                let bytes = iop.bin_encode_le().unwrap();
                for bytes_chunks in bytes.chunks(std::mem::size_of::<u32>()).rev().take(1) {
                    let word_b = bytes_chunks.try_into().expect("Invalid slice length");
                    let word_u32 = u32::from_le_bytes(word_b);
                    self.regmap.ack_pdg(word_u32);
                }

                // Generate executed DOp order
                #[cfg(feature = "isc-order-check")]
                if let Some(dump_path) = self.options.dump_out.as_ref() {
                    let iop_hex = iop.bin_encode_le().unwrap();
                    let iop_opcode = iop_hex.last().unwrap();
                    let iop_as_header = format!("# {}", iop.asm_encode(0));

                    let asm_p = format!("{dump_path}/dop/dop_{iop_opcode:x}_executed.asm");
                    hpu_asm::write_asm(
                        &iop_as_header,
                        &self.dops_exec_order,
                        &asm_p,
                        hpu_asm::ARG_MIN_WIDTH,
                    )
                    .unwrap();
                    let hex_p = format!("{dump_path}/iop/iop_{iop_opcode:x}_executed.hex");
                    hpu_asm::write_hex("", self.dops_exec_order.as_slice(), &hex_p).unwrap();
                }

                // Generate report
                let time_rpt = self.isc.time_report();
                let dop_rpt = self.isc.dop_report();
                tracing::info!("Report for IOp: {}", iop.asm_encode(8));
                tracing::info!("{time_rpt:?}");
                tracing::info!("{dop_rpt}");

                if let Some(mut rpt_file) = self.options.report_file(&iop.clone().into()) {
                    writeln!(rpt_file, "Report for IOp: {}", iop.asm_encode(8)).unwrap();
                    writeln!(rpt_file, "{time_rpt:?}").unwrap();
                    writeln!(rpt_file, "{dop_rpt}").unwrap();
                }

                let trace = self.isc.reset_trace();
                trace.iter().for_each(|pt| tracing::trace!("{pt}"));
                if let Some(mut trace_file) = self.options.report_trace(&iop.into()) {
                    trace
                        .into_iter()
                        .for_each(|pt| writeln!(trace_file, "{pt}").unwrap());
                }
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
    fn apply_pbs2reg(&mut self, dst_rid: usize, src_rid: usize, lut: hpu_asm::Pbs) {
        let mut cpu_reg = self.reg2cpu(src_rid);

        // Generate Lut
        let hpu_lut = create_hpu_lookuptable(self.params.rtl_params.clone(), lut);
        let mut tfhe_lut = hpu_lut.as_view().into();

        // Get keys and computation buffer
        let (ksk, ref mut bfr_after_ks, bsk) = self.get_server_key();

        // TODO add a check on trivialness for fast simulation ?
        // TODO assert ordering
        keyswitch_lwe_ciphertext(ksk, &cpu_reg, bfr_after_ks);
        blind_rotate_ntt64_bnf_assign(bfr_after_ks, &mut tfhe_lut, &bsk);
        extract_lwe_sample_from_glwe_ciphertext(&tfhe_lut, &mut cpu_reg, MonomialDegree(0));
        self.cpu2reg(dst_rid, cpu_reg.as_view());
    }

    // NB: to prevent issues with borrow checker we have to clone the value from
    // the regfile. A clone is also required for conversion
    // Thus, directly cast value in Cpu version to prevent extra clone
    /// Extract a cpu value from register file
    fn reg2cpu(&self, reg_id: usize) -> LweCiphertextOwned<u64> {
        let reg = self.regfile[reg_id].as_view();
        LweCiphertextOwned::from(reg)
    }

    /// Insert a cpu value into the register file
    fn cpu2reg(&mut self, reg_id: usize, cpu: LweCiphertextView<u64>) {
        let hpu = HpuLweCiphertextOwned::<u64>::from_with(cpu, self.params.rtl_params.clone());
        std::iter::zip(
            self.regfile[reg_id].as_mut_view().into_container(),
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
        &LweKeyswitchKeyOwned<u64>,
        &mut LweCiphertextOwned<u64>,
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
                    .for_each(|(id, (hpu, pc))| {
                        let bank = &self.hbm_bank[*pc];
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
                    .for_each(|(id, (hpu, pc))| {
                        let bank = &self.hbm_bank[*pc];
                        let ofst = {
                            let (msb, lsb) = self.regmap.addr_offset().ksk[id];
                            ((msb as usize) << 32) + lsb as usize
                        };
                        bank.read_across_chunk(ofst, hpu);
                    });
                ksk
            };
            // Allocate Pbs intermediate buffer
            let pbs_p = ClassicPBSParameters::from(self.params.rtl_params.clone());
            let bfr_after_ks = LweCiphertext::new(
                0,
                pbs_p.lwe_dimension.to_lwe_size(),
                pbs_p.ciphertext_modulus,
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
            let regf = match op {
                hpu_asm::DOp::LD(op_impl) => self.regfile[op_impl.dst].as_view(),

                hpu_asm::DOp::TLDA(_) | hpu_asm::DOp::TLDB(_) | hpu_asm::DOp::TLDH(_) => panic!(
                    "Templated operation mustn't reach the Hpu execution
                unit. Check ucore translation"
                ),
                hpu_asm::DOp::ST(op_impl) => self.regfile[op_impl.src].as_view(),
                hpu_asm::DOp::TSTD(_) | hpu_asm::DOp::TSTH(_) => panic!(
                    "Templated operation mustn't reach the Hpu execution
                unit. Check ucore translation"
                ),

                hpu_asm::DOp::ADDS(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::SUBS(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::SSUB(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::MULS(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::ADD(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::SUB(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::MAC(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::PBS(op_impl) => self.regfile[op_impl.dst].as_view(),
                hpu_asm::DOp::PBS_F(op_impl) => self.regfile[op_impl.dst].as_view(),
                _ => return,
            };

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
                let file_path = format!("{base_path}_{:0>1x}.hex", i);
                let mut wr_f = MockupOptions::open_wr_file(&file_path);

                writeln!(&mut wr_f, "# LweCiphertext slice #{}", i).unwrap();
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
            let raw_err = if let Some(dst) = exec_dop.dst().get(0) {
                dop.src()
                    .iter()
                    .map(|src| src == dst)
                    .fold(false, |acc, cur| acc || cur)
            } else {
                false
            };

            // Write afer read check
            // Mainly associated register is read before the expected write
            let war_err = if let Some(dop_dst) = dop.dst().get(0) {
                exec_dop
                    .src()
                    .iter()
                    .map(|src| src == dop_dst)
                    .fold(false, |acc, cur| acc || cur)
            } else {
                false
            };

            if raw_err {
                tracing::warn!(
                    "RAW_ERR {} -> {}",
                    exec_dop.asm_encode(0),
                    dop.asm_encode(0)
                );
            }
            if war_err {
                tracing::warn!(
                    "WAR_ERR {} -> {}",
                    exec_dop.asm_encode(0),
                    dop.asm_encode(0)
                );
            }
        }

        // Remove exec_dop from the list
        self.dops_check_order.remove(exec_pos);
    }
}
