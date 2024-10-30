use std::array::from_fn;
use std::collections::VecDeque;
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
use tfhe::shortint::ciphertext::MaxDegree;
use tfhe::shortint::parameters::{Degree, NoiseLevel};
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;

mod ipc;
use ipc::Ipc;

mod mockup_params;
pub use mockup_params::MockupParameters;

mod modules;
use modules::{HbmBank, InstructionScheduler, RegisterEvent, RegisterMap, UCore, HBM_BANK_NB};

use hpu_asm::{AsmBin, PbsLut};
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

    /// UCore model
    ucore: UCore,

    /// Instruction scheduler
    isc: InstructionScheduler,

    // WorkAckq interface -----------------------------------------------------
    workq_stream: Vec<u8>,
    /// Parser for workq_stream
    iop_parser: hpu_asm::Parser<hpu_asm::IOp>,
    /// Pending Iop
    iop_pdg: VecDeque<hpu_asm::IOp>,

    /// Tfhe server keys
    /// Read from memory after bsk_avail/ksk_avail register are set
    /// Conversion from Hpu->Cpu is costly. Thuse store it in the object to prevent extra
    /// computation
    sks: Option<ServerKey>,
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
        let isc = InstructionScheduler::new(params.isc_sim_params.clone());

        Self {
            config,
            params,
            ipc,
            regmap,
            hbm_bank,
            regfile,
            ucore,
            isc,
            workq_stream: Vec::new(),
            iop_parser,
            iop_pdg: VecDeque::new(),
            sks: None,
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
                                        self.iop_pdg.push_back(iop);
                                    }
                                    Err(_) => {
                                        // not enough data to match
                                    }
                                }
                            }
                        }
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

            // Simulate execution of an IOp if any
            while let Some(iop) = self.iop_pdg.front() {
                let dops = self.ucore.translate(self.hbm_bank.as_slice(), iop);
                let dops_exec = self.isc.schedule(dops);
                for dop in dops_exec {
                    self.exec(dop);
                }
            }
        }
    }
}

impl HpuSim {
    fn exec(&mut self, dop: hpu_asm::DOp) {
        tracing::debug!("Simulate execution of DOp: {dop:?}");
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
                std::iter::zip(hw_slice.into_iter(), ct_chunk.into_iter()).for_each(
                    |(hpu, hbm)| {
                        // NB: hbm chunk are extended to enforce page align buffer
                        // -> To prevent error during copy, with shrink the hbm buffer to the
                        // real   size before-hand
                        let size_b = std::mem::size_of_val(hpu);
                        let hbm_u64 =
                            bytemuck::cast_slice::<u8, u64>(&hbm.data.as_slice()[0..size_b]);
                        hpu.clone_from_slice(hbm_u64);
                    },
                );
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
            }
        }
    }

    /// Compute dst_rid <- Pbs(src_rid, lut)
    /// Use a function to prevent code duplication in PBS/PBS_F implementation
    /// NB: Current Pbs lookup function arn't reverted from Hbm memory
    /// TODO: Read PbsLut from Hbm instead of online generation based on Pbs Id
    fn apply_pbs2reg(&mut self, dst_rid: usize, src_rid: usize, lut: hpu_asm::Pbs) {
        let cpu_reg = self.reg2cpu(src_rid);

        let digit_p = hpu_asm::DigitParameters {
            msg_w: self.params.rtl_params.pbs_params.message_width,
            carry_w: self.params.rtl_params.pbs_params.carry_width,
        };
        let sks = self.get_server_key();

        let mut cpu_ct = Ciphertext::new(
            cpu_reg,
            Degree::new(sks.max_degree.get()),
            NoiseLevel::MAX,
            sks.message_modulus,
            sks.carry_modulus,
            sks.pbs_order,
        );

        let tfhe_lut = sks.generate_lookup_table(|x| lut.eval(&digit_p, x as usize) as u64);
        sks.apply_lookup_table_assign(&mut cpu_ct, &tfhe_lut);

        // lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);
        self.cpu2reg(dst_rid, cpu_ct.ct.as_view());
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
    fn get_server_key(&mut self) -> &ServerKey {
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

            // Construct Shortint server_key
            let cpu_bsk = NttLweBootstrapKey::from(hpu_bsk.as_view());
            let cpu_ksk = LweKeyswitchKey::from(hpu_ksk.as_view());

            let sks = {
                let pbs_p = ClassicPBSParameters::from(self.params.rtl_params.clone());
                ServerKey {
                    key_switching_key: cpu_ksk,
                    bootstrapping_key: ShortintBootstrappingKey::ClassicNtt(cpu_bsk),
                    message_modulus: pbs_p.message_modulus,
                    carry_modulus: pbs_p.carry_modulus,
                    max_degree: MaxDegree::from_msg_carry_modulus(
                        pbs_p.message_modulus,
                        pbs_p.carry_modulus,
                    ),
                    max_noise_level: MaxNoiseLevel::from_msg_carry_modulus(
                        pbs_p.message_modulus,
                        pbs_p.carry_modulus,
                    ),
                    ciphertext_modulus: pbs_p.ciphertext_modulus,
                    pbs_order: pbs_p.encryption_key_choice.into(),
                    pbs_mode: pbs_p.encryption_key_choice.into(),
                }
            };
            self.sks = Some(sks);
        }
        self.sks.as_ref().unwrap()
    }
}
