use hpu_asm::{DigitParameters, PbsLut};
use lwe_ciphertext::HpuLweCiphertext;
use lwe_keyswitch_key::HpuLweKeyswitchKey;
use std::array::from_fn;
use std::sync::mpsc;
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
use tfhe::core_crypto::hpu::from_with::{FromWith, IntoWith};
use tfhe::shortint::backward_compatibility::parameters::ClassicPBSParametersVersions;
use tfhe::shortint::ciphertext::MaxDegree;
use tfhe::shortint::parameters::{Degree, NoiseLevel};
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;

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

                    // NB: hbm chunk are extended to enforce page align buffer
                    // -> To prevent error during copy, with shrink the hbm buffer to the real
                    //   size before-hand
                    let shrinked_size_b =
                        (dst.as_ref().len().div_ceil(ct_chunk.len())) * std::mem::size_of::<u64>();
                    let ct_slice_u64 = ct_chunk
                        .iter()
                        .map(|chunk| {
                            bytemuck::cast_slice::<u8, u64>(
                                &chunk.data.as_slice()[0..shrinked_size_b],
                            )
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

                        // NB: hbm chunk are extended to enforce page align buffer
                        // -> Shrinked it to slice size to prevent error during copy
                        let ct_chunk_u64 = bytemuck::cast_slice_mut::<u8, u64>(
                            &mut ct_chunk.data.as_mut_slice()
                                [0..(slice.len() * std::mem::size_of::<u64>())],
                        );
                        ct_chunk_u64.copy_from_slice(slice.as_slice());
                    }
                }
                asm::DOp::TSTD(_) | asm::DOp::TSTH(_) => panic!(
                    "Templated operation mustn't reach the Hpu execution
                unit. Check ucore translation"
                ),

                asm::DOp::ADD(op_impl) => {
                    // NB: The first src is used as destination to prevent useless allocation
                    let mut cpu_s0 = self.reg2cpu(op_impl.src.0);
                    let cpu_s1 = self.reg2cpu(op_impl.src.1);
                    lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);
                    self.cpu2reg(op_impl.dst, cpu_s0.as_view());
                }
                asm::DOp::SUB(op_impl) => {
                    // NB: The first src is used as destination to prevent useless allocation
                    let mut cpu_s0 = self.reg2cpu(op_impl.src.0);
                    let cpu_s1 = self.reg2cpu(op_impl.src.1);
                    lwe_ciphertext_sub_assign(&mut cpu_s0, &cpu_s1);
                    self.cpu2reg(op_impl.dst, cpu_s0.as_view());
                }
                asm::DOp::MAC(op_impl) => {
                    // NB: Srcs are used as destination to prevent useless allocation
                    let mut cpu_s0 = self.reg2cpu(op_impl.src.0);
                    let mut cpu_s1 = self.reg2cpu(op_impl.src.1);

                    lwe_ciphertext_cleartext_mul_assign(
                        &mut cpu_s1,
                        Cleartext(op_impl.mul_factor as u64),
                    );
                    lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);

                    self.cpu2reg(op_impl.dst, cpu_s0.as_view());
                }
                asm::DOp::ADDS(op_impl) => {
                    // NB: The first src is used as destination to prevent useless allocation
                    let mut cpu_s0 = self.reg2cpu(op_impl.src);
                    let msg_encoded =
                        op_impl.msg_cst as u64 * self.params.rtl_params.pbs_params.delta();
                    lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                    self.cpu2reg(op_impl.dst, cpu_s0.as_view());
                }
                asm::DOp::SUBS(op_impl) => {
                    // NB: The first src is used as destination to prevent useless allocation
                    let mut cpu_s0 = self.reg2cpu(op_impl.src);
                    let msg_encoded =
                        op_impl.msg_cst as u64 * self.params.rtl_params.pbs_params.delta();
                    lwe_ciphertext_plaintext_sub_assign(&mut cpu_s0, Plaintext(msg_encoded));
                    self.cpu2reg(op_impl.dst, cpu_s0.as_view());
                }
                asm::DOp::SSUB(op_impl) => {
                    // NB: The first src is used as destination to prevent useless allocation
                    let mut cpu_s0 = self.reg2cpu(op_impl.src);
                    lwe_ciphertext_opposite_assign(&mut cpu_s0);
                    let msg_encoded =
                        op_impl.msg_cst as u64 * self.params.rtl_params.pbs_params.delta();
                    lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                    self.cpu2reg(op_impl.dst, cpu_s0.as_view());
                }
                asm::DOp::MULS(op_impl) => {
                    // NB: The first src is used as destination to prevent useless allocation
                    let mut cpu_s0 = self.reg2cpu(op_impl.src);
                    lwe_ciphertext_cleartext_mul_assign(
                        &mut cpu_s0,
                        Cleartext(op_impl.msg_cst as u64),
                    );
                    self.cpu2reg(op_impl.dst, cpu_s0.as_view());
                }
                asm::DOp::PBS(op_impl) => self.apply_pbs2reg(op_impl.dst, op_impl.src, op_impl.lut),
                asm::DOp::PBS_F(op_impl) => {
                    self.apply_pbs2reg(op_impl.dst, op_impl.src, op_impl.lut)
                }
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
            }
        }
    }

    /// Compute dst_rid <- Pbs(src_rid, lut)
    /// Use a function to prevent code duplication in PBS/PBS_F implementation
    fn apply_pbs2reg(&mut self, dst_rid: usize, src_rid: usize, lut: hpu_asm::Pbs) {
        let cpu_reg = self.reg2cpu(src_rid);

        let digit_p = DigitParameters {
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
        self.regfile[reg_id].as_mut().copy_from_slice(hpu.as_ref());
    }

    /// Get the inner server key used for computation
    /// Check the register state and extract sks from memory if needed
    fn get_server_key(&mut self) -> &ServerKey {
        if let Some(sks) = self.sks.as_ref() {
            sks
        } else {
            // TODO check register states
            // Extract HpuBsk /HpuKsk from hbm
            let hpu_bsk = HpuLweBootstrapKeyOwned::new(0, self.params.rtl_params.clone());
            let hpu_ksk = HpuLweKeyswitchKey::new(0, self.params.rtl_params.clone());

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
                    ciphertext_modulus: todo!(),
                    pbs_order: pbs_p.encryption_key_choice.into(),
                    pbs_mode: pbs_p.encryption_key_choice.into(),
                }
            };
            self.sks = Some(sks);
            self.sks.as_ref().unwrap()
        }
    }
}
