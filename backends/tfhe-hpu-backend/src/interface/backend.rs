/// Implement inner-view of Hpu backend
use super::*;
use crate::asm::PbsLut;
use crate::entities::*;
use crate::fw::{Fw, FwParameters};
use crate::{asm, ffi};
use rtl::FromRtl;

use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{mpsc, Arc, Mutex};

use tracing::{debug, info, trace};

pub struct HpuBackend {
    // Low-level hardware handling
    hpu_hw: ffi::HpuHw,
    regmap: hw_regmap::FlatRegmap,

    // Extracted parameters
    pub(crate) params: HpuParameters,
    // Prevent to parse regmap at each polling iteration
    workq_addr: u64,
    ackq_addr: u64,

    // Key memory
    bsk_key: memory::HugeMemory<u64>,
    ksk_key: memory::HugeMemory<u64>,

    // Lut and Fw memory
    lut_mem: memory::HugeMemory<u64>,
    fw_mem: memory::HugeMemory<u32>,

    // Memory management
    // Board memory is abstract as a bunch of ciphertext slot
    // Used a dedicaed manager to handle lifetime of used slot
    pub(crate) ct_mem: memory::CiphertextMemory,

    // Work management
    // Keep track of issued IOp and associated variables
    cmd_q: VecDeque<cmd::HpuCmd>,
    cmd_rx: mpsc::Receiver<cmd::HpuCmd>,
    pub(crate) cmd_tx: mpsc::Sender<cmd::HpuCmd>,
}

pub struct HpuBackendLock(Mutex<HpuBackend>);

impl HpuBackendLock {
    pub fn new(inner: HpuBackend) -> Self {
        Self(Mutex::new(inner))
    }
}
impl std::ops::Deref for HpuBackendLock {
    type Target = Mutex<HpuBackend>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
unsafe impl Send for HpuBackendLock {}
unsafe impl Sync for HpuBackendLock {}

#[derive(Clone)]
pub struct HpuBackendWrapped(Arc<HpuBackendLock>);

impl HpuBackendWrapped {
    #[allow(unused)]
    pub fn new(inner: HpuBackend) -> Self {
        Self(Arc::new(HpuBackendLock::new(inner)))
    }
    pub fn new_wrapped(config: &config::HpuConfig) -> Self {
        Self(Arc::new(HpuBackendLock::new(HpuBackend::new(config))))
    }
}
impl std::ops::Deref for HpuBackendWrapped {
    type Target = Arc<HpuBackendLock>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
unsafe impl Send for HpuBackendWrapped {}
unsafe impl Sync for HpuBackendWrapped {}

/// Handle HpuBackend construction and initialisation
impl HpuBackend {
    pub fn new(config: &config::HpuConfig) -> Self {
        let mut hpu_hw = ffi::HpuHw::new_hpu_hw(&config.fpga.ffi);
        let regmap = hw_regmap::FlatRegmap::from_file(&config.fpga.regmap);

        let params = HpuParameters::from_rtl(&mut hpu_hw, &regmap);
        // Flush ack_q
        // Ensure that no residue from previous execution were stall in the pipe
        let ackq_addr = (*regmap
            .register()
            .get("WorkAck::ackq")
            .expect("Unknow register, check regmap definition")
            .offset()) as u64;
        loop {
            let ack_code = hpu_hw.read_reg(ackq_addr);
            if ack_code == ACKQ_EMPTY {
                break;
            }
        }

        // Apply Rtl configuration
        // Bpip use
        hpu_hw.write_reg(
            *regmap
                .register()
                .get("Bpip::use")
                .expect("Unknow register, check regmap definition")
                .offset() as u64,
            config.rtl.bpip_used as u32,
        );

        // Bpip timeout
        hpu_hw.write_reg(
            *regmap
                .register()
                .get("Bpip::timeout")
                .expect("Unknow register, check regmap definition")
                .offset() as u64,
            config.rtl.bpip_timeout,
        );

        info!("{params:?}");
        debug!(
            "Isc registers {:?}",
            rtl::runtime::InfoIsc::from_rtl(&mut hpu_hw, &regmap)
        );
        debug!(
            "PeMem registers {:?}",
            rtl::runtime::InfoPeMem::from_rtl(&mut hpu_hw, &regmap)
        );
        debug!(
            "PeAlu registers {:?}",
            rtl::runtime::InfoPeAlu::from_rtl(&mut hpu_hw, &regmap)
        );
        debug!(
            "PePbs registers {:?}",
            rtl::runtime::InfoPePbs::from_rtl(&mut hpu_hw, &regmap)
        );

        let workq_addr = (*regmap
            .register()
            .get("WorkAck::workq")
            .expect("Unknow register, check regmap definition")
            .offset()) as u64;
        let ackq_addr = (*regmap
            .register()
            .get("WorkAck::ackq")
            .expect("Unknow register, check regmap definition")
            .offset()) as u64;

        // Allocate memory for Bsk
        let bsk_props = {
            let bsk_pc = &params.pc_params.bsk_pc;
            let bsk_size = hpu_lwe_bootstrap_key_size(&params);

            let cut_coefs = bsk_size.div_ceil(*bsk_pc);
            let hbm_cut = config
                .board
                .bsk_pc
                .clone()
                .into_iter()
                .take(*bsk_pc)
                .collect::<Vec<_>>();
            memory::HugeMemoryProperties { hbm_cut, cut_coefs }
        };
        let bsk_key = memory::HugeMemory::alloc(&mut hpu_hw, bsk_props);

        // Allocate memory for Ksk
        let ksk_props = {
            let ksk_pc = &params.pc_params.ksk_pc;
            let ksk_size = hpu_lwe_keyswitch_key_size(&params);

            let cut_coefs = ksk_size.div_ceil(*ksk_pc);
            let hbm_cut = config
                .board
                .ksk_pc
                .clone()
                .into_iter()
                .take(*ksk_pc)
                .collect::<Vec<_>>();

            memory::HugeMemoryProperties { hbm_cut, cut_coefs }
        };
        let ksk_key = memory::HugeMemory::alloc(&mut hpu_hw, ksk_props);

        // Allocate memory for GlweLut
        let lut_props = memory::HugeMemoryProperties {
            hbm_cut: vec![config.board.lut_pc],
            cut_coefs: config.board.lut_mem * params.pbs_params.polynomial_size,
        };
        let lut_mem = memory::HugeMemory::alloc(&mut hpu_hw, lut_props);

        // Allocate memory for Fw translation table
        let fw_props = memory::HugeMemoryProperties {
            hbm_cut: vec![config.board.fw_pc],
            cut_coefs: config.board.fw_size, // NB: here `size` is used as raw size (!= slot nb)
        };
        let fw_mem = memory::HugeMemory::alloc(&mut hpu_hw, fw_props);

        // Allocate memory pool for Ct
        // NB: Compute size of each cut.
        // Cut are 4k aligned -> One cut match with page boundary but the second one (with body
        // extra coefs) crossed it => Use an extra page in both to have same addr incr (and
        // match Rtl behavior)
        let cut_size_b = memory::page_align(
            hpu_big_lwe_ciphertext_size(&params).div_ceil(params.pc_params.pem_pc)
                * std::mem::size_of::<u64>(),
        );
        let ct_props = memory::CiphertextMemoryProperties {
            hbm_cut: config.board.ct_pc.clone(),
            // NB: Xrt only support page align memory allocation. Thus we round cut coefs to
            // match the next 4k page boundary
            cut_size_b,
            slot_nb: config.board.ct_mem,
        };
        debug!("Ct_mem properties -> {:?}", ct_props);
        let ct_mem = memory::CiphertextMemory::alloc(&mut hpu_hw, &regmap, &ct_props);

        // Construct channel for mt API
        // Keep track of the sender for clone it later on
        let (cmd_tx, cmd_rx) = mpsc::channel();

        Self {
            hpu_hw,
            regmap,
            params,
            workq_addr,
            ackq_addr,
            bsk_key,
            ksk_key,
            lut_mem,
            fw_mem,
            ct_mem,
            cmd_q: VecDeque::new(),
            cmd_rx,
            cmd_tx,
        }
    }
}

/// Bootstrapping Key handling
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuBackend {
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub fn bsk_unset(&mut self) {
        let Self {
            ref mut hpu_hw,
            regmap,
            ..
        } = self;

        // Extract register from regmap
        let bsk_avail = regmap
            .register()
            .get("Keys_Bsk::avail")
            .expect("Unknow register, check regmap definition");
        let bsk_reset = regmap
            .register()
            .get("Keys_Bsk::reset")
            .expect("Unknow register, check regmap definition");

        // Cache reset procedure
        // 1. Wait for end of batch process (WARN: Not handled by this function)
        // 2. Set bit reset_cache = 1
        // 3. Set bit key_avail = 0
        // 4. Wait for reset_cache_done = 1
        // 5. Set bit reset_cache = 0, set reset_cache_done = 0
        // -> Design is ready to receive a new key
        hpu_hw.write_reg(*bsk_reset.offset() as u64, 0x1);
        hpu_hw.write_reg(*bsk_avail.offset() as u64, 0x0);
        loop {
            let done = {
                let val = hpu_hw.read_reg(*bsk_reset.offset() as u64);
                let fields = bsk_reset.as_field(val);

                *fields.get("done").expect("Unknow field") != 0
            };
            if done {
                break;
            }
        }

        hpu_hw.write_reg(*bsk_reset.offset() as u64, 0x0);
    }

    #[tracing::instrument(level = "debug", skip(self, bsk), ret)]
    pub fn bsk_set(&mut self, bsk: HpuLweBootstrapKeyOwned<u64>) {
        let Self {
            ref mut hpu_hw,
            regmap,
            params,
            bsk_key,
            ..
        } = self;

        // Extract register from regmap
        let bsk_avail = regmap
            .register()
            .get("Keys_Bsk::avail")
            .expect("Unknow register, check regmap definition");
        let bsk_addr_pc = (0..params.pc_params.bsk_pc)
            .map(|idx| {
                let lsb_name = format!("Keys_Bsk::addr_pc_pc{idx}_lsb");
                let msb_name = format!("Keys_Bsk::addr_pc_pc{idx}_msb");
                let lsb = regmap
                    .register()
                    .get(&lsb_name)
                    .expect("Unknow register, check regmap definition");
                let msb = regmap
                    .register()
                    .get(&msb_name)
                    .expect("Unknow register, check regmap definition");
                (lsb, msb)
            })
            .collect::<Vec<_>>();

        // Write key in associated buffer
        for (id, bsk_cut) in bsk.as_view().into_container().into_iter().enumerate() {
            bsk_key.write_cut_at(id, 0, bsk_cut);
            #[cfg(feature = "io-dump")]
            io_dump::dump(
                &bsk_cut,
                params,
                io_dump::DumpKind::Bsk,
                io_dump::DumpId::Key(id),
            );
        }

        // Write pc_addr in memory
        for (addr, (lsb, msb)) in std::iter::zip(bsk_key.cut_paddr().iter(), bsk_addr_pc.iter()) {
            hpu_hw.write_reg(
                *msb.offset() as u64,
                ((addr >> u32::BITS) & (u32::MAX) as u64) as u32,
            );
            hpu_hw.write_reg(*lsb.offset() as u64, (addr & (u32::MAX as u64)) as u32);
        }

        // Toggle avail bit
        hpu_hw.write_reg(*bsk_avail.offset() as u64, 0x1);
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub fn bsk_is_set(&self) -> bool {
        let Self { hpu_hw, regmap, .. } = self;

        // Extract register from regmap
        let bsk_avail = regmap
            .register()
            .get("Keys_Bsk::avail")
            .expect("Unknow register, check regmap definition");

        let val = hpu_hw.read_reg(*bsk_avail.offset() as u64);
        let fields = bsk_avail.as_field(val);

        *fields.get("avail").expect("Unknow field") != 0
    }
}

/// KeyswitchKey handling
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuBackend {
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub fn ksk_unset(&mut self) {
        let Self {
            ref mut hpu_hw,
            regmap,
            ..
        } = self;

        // Extract register from regmap
        let ksk_avail = regmap
            .register()
            .get("Keys_Ksk::avail")
            .expect("Unknow register, check regmap definition");
        let ksk_reset = regmap
            .register()
            .get("Keys_Ksk::reset")
            .expect("Unknow register, check regmap definition");

        // Cache reset procedure
        // 1. Wait for end of batch process (WARN: Not handled by this function)
        // 2. Set bit reset_cache = 1
        // 3. Set bit key_avail = 0
        // 4. Wait for reset_cache_done = 1
        // 5. Set bit reset_cache = 0, set reset_cache_done = 0
        // -> Design is ready to receive a new key
        hpu_hw.write_reg(*ksk_reset.offset() as u64, 0x1);
        hpu_hw.write_reg(*ksk_avail.offset() as u64, 0x0);
        loop {
            let done = {
                let val = hpu_hw.read_reg(*ksk_reset.offset() as u64);
                let fields = ksk_reset.as_field(val);

                *fields.get("done").expect("Unknow field") != 0
            };
            if done {
                break;
            }
        }

        hpu_hw.write_reg(*ksk_reset.offset() as u64, 0x0);
    }
    #[tracing::instrument(level = "debug", skip(self, ksk), ret)]
    pub fn ksk_set(&mut self, ksk: HpuLweKeyswitchKeyOwned<u64>) {
        let Self {
            ref mut hpu_hw,
            regmap,
            params,
            ksk_key,
            ..
        } = self;

        // Extract register from regmap
        let ksk_avail = regmap
            .register()
            .get("Keys_Ksk::avail")
            .expect("Unknow register, check regmap definition");
        let ksk_addr_pc = (0..params.pc_params.ksk_pc)
            .map(|idx| {
                let lsb_name = format!("Keys_Ksk::addr_pc_pc{idx}_lsb");
                let msb_name = format!("Keys_Ksk::addr_pc_pc{idx}_msb");
                let lsb = regmap
                    .register()
                    .get(&lsb_name)
                    .expect("Unknow register, check regmap definition");
                let msb = regmap
                    .register()
                    .get(&msb_name)
                    .expect("Unknow register, check regmap definition");
                (lsb, msb)
            })
            .collect::<Vec<_>>();

        // Write key in associated buffer
        for (id, ksk_cut) in ksk.as_view().into_container().into_iter().enumerate() {
            ksk_key.write_cut_at(id, 0, ksk_cut);
            #[cfg(feature = "io-dump")]
            io_dump::dump(
                &ksk_cut,
                params,
                io_dump::DumpKind::Ksk,
                io_dump::DumpId::Key(id),
            );
        }

        // Write pc_addr in memory
        for (addr, (lsb, msb)) in std::iter::zip(ksk_key.cut_paddr().iter(), ksk_addr_pc.iter()) {
            hpu_hw.write_reg(
                *msb.offset() as u64,
                ((addr >> u32::BITS) & (u32::MAX) as u64) as u32,
            );
            hpu_hw.write_reg(*lsb.offset() as u64, (addr & (u32::MAX as u64)) as u32);
        }

        // Toggle avail bit
        hpu_hw.write_reg(*ksk_avail.offset() as u64, 0x1);
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub fn ksk_is_set(&self) -> bool {
        let Self { hpu_hw, regmap, .. } = self;

        // Extract register from regmap
        let ksk_avail = regmap
            .register()
            .get("Keys_Ksk::avail")
            .expect("Unknow register, check regmap definition");

        let val = hpu_hw.read_reg(*ksk_avail.offset() as u64);
        let fields = ksk_avail.as_field(val);

        *fields.get("avail").expect("Unknow field") != 0
    }
}

/// Handle Glwe Lut initialisation
/// Lut and Fw are merged since
impl HpuBackend {
    #[tracing::instrument(level = "debug", skip(self, gen_lut), ret)]
    pub(crate) fn lut_init<F>(&mut self, gen_lut: F)
    where
        F: Fn(HpuParameters, asm::Pbs) -> HpuGlweLookuptableOwned<u64>,
    {
        let Self {
            ref mut hpu_hw,
            regmap,
            params,
            lut_mem,
            ..
        } = self;

        // Iterate over HwHpu::PbsLut
        // Construct them with associated parameters set
        // And upload them in memory
        for lut_impl in asm::Pbs::list_all() {
            let lut_gid = lut_impl.gid().0 as usize;

            // Write it in on-board memory
            // Lut are encoded as trivial ciphertext.
            // Thus to prevent useless memory xfer, only the Body polynomial is uploaded on Hw
            let hpu_lut = gen_lut(params.clone(), lut_impl);

            // NB: lut_mem are always on 1cut
            let ofst = lut_gid * params.pbs_params.polynomial_size;
            lut_mem.write_cut_at(0, ofst, hpu_lut.as_view().into_container());
            #[cfg(feature = "io-dump")]
            io_dump::dump(
                &hpu_lut.as_ref(),
                params,
                io_dump::DumpKind::Glwe,
                io_dump::DumpId::Lut(lut_gid),
            );
        }

        // Configure Hpu register accordingly
        // Extract register from regmap
        let reg_lsb = regmap
            .register()
            .get("PbsLut::addr_lsb")
            .expect("Unknow register, check regmap definition");
        let reg_msb = regmap
            .register()
            .get("PbsLut::addr_msb")
            .expect("Unknow register, check regmap definition");

        let lut_addr = lut_mem.cut_paddr()[0];
        hpu_hw.write_reg(
            *reg_msb.offset() as u64,
            ((lut_addr >> u32::BITS) & (u32::MAX) as u64) as u32,
        );
        hpu_hw.write_reg(
            *reg_lsb.offset() as u64,
            (lut_addr & (u32::MAX as u64)) as u32,
        );
    }
}

/// Handle Fw Lut and translation table init
impl HpuBackend {
    #[tracing::instrument(skip(self, config))]
    pub(crate) fn fw_init(&mut self, config: &config::HpuConfig) {
        // Create Asm architecture properties and Fw instanciation
        // TODO construct from real params
        let fw_arch_props = FwParameters {
            regs: self.params.regf_params.reg_nb,
            heap_size: config.board.heap_size,
            pbs_batch_w: config.firmware.pbs_batch_w,
            msg_w: 2,
            carry_w: 2,
            nu: 5,
            // TODO extend with multi-width support
            integer_w: config.firmware.integer_w[0],
        };

        let mut fw = crate::fw::fw_impl::ilp::Ilp::default();
        // Generate Fw for standard operation
        // -> All operation with an associated alias
        let mut id_fw = asm::iop::IOP_LIST
            .iter()
            .map(|iop| {
                let opcode = iop.opcode();
                let prog = fw.expand(&fw_arch_props, iop);
                (opcode.0 as usize, prog.tr_table())
            })
            .collect::<Vec<_>>();

        // Load custom IOp from file

        for (name, asm_file) in config.firmware.custom_iop.iter() {
            let iop = asm::AsmIOpcode::from_str(name).expect("Invalid Custom Iop name");
            let opcode = iop.opcode();
            let prog =
                asm::Program::<asm::DOp>::read_asm(asm_file).expect("Invalid custom_iop file");
            id_fw.push((opcode.0 as usize, prog.tr_table()));
        }

        // Sanity check
        let _sync_opcode = asm::dop::DOpSync::opcode();
        for (id, fw_bytes) in id_fw.iter() {
            // All IOp entry must be gte (MIN_IOP_SIZE-1)
            // NB fw_bytes contain size + DOps -> gte MIN_IOP_SIZE
            assert!(
                fw_bytes.len() >= self.params.isc_params.min_iop_size,
                "Error: IOp {id} is too short and could lead to sync_id overflow"
            );
            // All IOp mustn't contain SYNC token
            // TODO enable sync check
            // -> Find a proper way to match on Sync opcode
            // assert!(!fw_bytes.contains(&sync_opcode),
            //         "Error: IOp {id} contain SYNC. This break the min_iop_size requirement and
            // could lead to sync_id overflow");
        }

        // Sort by opcode and write Lut and translation table into memory
        // NB: ublaze is a 32b cpu => addr-lut/ translation word must be 32b word
        id_fw.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        let mut ofst = 0x100; // Opcode is 8bit -> 256 words entry
        let cut_ofst = self.fw_mem.cut_paddr()[0] as usize;

        // Default tr_lut with fallback entry
        // Uninit entries point to first tr-table
        let mut tr_lut = vec![(cut_ofst + (ofst * std::mem::size_of::<u32>())) as u32; 256];

        for (id, fw_bytes) in id_fw.into_iter() {
            // Store lookup addr
            // NB: ublaze expect addr with Hbm_pc offset
            // NB': Ublaze understand lut entry as ofst from PC_MEM => on't add cut_ofst in the
            // entry
            let byte_ofst = (/* cut_ofst + */(ofst * std::mem::size_of::<u32>())) as u32;
            tr_lut[id] = byte_ofst;

            // Write tr-table
            let fw_words = bytemuck::cast_slice::<_, u32>(fw_bytes.as_slice());
            self.fw_mem.write_cut_at(0, ofst, fw_words);
            tracing::debug!("Opcode::{id:x} @{ofst:x} [{byte_ofst:x}]");
            tracing::trace!("TrTable::{fw_words:x?}");
            ofst += fw_words.len();
        }
        // Write lookup table all at once
        self.fw_mem.write_cut_at(0, 0, tr_lut.as_slice());
    }
}

impl HpuBackend {
    #[tracing::instrument(skip(self, cmd))]
    fn workq_push(&mut self, cmd: cmd::HpuCmd) -> Result<(), HpuInternalError> {
        let Self {
            ref mut hpu_hw,
            workq_addr,
            cmd_q,
            ..
        } = self;

        // Steps are as follow
        // 1. Enforce that source ops are synced on Hw
        cmd.src
            .iter()
            .map(|src| src.inner.lock().unwrap().try_hpu_sync())
            .collect::<Result<Vec<_>, _>>()?;

        // 2. Issue work to Hpu through workq
        // Convert Iop in a stream of bytes
        let op_words = cmd.op.to_words();
        tracing::debug!("Op Asm {}", cmd.op);
        tracing::trace!("Op Words {:x?}", op_words);

        // Write them in workq entry
        // NB: No queue full check was done ...
        for w in op_words.iter() {
            hpu_hw.write_reg(*workq_addr, *w);
        }

        // 3. Update dst state to OpPending
        cmd.dst
            .iter()
            .for_each(|dst| dst.inner.lock().unwrap().operation_pending());

        // Keep track of op in cmd_q for lifetime tracking
        cmd_q.push_back(cmd);

        Ok(())
    }

    /// Poll ack_q
    /// When ack received pop entry in cmd_q and update variable accordingly
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn poll_ack_q(&mut self) -> Result<bool, HpuInternalError> {
        let Self {
            ref mut hpu_hw,
            ackq_addr,
            cmd_q,
            regmap,
            ..
        } = self;

        trace!(
            "Isc registers {:?}",
            rtl::runtime::InfoIsc::from_rtl(hpu_hw, regmap)
        );
        trace!(
            "PeMem registers {:?}",
            rtl::runtime::InfoPeMem::from_rtl(hpu_hw, regmap)
        );
        trace!(
            "PeAlu registers {:?}",
            rtl::runtime::InfoPeAlu::from_rtl(hpu_hw, regmap)
        );
        trace!(
            "PePbs registers {:?}",
            rtl::runtime::InfoPePbs::from_rtl(hpu_hw, regmap)
        );

        let ack_code = hpu_hw.read_reg(*ackq_addr);
        if ack_code != ACKQ_EMPTY {
            let ack_cmd = cmd_q.pop_front().unwrap();
            // TODO check that ack_code match with expected op msb
            tracing::debug!("Received ack {:x} for IOp  {}", ack_code, ack_cmd.op);
            // update dst state and drop srcs ref
            ack_cmd
                .dst
                .iter()
                .for_each(|dst| dst.inner.lock().unwrap().operation_done());
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl HpuBackend {
    /// This function is in charge of:
    ///  * Xfer cmd from the queue to the HW
    ///  * Poll for ack and update vars state accordingly
    ///  * Collect released memory
    pub(crate) fn run_step(&mut self) -> Result<(), HpuInternalError> {
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            self.workq_push(cmd)?;
        }
        while self.poll_ack_q()? {}

        self.ct_mem.gc_bundle();
        Ok(())
    }
}

impl Drop for HpuBackend {
    fn drop(&mut self) {
        // Release ffi allocated memory
        // Couldn't rely on Drop trait of inner objects since it required reference to associated
        // ffi backend
        self.bsk_key.release(&mut self.hpu_hw);
        self.ksk_key.release(&mut self.hpu_hw);
        self.lut_mem.release(&mut self.hpu_hw);
        self.fw_mem.release(&mut self.hpu_hw);
        self.ct_mem.release(&mut self.hpu_hw);
    }
}
