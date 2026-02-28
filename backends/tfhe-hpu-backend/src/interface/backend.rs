/// Implement inner-view of Hpu backend
use super::*;
use crate::asm::PbsLut;
use crate::entities::*;
use crate::fw::isc_sim::PeConfigStore;
use crate::fw::{Fw, FwParameters};
use crate::{asm, ffi};
use rtl::FromRtl;

use itertools::Itertools;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{mpsc, Arc, Mutex};
use strum::VariantNames;

use tracing::{debug, info, trace};

use rayon::prelude::*;

pub struct HpuBackend {
    // Low-level hardware handling
    hpu_hw: ffi::HpuHw,
    regmap: hw_regmap::FlatRegmap,

    // Extracted parameters
    pub(crate) params: HpuParameters,
    #[cfg(feature = "hw-v80")]
    hpu_version_major: u32,
    #[cfg(feature = "hw-v80")]
    hpu_version_minor: u32,
    // Prevent to parse regmap at each polling iteration
    #[cfg(not(feature = "hw-v80"))]
    workq_addr: u64,
    #[cfg(not(feature = "hw-v80"))]
    ackq_addr: u64,

    // Key memory
    bsk_key: memory::HugeMemory<u64>,
    ksk_key: memory::HugeMemory<u64>,

    // Lut and Fw memory
    lut_mem: memory::HugeMemory<u64>,
    fw_mem: memory::HugeMemory<u32>,
    init_fw_width: Vec<usize>,

    // Memory management
    // Board memory is abstract as a bunch of ciphertext slot
    // Used a dedicaed manager to handle lifetime of used slot
    pub(crate) ct_mem: memory::CiphertextMemory,

    // HW Trace cut
    trace_mem: memory::HugeMemory<u32>,

    // Work management
    // Keep track of issued IOp and associated variables
    cmd_q: VecDeque<cmd::HpuCmd>,
    cmd_rx: mpsc::Receiver<cmd::HpuCmd>,
}

pub struct HpuBackendLock(Mutex<HpuBackend>);

impl HpuBackendLock {
    fn new(inner: HpuBackend) -> Self {
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
    pub fn new_wrapped(config: &config::HpuConfig) -> (Self, mpsc::Sender<cmd::HpuCmd>) {
        let (be, cmd_api) = HpuBackend::new(config);
        (Self(Arc::new(HpuBackendLock::new(be))), cmd_api)
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
    pub fn new(config: &config::HpuConfig) -> (Self, mpsc::Sender<cmd::HpuCmd>) {
        let mut hpu_hw = ffi::HpuHw::new_hpu_hw(
            &config.fpga.ffi,
            std::time::Duration::from_micros(config.fpga.polling_us),
        );
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
        let regmap = hw_regmap::FlatRegmap::from_file(&regmap_str);
        let mut params = HpuParameters::from_rtl(&mut hpu_hw, &regmap);

        #[cfg(feature = "hw-v80")]
        let (hpu_version_major, hpu_version_minor) = {
            let version_reg = regmap
                .register()
                .get("info::version")
                .expect("Unknown register, check regmap definition");
            let hpu_version_val = hpu_hw.read_reg(*version_reg.offset() as u64);
            let hpu_version_fields = version_reg.as_field(hpu_version_val);
            (
                *hpu_version_fields.get("major").expect("Unknown field"),
                *hpu_version_fields.get("minor").expect("Unknown field"),
            )
        };

        // In case this is not filled by from_rtl()
        if params.ntt_params.min_pbs_nb.is_none() {
            params.ntt_params.min_pbs_nb = Some(config.firmware.min_batch_size);
        }

        // Init on-board memory
        hpu_hw.init_mem(config, &params);

        // Flush ack_q
        // Ensure that no residue from previous execution were stall in the pipe
        #[cfg(feature = "hw-v80")]
        {
            // TODO add ack flush to prevent error with previous stall execution
        }
        #[cfg(not(feature = "hw-v80"))]
        {
            let ackq_addr = (*regmap
                .register()
                .get("WorkAck::ackq")
                .expect("Unknown register, check regmap definition")
                .offset()) as u64;
            loop {
                let ack_code = hpu_hw.read_reg(ackq_addr);
                if ack_code == ACKQ_EMPTY {
                    break;
                }
            }
        }

        // Apply Rtl configuration
        // Bpip use
        let bpip_use_reg = regmap
            .register()
            .get("bpip::use")
            .expect("Unknown register, check regmap definition");
        hpu_hw.write_reg(
            *bpip_use_reg.offset() as u64,
            bpip_use_reg.from_field(
                [
                    ("use_bpip", config.rtl.bpip_use as u32),
                    ("use_opportunism", config.rtl.bpip_use_opportunism as u32),
                ]
                .into(),
            ),
        );

        // Bpip timeout
        hpu_hw.write_reg(
            *regmap
                .register()
                .get("bpip::timeout")
                .expect("Unknown register, check regmap definition")
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

        #[cfg(not(feature = "hw-v80"))]
        let workq_addr = (*regmap
            .register()
            .get("WorkAck::workq")
            .expect("Unknown register, check regmap definition")
            .offset()) as u64;
        #[cfg(not(feature = "hw-v80"))]
        let ackq_addr = (*regmap
            .register()
            .get("WorkAck::ackq")
            .expect("Unknown register, check regmap definition")
            .offset()) as u64;

        // Allocate memory for Bsk
        let bsk_props = {
            let bsk_pc = &params.pc_params.bsk_pc;
            let bsk_size = hpu_lwe_bootstrap_key_size(&params);

            let cut_coefs = bsk_size.div_ceil(*bsk_pc);
            let mem_cut = config
                .board
                .bsk_pc
                .clone()
                .into_iter()
                .take(*bsk_pc)
                .collect::<Vec<_>>();
            memory::HugeMemoryProperties { mem_cut, cut_coefs }
        };
        let bsk_key = memory::HugeMemory::alloc(&mut hpu_hw, bsk_props);

        // Allocate memory for Ksk
        let ksk_props = {
            let ksk_pc = &params.pc_params.ksk_pc;
            let ksk_size = hpu_lwe_keyswitch_key_size(&params);

            let cut_coefs = ksk_size.div_ceil(*ksk_pc);
            let mem_cut = config
                .board
                .ksk_pc
                .clone()
                .into_iter()
                .take(*ksk_pc)
                .collect::<Vec<_>>();

            memory::HugeMemoryProperties { mem_cut, cut_coefs }
        };
        let ksk_key = memory::HugeMemory::alloc(&mut hpu_hw, ksk_props);

        // Allocate memory for GlweLut
        let lut_props = memory::HugeMemoryProperties {
            mem_cut: vec![config.board.lut_pc],
            cut_coefs: config.board.lut_mem * params.pbs_params.polynomial_size,
        };
        let lut_mem = memory::HugeMemory::alloc(&mut hpu_hw, lut_props);

        // Allocate memory for Fw translation table
        let fw_props = memory::HugeMemoryProperties {
            mem_cut: vec![config.board.fw_pc],
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
            mem_cut: config.board.ct_pc.clone(),
            // NB: Xrt only support page align memory allocation. Thus we round cut coefs to
            // match the next 4k page boundary
            cut_size_b,
            slot_nb: config.board.ct_mem,
            used_as_heap: config.board.heap_size,
            retry_rate_us: config.fpga.polling_us,
        };
        debug!("Ct_mem properties -> {:?}", ct_props);
        let ct_mem = memory::CiphertextMemory::alloc(&mut hpu_hw, &regmap, &ct_props);

        // load trace ptr from config (size does not matter so putting 256)
        let trace_props = memory::HugeMemoryProperties {
            mem_cut: vec![config.board.trace_pc],
            cut_coefs: 256,
        };
        let trace_mem = memory::HugeMemory::alloc(&mut hpu_hw, trace_props);

        // Construct channel for mt API
        // Keep track of the sender for clone it later on
        let (cmd_tx, cmd_rx) = mpsc::channel();

        (
            Self {
                hpu_hw,
                regmap,
                params,
                #[cfg(feature = "hw-v80")]
                hpu_version_major,
                #[cfg(feature = "hw-v80")]
                hpu_version_minor,
                #[cfg(not(feature = "hw-v80"))]
                workq_addr,
                #[cfg(not(feature = "hw-v80"))]
                ackq_addr,
                bsk_key,
                ksk_key,
                lut_mem,
                fw_mem,
                init_fw_width: Vec::new(),
                ct_mem,
                trace_mem,
                cmd_q: VecDeque::new(),
                cmd_rx,
            },
            cmd_tx,
        )
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
            .get("bsk_avail::avail")
            .expect("Unknown register, check regmap definition");
        let bsk_reset = regmap
            .register()
            .get("bsk_avail::reset")
            .expect("Unknown register, check regmap definition");

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

                *fields.get("done").expect("Unknown field") != 0
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
            .get("bsk_avail::avail")
            .expect("Unknown register, check regmap definition");
        let bsk_addr_pc = (0..params.pc_params.bsk_pc)
            .map(|idx| {
                let lsb_name = format!("hbm_axi4_addr_3in3::bsk_pc{idx}_lsb");
                let msb_name = format!("hbm_axi4_addr_3in3::bsk_pc{idx}_msb");
                let lsb = regmap
                    .register()
                    .get(&lsb_name)
                    .expect("Unknown register, check regmap definition");
                let msb = regmap
                    .register()
                    .get(&msb_name)
                    .expect("Unknown register, check regmap definition");
                (lsb, msb)
            })
            .collect::<Vec<_>>();

        // Write key in associated buffer
        for (id, bsk_cut) in bsk.as_view().into_container().into_iter().enumerate() {
            bsk_key.write_cut_at(id, 0, bsk_cut);
            #[cfg(feature = "io-dump")]
            io_dump::dump(
                bsk_cut,
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
            .get("bsk_avail::avail")
            .expect("Unknown register, check regmap definition");

        let val = hpu_hw.read_reg(*bsk_avail.offset() as u64);
        let fields = bsk_avail.as_field(val);

        *fields.get("avail").expect("Unknown field") != 0
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
            .get("ksk_avail::avail")
            .expect("Unknown register, check regmap definition");
        let ksk_reset = regmap
            .register()
            .get("ksk_avail::reset")
            .expect("Unknown register, check regmap definition");

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

                *fields.get("done").expect("Unknown field") != 0
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
            .get("ksk_avail::avail")
            .expect("Unknown register, check regmap definition");
        let ksk_addr_pc = (0..params.pc_params.ksk_pc)
            .map(|idx| {
                let lsb_name = format!("hbm_axi4_addr_1in3::ksk_pc{idx}_lsb");
                let msb_name = format!("hbm_axi4_addr_1in3::ksk_pc{idx}_msb");
                let lsb = regmap
                    .register()
                    .get(&lsb_name)
                    .expect("Unknown register, check regmap definition");
                let msb = regmap
                    .register()
                    .get(&msb_name)
                    .expect("Unknown register, check regmap definition");
                (lsb, msb)
            })
            .collect::<Vec<_>>();

        // Write key in associated buffer
        for (id, ksk_cut) in ksk.as_view().into_container().into_iter().enumerate() {
            ksk_key.write_cut_at(id, 0, ksk_cut);
            #[cfg(feature = "io-dump")]
            io_dump::dump(
                ksk_cut,
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
            .get("ksk_avail::avail")
            .expect("Unknown register, check regmap definition");

        let val = hpu_hw.read_reg(*ksk_avail.offset() as u64);
        let fields = ksk_avail.as_field(val);

        *fields.get("avail").expect("Unknown field") != 0
    }
}

/// Handle Glwe Lut initialisation
/// Lut and Fw are merged since
impl HpuBackend {
    #[tracing::instrument(level = "debug", skip(self, gen_lut), ret)]
    pub(crate) fn lut_init<F>(&mut self, gen_lut: F)
    where
        F: Fn(HpuParameters, &asm::Pbs) -> HpuGlweLookuptableOwned<u64>,
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
            let hpu_lut = gen_lut(params.clone(), &lut_impl);

            // NB: lut_mem are always on 1cut
            let ofst = lut_gid * params.pbs_params.polynomial_size;
            lut_mem.write_cut_at(0, ofst, hpu_lut.as_view().into_container());
            #[cfg(feature = "io-dump")]
            io_dump::dump(
                hpu_lut.as_ref(),
                params,
                io_dump::DumpKind::Glwe,
                io_dump::DumpId::Lut(lut_gid),
            );
        }

        // Configure Hpu register accordingly
        // Extract register from regmap
        let reg_lsb = regmap
            .register()
            .get("hbm_axi4_addr_1in3::glwe_pc0_lsb")
            .expect("Unknown register, check regmap definition");
        let reg_msb = regmap
            .register()
            .get("hbm_axi4_addr_1in3::glwe_pc0_msb")
            .expect("Unknown register, check regmap definition");

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

/// HW trace initialisation
impl HpuBackend {
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub(crate) fn trace_init(&mut self) {
        let Self {
            ref mut hpu_hw,
            regmap,
            trace_mem,
            ..
        } = self;

        // Configure Hpu register accordingly
        // Extract register from regmap
        let reg_lsb = regmap
            .register()
            .get("hbm_axi4_addr_1in3::trc_pc0_lsb")
            .expect("Unknown register, check regmap definition");
        let reg_msb = regmap
            .register()
            .get("hbm_axi4_addr_1in3::trc_pc0_msb")
            .expect("Unknown register, check regmap definition");

        let trace_addr = trace_mem.cut_paddr()[0];
        hpu_hw.write_reg(
            *reg_msb.offset() as u64,
            ((trace_addr >> u32::BITS) & (u32::MAX) as u64) as u32,
        );
        hpu_hw.write_reg(
            *reg_lsb.offset() as u64,
            (trace_addr & (u32::MAX as u64)) as u32,
        );
    }
}

/// Handle Fw Lut and translation table init
impl HpuBackend {
    #[tracing::instrument(skip(self, config))]
    pub(crate) fn fw_init(&mut self, config: &config::HpuConfig) {
        // Create Asm architecture properties and Fw instantiation
        let pe_cfg = PeConfigStore::from((&self.params, config));
        let fw_name =
            crate::fw::FwName::from_str(&config.firmware.implementation).unwrap_or_else(|_| {
                panic!(
                    "Unknown firmware name {}, list of possible firmware names: {}",
                    config.firmware.implementation,
                    crate::fw::AvlblFw::VARIANTS.iter().join(",")
                );
            });
        let fw = crate::fw::AvlblFw::new(&fw_name);

        // TODO Add RTL register for the nu value
        let mut fw_params = FwParameters {
            register: self.params.regf_params.reg_nb,
            isc_depth: self.params.isc_params.depth,
            heap_size: config.board.heap_size,
            min_iop_size: self.params.isc_params.min_iop_size,
            min_pbs_batch_w: self
                .params
                .ntt_params
                .min_pbs_nb
                .unwrap_or(self.params.ntt_params.batch_pbs_nb),
            pbs_batch_w: self.params.ntt_params.batch_pbs_nb,
            total_pbs_nb: self.params.ntt_params.total_pbs_nb,
            msg_w: self.params.pbs_params.message_width,
            carry_w: self.params.pbs_params.carry_width,
            nu: 5,
            integer_w: 0,
            use_ipip: !config.rtl.bpip_use,
            kogge_cfg: config.firmware.kogge_cfg.expand(),
            op_cfg: config.firmware.op_cfg.clone(),
            cur_op_cfg: config.firmware.op_cfg.default(),
            pe_cfg,
            op_name: None,
        };

        // Check that required number of integer_w don't overflow the lookup table space
        let integer_w_max = config.firmware.integer_w.iter().max().unwrap_or(&0);
        let blk_w_max = integer_w_max / fw_params.msg_w;
        assert!(
            blk_w_max < FW_TABLE_ENTRY,
            "ERROR: requested {} fw configuration but current implementation only support {} entries",
            config.firmware.integer_w.len(),
            FW_TABLE_ENTRY
        );
        let mut tr_table_ofst = FW_TABLE_ENTRY * 0x100; // Opcode is 8bit -> 256 words entry
        let cut_ofst = self.fw_mem.cut_paddr()[0] as usize;

        for integer_w in config.firmware.integer_w.iter() {
            // Update fw parameters with concrete integer_width
            assert_eq!(
                integer_w % fw_params.msg_w,
                0,
                "ERROR: requested integer_w {integer_w} isn't compliant with MSG_W {}",
                fw_params.msg_w
            );
            let blk_w = integer_w / fw_params.msg_w;
            fw_params.integer_w = *integer_w;

            // Generate Fw for standard operation
            // -> All operation with an associated alias
            let mut id_fw = asm::iop::IOP_LIST
                .par_iter()
                .map(|iop| {
                    let opcode = iop.opcode();
                    let prog = fw.expand(&fw_params, iop);
                    (opcode.0 as usize, prog.tr_table())
                })
                .collect::<Vec<_>>();

            // Load custom IOp from file
            for (name, asm_file) in config.firmware.custom_iop.iter() {
                let iop = asm::AsmIOpcode::from_str(name)
                    .unwrap_or_else(|_| panic!("Invalid Custom Iop name {name}"));
                let opcode = iop.opcode();
                let prog = asm::Program::<asm::DOp>::read_asm(&asm_file.expand())
                    .unwrap_or_else(|_| panic!("Invalid custom_iop file {}", asm_file.expand()));
                id_fw.push((opcode.0 as usize, prog.tr_table()));
            }

            // Sanity check
            let sync_opcode = asm::dop::DOpSync::opcode();
            for (id, fw_bytes) in id_fw.iter() {
                // All IOp entry must be gte (MIN_IOP_SIZE-1)
                // NB fw_bytes contain size + DOps -> gte MIN_IOP_SIZE
                assert!(
                    fw_bytes.len() >= self.params.isc_params.min_iop_size,
                    "Error: IOp {id} is too short and could lead to sync_id overflow"
                );
                // All IOp mustn't contain SYNC token
                let mut sync_dop = fw_bytes
                    .iter()
                    .filter(|w| (((*w >> 24) & 0xff) as u8) == sync_opcode)
                    .peekable();
                assert!(
                    sync_dop.peek().is_none(),
                    "Error: IOp[0x{id:x}] contain SYNC. This break the min_iop_size requirement and
                could lead to sync_id overflow"
                );
            }

            // Sort by opcode and write Lut and translation table into memory
            // NB: ucore is a 32b cpu => addr-lut/ translation word must be 32b word
            id_fw.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            let blk_ofst = (blk_w - 1) * 0x100; // Opcode is 8bit -> 256 words per blk_w

            // Default tr_lut with fallback entry
            // Uninit entries point to fist tr-table entry
            let mut tr_lut =
                vec![(cut_ofst + (tr_table_ofst * std::mem::size_of::<u32>())) as u32; 256];

            for (id, fw_bytes) in id_fw.into_iter() {
                // Store lookup addr
                // NB: ucore expect addr with physical memory offset
                // NB': ucore understand lut entry as ofst from PHYS_MEM => don't add cut_ofst in
                // the entry
                let byte_ofst = /* cut_ofst + */(tr_table_ofst * std::mem::size_of::<u32>()) as u32;
                tr_lut[id] = byte_ofst;

                // Write tr-table
                let fw_words = bytemuck::cast_slice::<_, u32>(fw_bytes.as_slice());
                self.fw_mem.write_cut_at(0, tr_table_ofst, fw_words);
                tracing::debug!(
                    "Opcode::{id:x}[{} dops] @{tr_table_ofst:x} [{byte_ofst:x}]",
                    fw_words.len()
                );
                tracing::trace!("TrTable::{fw_words:x?}");
                tr_table_ofst += fw_words.len();
            }
            // Write lookup table all at once
            self.fw_mem.write_cut_at(0, blk_ofst, tr_lut.as_slice());
            tracing::debug!(
                "Fw[{blk_w}]:: lut entry @{blk_ofst:x} [{:x}]",
                blk_ofst * std::mem::size_of::<u32>()
            );
            tracing::trace!(" LutTable=> {tr_lut:x?}");

            // Update init_fw_width list enable to runtime check
            self.init_fw_width.push(*integer_w);
        }
    }
}

impl HpuBackend {
    #[tracing::instrument(skip(self, cmd))]
    fn workq_push(&mut self, cmd: cmd::HpuCmd) -> Result<(), HpuInternalError> {
        let Self {
            ref mut hpu_hw,
            #[cfg(not(feature = "hw-v80"))]
            workq_addr,
            cmd_q,
            ..
        } = self;

        // Check if issued command
        // NB: fw_blk_width is 0 encoded => 0 ~ 1 block ciphertext
        assert!(
        self.init_fw_width.contains(&((cmd.op.fw_blk_width()+1)*self.params.pbs_params.message_width)
        ),
        "Requested integer width {:?} isn't configured in [Hpu: {:?}] and could lead to Undefined Behavior. Please check Hpu configuration file.",
        (cmd.op.fw_blk_width()+1) * self.params.pbs_params.message_width,
        self.init_fw_width
    );

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
        #[cfg(feature = "hw-v80")]
        {
            hpu_hw.iop_push(op_words.as_slice());
        }
        #[cfg(not(feature = "hw-v80"))]
        {
            for w in op_words.iter() {
                hpu_hw.write_reg(*workq_addr, *w);
            }
        }

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
            #[cfg(not(feature = "hw-v80"))]
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

        #[cfg(feature = "hw-v80")]
        {
            let ack_nb = hpu_hw.iop_ack_rd();
            if ack_nb == 0 {
                Ok(false)
            } else {
                tracing::debug!("Received ack {ack_nb} IOp ack. Pending cmd {}", cmd_q.len());
                for _ack in 0..ack_nb {
                    let ack_cmd = cmd_q.pop_front().unwrap();
                    // TODO check that ack_code match with expected op msb
                    tracing::debug!("Received ack for IOp  {}", ack_cmd.op);
                    // update dst state and drop srcs ref
                    ack_cmd
                        .dst
                        .iter()
                        .for_each(|dst| dst.inner.lock().unwrap().operation_done());
                }
                Ok(true)
            }
        }
        #[cfg(not(feature = "hw-v80"))]
        {
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
}

impl HpuBackend {
    /// This function flush all pending cmd
    pub(crate) fn flush_workq(&mut self) -> Result<(), HpuInternalError> {
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            self.workq_push(cmd)?;
        }
        Ok(())
    }
    /// This function flush all pending ack
    pub(crate) fn flush_ackq(&mut self) -> Result<(), HpuInternalError> {
        while self.poll_ack_q()? {}
        Ok(())
    }

    #[cfg(feature = "hw-v80")]
    pub(crate) fn get_hpu_version(&self) -> (u32, u32) {
        (self.hpu_version_major, self.hpu_version_minor)
    }

    #[cfg(feature = "hw-v80")]
    pub(crate) fn map_bar_reg(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.hpu_hw.map_bar_reg()
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
