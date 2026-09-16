/// Implement inner-view of Hpu backend
use super::*;
use crate::asm::{IOpSig, MAX_HPU_IN_CLUSTER};
use crate::entities::*;
use crate::interface::cache::{DynFwEntry, DynFwError};
use crate::{asm, ffi};
use bytemuck::{Pod, Zeroable};
use rtl::FromRtl;

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::{atomic, Arc, Mutex};
use zhc::crypto::integer_semantics::lut::{LutId, LutRegistry};
use zhc::ir::IR;
use zhc::langs::doplang;
use zhc::prelude::Fingerprint;

use zhc::builder::CiphertextSpec;

use tracing::{debug, info, trace};

use std::time::{SystemTime, UNIX_EPOCH};

/// Runtime configuration of the ucore
/// This structure is used to configure the ucore fw with custom runtime information
/// It rely on C-struct layout to keep compatibilities with arm cortex-R SW
/// NB: This structure is shared at the beginning of Fw memory with 64w of u32 reserved
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UcoreConfig {
    pub node_id: u8,
    pub timestamp: u32,
    pub node_mask: u8,
    pub user_size: u16,
    pub b2b_size: u16,
    _padding: [u8; 2],
    pub dyn_iop_addr: u32,
    pub dyn_iop_size: u32,
    // NB: modification in this file must match the one in amc.c
    _reserved_word: [u32; 59],
}
// SAFETY: UcoreConfig is repr(C) with only Zeroable/Pod types
unsafe impl Zeroable for UcoreConfig {}
unsafe impl Pod for UcoreConfig {}

impl UcoreConfig {
    pub fn new(
        node_id: u8,
        node_mask: u8,
        user_size: u16,
        b2b_size: u16,
        dyn_iop_addr: u32,
        dyn_iop_size: u32,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards!")
            .as_secs() as u32;

        Self {
            node_id,
            timestamp,
            node_mask,
            user_size,
            b2b_size,
            _padding: [0; 2],
            dyn_iop_addr,
            dyn_iop_size,
            _reserved_word: [u32::MAX; 59],
        }
    }
}

// Custom display implementation with Debug like format to discard _padding fields
impl std::fmt::Display for UcoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UcoreConfig")
            .field("node_id", &self.node_id)
            .field("timestamp", &self.timestamp)
            .field("node_mask", &format_args!("{:#010b}", self.node_mask))
            .field("user_size", &self.user_size)
            .field("b2b_size", &self.b2b_size)
            .finish()
    }
}

pub struct HpuNode {
    // Low-level hardware handling
    hpu_hw: ffi::HpuHw,
    regmap: hw_regmap::FlatRegmap,

    // Node id
    hid: u8,
    node_mask: u8,
    // Extracted parameters
    pub(crate) params: Arc<HpuParameters>,

    // Key memory
    bsk_key: memory::HugeMemory<u64>,
    ksk_key: memory::HugeMemory<u64>,

    // Lut and Fw memory
    lut_cache: cache::LutCache,
    fw_mem: memory::HugeMemory<u32>,
    dyn_fw_cache: cache::DynFwCache,

    // Memory management
    // Board memory is abstract as a bunch of ciphertext slot
    // Used a dedicaed manager to handle lifetime of used slot
    pub(crate) ct_mem: memory::CiphertextMemory,
    ct_base_addr: Vec<u64>,

    // HW Trace cut
    trace_mem: memory::HugeMemory<u32>,

    // Keep track of pending IOp
    // Enable to match Sync on IOp data
    cmdq: VecDeque<Arc<cmd::HpuCmd>>,
}

pub struct HpuNodeLock(Mutex<HpuNode>);

impl HpuNodeLock {
    fn new(inner: HpuNode) -> Self {
        Self(Mutex::new(inner))
    }
}
impl std::ops::Deref for HpuNodeLock {
    type Target = Mutex<HpuNode>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
unsafe impl Send for HpuNodeLock {}
unsafe impl Sync for HpuNodeLock {}

#[derive(Clone)]
pub struct HpuNodeWrapped {
    pub(crate) params: Arc<HpuParameters>,
    pub(crate) ct_mem: memory::CiphertextMemory,
    inner: Arc<HpuNodeLock>,
}

impl HpuNodeWrapped {
    pub fn new_wrapped(id: u8, config: &config::HpuConfig) -> Self {
        let node = HpuNode::new(id, config);
        let ct_mem = node.ct_mem.clone();
        let params = node.params.clone();

        Self {
            params,
            ct_mem,
            inner: Arc::new(HpuNodeLock::new(node)),
        }
    }
}
impl std::ops::Deref for HpuNodeWrapped {
    type Target = Arc<HpuNodeLock>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
unsafe impl Send for HpuNodeWrapped {}
unsafe impl Sync for HpuNodeWrapped {}

/// Handle HpuBackend construction and initialisation
impl HpuNode {
    pub fn new(hid: u8, config: &config::HpuConfig) -> Self {
        let node_mask = {
            let mut mask = 0;
            for node in config.fpga.node_id.iter() {
                mask |= 1 << node;
            }
            mask
        };

        let mut hpu_hw = ffi::HpuHw::open_hpu_hw(
            hid,
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
        let params = {
            let mut orig_params = HpuParameters::from_rtl(&mut hpu_hw, &regmap);

            // In case this is not filled by from_rtl()
            if orig_params.ntt_params.min_pbs_nb.is_none() {
                orig_params.ntt_params.min_pbs_nb = Some(config.firmware.min_batch_size);
            }
            Arc::new(orig_params)
        };

        // Init on-board memory
        hpu_hw.init_mem(config, &params);

        // Flush ack_q
        // Ensure that no residue from previous execution were stall in the pipe
        hpu_hw.iop_ack_rd();

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
            "[N{hid}] Isc registers {:?}",
            rtl::runtime::InfoIsc::from_rtl(&mut hpu_hw, &regmap)
        );
        debug!(
            "[N{hid}] PeMem registers {:?}",
            rtl::runtime::InfoPeMem::from_rtl(&mut hpu_hw, &regmap)
        );
        debug!(
            "[N{hid}] PeAlu registers {:?}",
            rtl::runtime::InfoPeAlu::from_rtl(&mut hpu_hw, &regmap)
        );
        debug!(
            "[N{hid}] PePbs registers {:?}",
            rtl::runtime::InfoPePbs::from_rtl(&mut hpu_hw, &regmap)
        );

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
        debug!("[N{hid}] Bsk_mem properties -> {:?}", bsk_props);
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
        debug!("[N{hid}] Ksk_mem properties -> {:?}", ksk_props);
        let ksk_key = memory::HugeMemory::alloc(&mut hpu_hw, ksk_props);

        // Allocate memory for GlweLut
        let lut_cache = cache::LutCache::new(
            &mut hpu_hw,
            config.board.lut_pc,
            config.board.lut_mem,
            params.pbs_params.polynomial_size,
        );
        debug!("[N{hid}] Lut_cache entries -> {:?}", config.board.lut_mem);

        // Allocate memory for Fw translation table
        let fw_props = memory::HugeMemoryProperties {
            mem_cut: vec![config.board.fw_pc],
            cut_coefs: config.board.fw_size, // NB: here `size` is used as raw size (!= slot nb)
        };
        debug!("[N{hid}] Fw_mem properties -> {:?}", fw_props);
        let fw_mem = memory::HugeMemory::alloc(&mut hpu_hw, fw_props);

        // Allocate cache structure for Zhc dynamic Iop handling
        let dyn_fw_cache = cache::DynFwCache::new(
            &mut hpu_hw,
            config.board.dyn_fw_pc,
            config.board.dyn_fw_size,
        );

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
            slot_nb: config.board.user_size,
            retry_rate_us: config.fpga.polling_us,
        };
        debug!("[N{hid}] Ct_mem properties -> {:?}", ct_props);
        let (ct_mem, ct_base_addr) =
            memory::CiphertextMemory::alloc(&mut hpu_hw, &regmap, &ct_props);

        // load trace ptr from config (size does not matter so putting 256)
        let trace_props = memory::HugeMemoryProperties {
            mem_cut: vec![config.board.trace_pc],
            cut_coefs: 256,
        };
        let trace_mem = memory::HugeMemory::alloc(&mut hpu_hw, trace_props);

        Self {
            hpu_hw,
            regmap,
            hid,
            node_mask,
            params,
            bsk_key,
            ksk_key,
            lut_cache,
            fw_mem,
            dyn_fw_cache,
            ct_mem,
            ct_base_addr,
            trace_mem,
            cmdq: VecDeque::new(),
        }
    }
}

/// MHDMA configuration
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuNode {
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub fn mhdma_cfg(&mut self) {
        let Self {
            ref mut hpu_hw,
            regmap,
            hid,
            ct_base_addr,
            ..
        } = self;

        let ct_pc_nb = ct_base_addr.len();

        // Extract register from regmap
        let mhdma_hpu_ids = (0..MAX_HPU_IN_CLUSTER)
            .map(|idx| {
                let reg_name = format!("mhdma_system::hpu_id_{idx}");
                let reg = regmap
                    .register()
                    .get(&reg_name)
                    .expect("Unknown register, check regmap definition");
                reg
            })
            .collect::<Vec<_>>();
        let mhdma_timeout_notify = regmap
            .register()
            .get("mhdma_system::timeout_notify")
            .expect("Unknown register, check regmap definition");
        let mhdma_timeout_rr = regmap
            .register()
            .get("mhdma_system::timeout_read_req")
            .expect("Unknown register, check regmap definition");
        let mhdma_addr_pc = (0..ct_pc_nb)
            .map(|idx| {
                let lsb_name = format!("mhdma_hbm_axi4_addr_2in3::ct_pc{idx}_lsb");
                let msb_name = format!("mhdma_hbm_axi4_addr_2in3::ct_pc{idx}_msb");
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

        let board_props = ffi::HpuHw::get_board_properties();
        debug!("[N{hid}] Board properties -> {:?}", board_props);

        for idx in 0..MAX_HPU_IN_CLUSTER {
            let hpu_id = mhdma_hpu_ids[idx];
            let mac_addr = {
                let mut mac = if idx < board_props.len() {
                    board_props[idx].mac_addr
                } else {
                    0
                };
                if idx as u8 == *hid {
                    mac |= 0x80000000;
                }
                mac
            };
            debug!(
                "[N{hid}] MAC of HPU {idx} -> @{:X} {:X}",
                *hpu_id.offset() as u64,
                mac_addr
            );
            hpu_hw.write_reg(*hpu_id.offset() as u64, mac_addr);
        }
        hpu_hw.write_reg(*mhdma_timeout_notify.offset() as u64, 0xFFFFFFFF);
        hpu_hw.write_reg(*mhdma_timeout_rr.offset() as u64, 0xFFFFFFFF);

        for idx in 0..ct_pc_nb {
            let mhdma_addr_pc_lsb = mhdma_addr_pc[idx].0;
            let mhdma_addr_pc_msb = mhdma_addr_pc[idx].1;
            debug!(
                "[N{hid}] addr of ct_pc[{idx}] given to MHDMA -> @{:X}",
                ct_base_addr[idx]
            );
            hpu_hw.write_reg(
                *mhdma_addr_pc_msb.offset() as u64,
                (ct_base_addr[idx] >> 32) as u32,
            );
            hpu_hw.write_reg(
                *mhdma_addr_pc_lsb.offset() as u64,
                (ct_base_addr[idx] & 0xFFFFFFFF) as u32,
            );
        }
    }
}

/// Bootstrapping Key handling
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuNode {
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
    pub fn bsk_set(&mut self, bsk: HpuLweBootstrapKeyView<u64>) {
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
impl HpuNode {
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
    pub fn ksk_set(&mut self, ksk: HpuLweKeyswitchKeyView<u64>) {
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
impl HpuNode {
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub(crate) fn lut_init(&mut self) {
        let Self {
            ref mut hpu_hw,
            regmap,
            lut_cache,
            ..
        } = self;

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

        let lut_addr = lut_cache.get_pool_paddr();
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
impl HpuNode {
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

pub fn new_zhc_config(config: &HpuConfig, params: &HpuParameters) -> zhc::config::hpu::HpuConfig {
    use zhc::config::hpu::HpuConfig;
    use zhc::utils::units::{Cycle, MHz};

    // TODO: Add register to depicts the number of computation units (NB: Currently fixed to 1)
    let total_pbs_nb = params.ntt_params.total_pbs_nb;

    // Extract used parameters for ease of access
    let batch_pbs = params.ntt_params.batch_pbs_nb;
    let lwe_k = params.pbs_params.lwe_dimension;
    let glwe_k = params.pbs_params.glwe_dimension;
    let poly_size = params.pbs_params.polynomial_size;
    let pem_axi_w = params.pc_params.pem_pc * params.pc_params.pem_bytes_w * 8;
    let ct_w = params.ntt_params.ct_width as usize;
    let lbx = params.ks_params.lbx;
    let min_batch_size = params.ntt_params.min_pbs_nb.unwrap();

    // Compute some intermediate values
    let blwe_coefs = (poly_size * glwe_k) + 1;
    let glwe_coefs = poly_size * (glwe_k + 1);
    let rpsi = params.ntt_params.radix * params.ntt_params.psi;

    // Cycles required to load a ciphertext in the computation pipe
    let ct_load_cycles = usize::div_ceil(glwe_coefs * params.pbs_params.pbs_level, rpsi);
    // Latency of a Cmux for a batch
    let cmux_lat = ct_load_cycles * batch_pbs;

    // NB: Keyswitch latency is dimension to match roughly the Cmux latency (with lbx coefs in
    // //) Keep this approximation here
    let ks_cycles = cmux_lat * lbx;

    let ldst_raw_cycle = (blwe_coefs * ct_w).div_ceil(pem_axi_w);
    let ldst_cycle = ldst_raw_cycle * 2;
    let kspbs_rd_cycle = blwe_coefs.div_ceil(params.regf_params.coef_nb);
    let kspbs_cnst_cost = kspbs_rd_cycle; // write to regfile
    let kspbs_pbs_cost = (
        ks_cycles // latency of keyswitch
        + lwe_k * cmux_lat // Loop of cmux lat
        + batch_pbs * blwe_coefs.div_ceil(rpsi / 2 /* approx */)
        //Sample extract latency
    ) / batch_pbs;

    HpuConfig {
        freq: MHz(300),
        isc_depth: 64,
        isc_query_period: Cycle(12),
        mem_fifo_capacity: 8,
        mem_read_latency: ldst_cycle,
        mem_write_latency: ldst_cycle + 1,
        alu_fifo_capacity: 8,
        alu_read_latency: blwe_coefs,
        alu_write_latency: blwe_coefs + 1,
        pbs_fifo_capacity: 8,
        pbs_memory_capacity: total_pbs_nb,
        pbs_min_batch_size: min_batch_size,
        pbs_max_batch_size: batch_pbs,
        pbs_timeout: Cycle(100_000),
        pbs_load_unload_latency: kspbs_cnst_cost,
        pbs_processing_latency_a: kspbs_pbs_cost,
        pbs_processing_latency_b: kspbs_cnst_cost,
        pbs_processing_latency_m: min_batch_size,
        regf_size: 64,
        heap_size: config.board.heap_size,
    }
}

/// Handle Fw Lut and translation table init
/// NB: First part of the translation table in the ucore runtime configuration
/// Two kinds of fw are available:
/// * Static firmware: Upload during setup time, contains OffTheShelf IOp supported by Hpu
/// * Dyn firmware: All IOp uploaded by User at runtime. There are tracked by a local cache to
///   handle on-chip memory.
///
/// Both share same TfheLut, a local cache is used to patch DOp stream with virtual LutId into
/// physical Gid
impl HpuNode {
    #[tracing::instrument(skip(self, config, gen_lut))]
    pub(crate) fn fw_init<F>(
        &mut self,
        config: &config::HpuConfig,
        fw_sig: &mut Option<HashMap<(asm::StaticIOp, u16), IOpSig>>,
        gen_lut: &F,
    ) where
        F: Fn(&HpuParameters, &[u64]) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        // Prevent borrow/borrow mut at same time
        let params = self.params.clone();

        // Fw-table memory layout is as follow: [NB: Offset expressed in WORDS]
        // |---> Hbm/Ddr Offset <- from HpuConfig
        // |0x00: ...
        // |      UcoreConfig: Runtime configuration for FW
        // |FW_RUNTIME_MAX_SIZE:...
        // |      IOp translation lookup: Based on IntegerWidth, IOpId, VirtId
        // |      found the matching DOp stream
        // |FW_RUNTIME_MAX_SIZE + IOP_NUMBER*FW_TABLE_ENTRY*MAX_HPU_IN_CLUSTER: ...
        // |      DOp stream [Size_in_word] [Dop stream]
        // |--->

        // Extract dyn_iop_addr
        let dyn_iop_addr = if let ffi::MemKind::Ddr { offset } = config.board.dyn_fw_pc {
            offset
        } else {
            panic!("DynFwPc must be in DDR");
        };

        // Write runtime configuration
        // FW cut is view as u32 array, cast UcoreConfig accordingly
        let fw_cfg = UcoreConfig::new(
            self.hid,
            self.node_mask,
            config.board.user_size as u16,
            config.board.b2b_size as u16,
            dyn_iop_addr as u32,
            config.board.dyn_fw_size as u32,
        );
        let fw_cfg_raw_u8 = bytemuck::bytes_of(&fw_cfg);
        let fw_cfg_raw_u32 = bytemuck::cast_slice::<u8, u32>(fw_cfg_raw_u8);
        self.fw_mem.write_cut_at(0, 0, fw_cfg_raw_u32);
        tracing::debug!("[N{}] {fw_cfg}", self.hid);

        // Check that required number of integer_w don't overflow the lookup table space
        let integer_w_max = config.firmware.integer_w.iter().max().unwrap_or(&0);
        let blk_w_max = integer_w_max / params.pbs_params.message_width;
        assert!(
            blk_w_max < FW_TABLE_ENTRY,
            "ERROR: requested {} fw configuration but current implementation only support {} entries",
            config.firmware.integer_w.len(),
            FW_TABLE_ENTRY
        );

        // For each blk_w there are IOp_number * MAX_HPU_IN_CLUSTER
        // Opcode is 8bit -> 256 words entry
        // WARN: tr_table_ofst is relative expressed from DOP_LUT_ADDR i.e. after the runtime config
        let mut tr_table_ofst = FW_TABLE_ENTRY * IOP_NUMBER * asm::MAX_HPU_IN_CLUSTER;

        // Fallback entry
        // All uninit IOp will point to 0 length firmware for error detection
        let error_value = [0_u32; 1];
        let error_entry = tr_table_ofst;
        self.fw_mem
            .write_cut_at(0, FW_RUNTIME_MAX_WORD + tr_table_ofst, &error_value);
        tracing::debug!("Uninit IOp point to 0x{:x} entry", FW_RUNTIME_MAX_WORD);
        tr_table_ofst += error_value.len();

        for integer_w in config.firmware.integer_w.iter() {
            // Update fw parameters with concrete integer_width
            assert_eq!(
                integer_w % params.pbs_params.message_width,
                0,
                "ERROR: requested integer_w {integer_w} isn't compliant with MSG_W {}",
                params.pbs_params.message_width
            );
            let blk_w = integer_w / params.pbs_params.message_width;

            // Generate Fw for standard operation
            // -> All operation with an associated alias
            //    => allocate lut but gather upload on real hw outside of the loop
            let mut id_fw = asm::StaticIOp::ALL
                .iter()
                .map(|iop| {
                    // Get pipeline
                    let mut pipeline = iop.get_hpu_pipeline(
                        &new_zhc_config(config, &params),
                        CiphertextSpec::new(*integer_w as u16, 2, 2),
                    );
                    // NB: Currently all StaticIOp target 1 node
                    // TODO get number of nodes from pipeline
                    let sign_tuple = (pipeline.get_prototype().clone(), 1);

                    // Kept track of associated signature
                    if let Some(sig) = fw_sig {
                        let _ = sig.insert((*iop, *integer_w as u16), sign_tuple);
                    }

                    // Upload required Lut if needed and generate relocation table
                    let lut_remap = self.update_lut_registry(pipeline.get_lut_registry(), gen_lut);
                    let dop_stream = pipeline
                        .with_hpu_lut_relocation(lut_remap)
                        .get_hpu_stream()
                        .to_owned();

                    ((iop.get_opcode(), 0), dop_stream)
                })
                .collect::<Vec<_>>();

            // Load custom IOp from file
            if let Some(custom) = config
                .firmware
                .custom_iop
                .get(&format!("integer_w_{integer_w}"))
            {
                for (name, asm_base_file) in custom.iter() {
                    let iop = asm::StaticIOp::from_str(name)
                        .unwrap_or_else(|_| panic!("Invalid Custom Iop name {name}"));
                    let opcode = iop.get_opcode();
                    let mut used_vid = 0;
                    if !(asm::StaticIOp::USER_RANGE_LB..=asm::StaticIOp::USER_RANGE_UB)
                        .contains(&opcode)
                    {
                        panic!(
                            "Custom Iop [{integer_w}::{opcode}] outside of USER_RANGE [{}; {}]",
                            asm::StaticIOp::USER_RANGE_LB,
                            asm::StaticIOp::USER_RANGE_UB
                        );
                    }

                    let mut used_preamble: Option<doplang::Preamble> = None;
                    for vid in 0..MAX_HPU_IN_CLUSTER {
                        let asm_file = format!("{}_v{vid}.asm", asm_base_file.expand());
                        if std::path::Path::new(&asm_file).exists() {
                            // TODO rework parse_assembly and used buffered read instead ?
                            let asm_src = std::fs::read_to_string(&asm_file).unwrap_or_else(|e| {
                                panic!(" Custom asm file {asm_file} unreadable: {e}")
                            });
                            let (preamble, cust_ir) = doplang::parse_assembly(&asm_src)
                                .unwrap_or_else(|e| {
                                    panic!(" Custom asm file {asm_file} contains error: {e}")
                                });
                            debug!("Read custom asm file: {asm_file}");
                            used_vid += 1;
                            // Check validity
                            let sync = doplang::sync_usage(&cust_ir);
                            assert!(
                                sync.0 == 0,
                                "Error: {asm_file} contain SYNC. This break the min_iop_size requirement and
                            could lead to sync_id overflow"
                            );

                            let mix = doplang::instruction_mix(&cust_ir);
                            assert!(
                                mix.total() >= self.params.isc_params.min_iop_size,
                                "Error: {asm_file} is too short and could lead to sync_id overflow",
                            );

                            // Upload required Lut if needed and generate relocation table
                            let lut_remap = self.update_lut_registry(&preamble.luts, gen_lut);
                            let dop_stream = zhc::pipeline::passes::hpu_generate_translation_table(
                                &cust_ir,
                                Some(&lut_remap),
                            );
                            used_preamble = Some(preamble);
                            id_fw.push(((opcode, vid), dop_stream));
                        } else {
                            trace!("Custom asm file: {asm_file} unavailable")
                        }
                    }
                    // Kept track of associated signature
                    let preamble = used_preamble.unwrap_or_else(|| {
                        panic!(
                        "Custom IOp: {opcode:?} failed. No file match given path {}_v{{[0-7]}}.asm",
                        asm_base_file.expand())
                    });
                    if let Some(sig) = fw_sig {
                        let _ =
                            sig.insert((iop, *integer_w as u16), (preamble.signature, used_vid));
                    }
                }
            }

            // Sort by opcode/vid and write Lut and translation table into memory
            // NB: in rust tuple are cmp from left to right i.e. iop first then vid in our case
            // NB: ucore is a 32b cpu => addr-lut/ translation word must be 32b word
            id_fw.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

            // Opcode is 8bit -> 256 words per blk_w
            let blk_ofst = (blk_w - 1) * IOP_NUMBER * MAX_HPU_IN_CLUSTER;

            // Default tr_lut with fallback entry
            // Uninit entries point to error entry
            // NB: ucore expect addr with physical memory offset (i.e. Byte offset
            // NB': ucore understand lut entry as ofst from PHYS_MEM => don't add cut_ofst in
            // the entry
            let mut tr_lut = vec![
                (error_entry * std::mem::size_of::<u32>()) as u32;
                IOP_NUMBER * MAX_HPU_IN_CLUSTER
            ];

            for (id, fw_bytes) in id_fw.into_iter() {
                // Store lookup addr
                let byte_ofst = (tr_table_ofst * std::mem::size_of::<u32>()) as u32;
                tr_lut[(id.0 as usize) * MAX_HPU_IN_CLUSTER + id.1] = byte_ofst;

                // Write tr-table
                let fw_words = bytemuck::cast_slice::<_, u32>(fw_bytes.as_slice());
                self.fw_mem
                    .write_cut_at(0, FW_RUNTIME_MAX_WORD + tr_table_ofst, fw_words);
                tracing::debug!(
                    "[{integer_w}]::Opcode::{:x}.v{}[{} dops] @{tr_table_ofst:x} [{byte_ofst:x}]",
                    id.0,
                    id.1,
                    fw_words.len()
                );
                tracing::trace!("[{integer_w}]::TrTable::{fw_words:x?}");
                tr_table_ofst += fw_words.len();
            }
            // Write lookup table all at once
            self.fw_mem
                .write_cut_at(0, FW_RUNTIME_MAX_WORD + blk_ofst, tr_lut.as_slice());
            tracing::debug!(
                "[{integer_w}]::Fw[{blk_w}]:: lut entry @{blk_ofst:x} [{:x}]",
                blk_ofst * std::mem::size_of::<u32>()
            );
            tracing::trace!("[{integer_w}]::LutTable=> {tr_lut:x?}");
        }
    }

    #[tracing::instrument(skip(self, doplang, gen_lut))]
    pub(crate) fn fw_dyn_init<F>(
        &mut self,
        fingerprint: Fingerprint,
        proto: IOpSig,
        doplang: &[IR<doplang::DopLang>],
        lut_registry: &LutRegistry,
        gen_lut: &F,
    ) -> Result<Arc<DynFwEntry>, DynFwError>
    where
        F: Fn(&HpuParameters, &[u64]) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        // Try hit
        if let Some(entry) = self.dyn_fw_cache.get_by_hash(&fingerprint) {
            Ok(entry)
        } else {
            // Upload required Lut if needed and generate relocation table
            let lut_remap = self.update_lut_registry(lut_registry, gen_lut);

            // Generate specialized DOp stream
            // Construct a owned copy while enforcing correct number of stream
            let streams = doplang
                .iter()
                .map(|hpu_ir| {
                    zhc::pipeline::passes::hpu_generate_translation_table(hpu_ir, Some(&lut_remap))
                })
                .collect::<Vec<_>>();

            // Enforce correct number of stream
            let mut owned_streams: [Vec<u32>; MAX_HPU_IN_CLUSTER] =
                std::array::from_fn(|_i| Vec::new());
            for (o, i) in std::iter::zip(owned_streams.iter_mut(), streams) {
                *o = i;
            }

            let entry = self
                .dyn_fw_cache
                .get_or_insert(fingerprint, proto, owned_streams)?;

            Ok(entry)
        }
    }

    fn update_lut_registry<F>(&mut self, registry: &LutRegistry, gen_lut: &F) -> Vec<LutId>
    where
        F: Fn(&HpuParameters, &[u64]) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        let params = self.params.clone();
        // Erase parameters args from current lut_gen
        // NB: lut_cache doesn't have access to hpu_parameters
        let curried_lut_gen = |raw_lut: &zhc::crypto::integer_semantics::lut::RawLut| {
            let lut_u64 = raw_lut
                .lut()
                .iter()
                .map(|v| v.raw_complete_bits() as u64)
                .collect::<Vec<_>>();
            gen_lut(&params, &lut_u64)
        };

        // Upload required Lut if needed and generate relocation table
        let mut lut_remap = Vec::new();
        for (_lid, lut) in registry.iter_luts() {
            let hw_entry = self
                .lut_cache
                .get_or_insert(lut.clone(), &curried_lut_gen)
                .expect("Unable to upload required Lut. Check size of lut_mem");
            lut_remap.push(*hw_entry.id());
        }
        lut_remap
    }
}

impl HpuNode {
    #[tracing::instrument(skip(self, cmd))]
    pub(crate) fn workq_push(&mut self, cmd: Arc<cmd::HpuCmd>) {
        let Self {
            ref mut hpu_hw,
            cmdq,
            hid,
            ..
        } = self;
        // Check if targeted IOp firmware is properly loaded
        // TODO to be verified must have been done earlier

        // Issue work to Hpu through workq
        // Convert Iop in a stream of bytes
        let op_words = cmd.op.to_words();
        tracing::debug!("[N{hid}] Op Asm {}", cmd.op);
        tracing::trace!("[N{hid}] Op Words {:x?}", op_words);

        // Write them in workq entry
        // NB: No queue full check was done ...
        hpu_hw.iop_push(op_words.as_slice());

        // Keep track of op in cmdq for lifetime tracking
        // Only for involved Hpu, other one just dispatch iop for keeping iid in sync
        // and required no ack back
        if cmd.op.mapping().virt_id(asm::PhysId(*hid)).is_some() {
            cmdq.push_back(cmd);
        }
    }

    /// flush ack_q
    /// Retrieved all available ack
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn flush_ackq(&mut self) -> (usize, usize) {
        let Self {
            ref mut hpu_hw,
            regmap,
            cmdq,
            hid,
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

        let ack_nb = hpu_hw.iop_ack_rd();
        let mut done_nb = 0;
        for _ack in 0..ack_nb {
            let ack_cmd = cmdq
                .pop_front()
                .unwrap_or_else(|| panic!("[N{hid}] Received ack for unmatched IOp"));
            // TODO check that ack_code match with expected op msb
            tracing::debug!("[N{hid}] Received ack for IOp {}", ack_cmd.op);

            // update iop pending counter
            // Also update dst state if pending counter reach 0
            let pdg = ack_cmd.pdg_sync.fetch_sub(1, atomic::Ordering::SeqCst);
            if pdg == 1 {
                ack_cmd
                    .dst
                    .iter()
                    .for_each(|dst| dst.inner.lock().unwrap().operation_done());
                done_nb += 1;
            }
        }
        (ack_nb as usize, done_nb)
    }
}

impl Drop for HpuNode {
    fn drop(&mut self) {
        // Release ffi allocated memory
        // Couldn't rely on Drop trait of inner objects since it required reference to associated
        // ffi backend
        self.bsk_key.release(&mut self.hpu_hw);
        self.ksk_key.release(&mut self.hpu_hw);
        self.lut_cache.release(&mut self.hpu_hw);
        self.fw_mem.release(&mut self.hpu_hw);
        self.dyn_fw_cache.release(&mut self.hpu_hw);
        self.ct_mem.release(&mut self.hpu_hw);
    }
}
