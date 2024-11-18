//!
//! Define structure and way to read them from register for all the
//! Hpu runtime information
use super::*;

#[derive(Debug, Default)]
pub struct InfoPePbs {
    /// Bpip used
    bpip_used: bool,
    /// Bpip timeout
    bpip_timeout: u32,

    /// PBS current BR-loop
    br_loop: u16,
    /// PBS current BR-loop parity
    br_loop_c: u8,

    /// KS current KS-loop
    ks_loop: u16,
    /// KS current BR-loop parity
    ks_loop_c: u8,

    /// pe_pbs pool_rp
    pool_rp: u8,
    /// pe_pbs pool_wp
    pool_wp: u8,
    /// pe_pbs ldg_pt
    ldg_pt: u8,
    /// pe_pbs ldb_pt
    ldb_pt: u8,

    /// pe_pbs ks_in_rp
    ks_in_rp: u8,
    /// pe_pbs ks_in_wp
    ks_in_wp: u8,
    /// pe_pbs ks_out_rp
    ks_out_rp: u8,
    /// pe_pbs ks_out_wp
    ks_out_wp: u8,
    /// pe_pbs pbs_in_rp
    pbs_in_rp: u8,
    /// pe_pbs pbs_in_wp
    pbs_in_wp: u8,

    /// pe_pbs ack counter (Could be reset by user)
    seq_ld_ack_cnt: u32,

    /// pe_pbs not full batch CMUX counter (Could be reset by user)
    seq_cmux_not_full_batch_cnt: u32,

    /// pe_pbs BPIP batch counter (Could be reset by user)
    seq_bpip_batch_cnt: u32,
    /// pe_pbs BPIP batch triggered with a flush counter (Could be reset by user)
    seq_bpip_batch_flush_cnt: u32,
    /// pe_pbs BPIP batch triggered with a timeout counter (Could be reset by user)
    seq_bpip_batch_timeout_cnt: u32,

    /// pe_pbs load BLWE reception max duration (Could be reset by user)
    ldb_rcp_dur: u32,
    /// pe_pbs load GLWE request max duration (Could be reset by user)
    ldg_req_dur: u32,
    /// pe_pbs load GLWE reception max duration (Could be reset by user)
    ldg_rcp_dur: u32,
    /// pe_pbs MMACC SXT reception duration (Could be reset by user)
    mmacc_sxt_rcp_dur: u32,

    /// pe_pbs MMACC SXT request duration (Could be reset by user)
    mmacc_sxt_req_dur: u32,
    /// pe_pbs MMACC SXT command without b duration (Could be reset by user)
    mmacc_sxt_cmd_wait_b_dur: u32,

    /// PEP input instruction counter (Could be reset by user)
    pep_inst_cnt: u32,
    /// PEP instruction acknowledge counter (Could be reset by user)
    pep_ack_cnt: u32,
}

impl FromRtl for InfoPePbs {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Info structure have method to update
        // Instead of redifine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

/// Add facilites once created to update/reset some fields
impl InfoPePbs {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_bpip(ffi_hw, regmap);
        self.update_loop(ffi_hw, regmap);
        self.update_pointer0(ffi_hw, regmap);
        self.update_pointer1(ffi_hw, regmap);
        self.update_pointer2(ffi_hw, regmap);
        self.update_seq_ld_ack_cnt(ffi_hw, regmap);
        self.update_seq_cmux_not_full_batch_cnt(ffi_hw, regmap);
        self.update_seq_bpip_batch_cnt(ffi_hw, regmap);
        self.update_seq_bpip_batch_flush_cnt(ffi_hw, regmap);
        self.update_seq_bpip_batch_timeout_cnt(ffi_hw, regmap);
        self.update_ldb_rcp_dur(ffi_hw, regmap);
        self.update_ldg_req_dur(ffi_hw, regmap);
        self.update_ldg_rcp_dur(ffi_hw, regmap);
        self.update_mmacc_sxt_rcp_dur(ffi_hw, regmap);
        self.update_mmacc_sxt_req_dur(ffi_hw, regmap);
        self.update_mmacc_sxt_cmd_wait_b_dur(ffi_hw, regmap);
        self.update_pep_inst_cnt(ffi_hw, regmap);
        self.update_pep_ack_cnt(ffi_hw, regmap);
    }

    pub fn update_bpip(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg_use = regmap
            .register()
            .get("Bpip::use")
            .expect("Unknow register, check regmap definition");
        self.bpip_used = ffi_hw.read_reg(*reg_use.offset() as u64) != 0;
        let reg_timeout = regmap
            .register()
            .get("Bpip::timeout")
            .expect("Unknow register, check regmap definition");
        self.bpip_timeout = ffi_hw.read_reg(*reg_timeout.offset() as u64) as u32;
    }

    pub fn update_loop(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::infos_loop")
            .expect("Unknow register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.br_loop = *fields.get("br_loop").expect("Unknow field") as u16;
        self.br_loop_c = *fields.get("br_loop_c").expect("Unknow field") as u8;
        self.ks_loop = *fields.get("ks_loop").expect("Unknow field") as u16;
        self.ks_loop_c = *fields.get("ks_loop_c").expect("Unknow field") as u8;
    }
    pub fn update_pointer0(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::infos_pointer0")
            .expect("Unknow register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.pool_rp = *fields.get("pool_rp").expect("Unknow field") as u8;
        self.pool_wp = *fields.get("pool_wp").expect("Unknow field") as u8;
        self.ldg_pt = *fields.get("ldg_pt").expect("Unknow field") as u8;
        self.ldb_pt = *fields.get("ldb_pt").expect("Unknow field") as u8;
    }

    pub fn update_pointer1(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::infos_pointer1")
            .expect("Unknow register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.ks_in_rp = *fields.get("ks_in_rp").expect("Unknow field") as u8;
        self.ks_in_wp = *fields.get("ks_in_wp").expect("Unknow field") as u8;
        self.ks_out_rp = *fields.get("ks_out_rp").expect("Unknow field") as u8;
        self.ks_out_wp = *fields.get("ks_out_wp").expect("Unknow field") as u8;
    }

    pub fn update_pointer2(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::infos_pointer2")
            .expect("Unknow register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.pbs_in_rp = *fields.get("pbs_in_rp").expect("Unknow field") as u8;
        self.pbs_in_wp = *fields.get("pbs_in_wp").expect("Unknow field") as u8;
    }

    pub fn update_seq_ld_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_ld_ack_cnt")
            .expect("Unknow register, check regmap definition");
        self.seq_ld_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_seq_cmux_not_full_batch_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_cmux_not_full_batch_cnt")
            .expect("Unknow register, check regmap definition");
        self.seq_cmux_not_full_batch_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_seq_bpip_batch_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_bpip_batch_cnt")
            .expect("Unknow register, check regmap definition");
        self.seq_bpip_batch_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_seq_bpip_batch_flush_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_bpip_batch_flush_cnt")
            .expect("Unknow register, check regmap definition");
        self.seq_bpip_batch_flush_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_seq_bpip_batch_timeout_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_bpip_batch_timeout_cnt")
            .expect("Unknow register, check regmap definition");
        self.seq_bpip_batch_timeout_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_ldb_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ldb_rcp_dur")
            .expect("Unknow register, check regmap definition");
        self.ldb_rcp_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_ldg_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ldg_req_dur")
            .expect("Unknow register, check regmap definition");
        self.ldg_req_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_ldg_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ldg_rcp_dur")
            .expect("Unknow register, check regmap definition");
        self.ldg_rcp_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_mmacc_sxt_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_mmacc_sxt_rcp_dur")
            .expect("Unknow register, check regmap definition");
        self.mmacc_sxt_rcp_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_mmacc_sxt_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_mmacc_sxt_req_dur")
            .expect("Unknow register, check regmap definition");
        self.mmacc_sxt_req_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_mmacc_sxt_cmd_wait_b_dur(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("Runtime::pep_mmacc_sxt_cmd_wait_b_dur")
            .expect("Unknow register, check regmap definition");
        self.mmacc_sxt_cmd_wait_b_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_pep_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_inst_cnt")
            .expect("Unknow register, check regmap definition");
        self.pep_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pep_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ack_cnt")
            .expect("Unknow register, check regmap definition");
        self.pep_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    #[allow(unused)]
    pub fn reset(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.reset_seq_ld_ack_cnt(ffi_hw, regmap);
        self.reset_seq_cmux_not_full_batch_cnt(ffi_hw, regmap);
        self.reset_seq_bpip_batch_cnt(ffi_hw, regmap);
        self.reset_seq_bpip_batch_flush_cnt(ffi_hw, regmap);
        self.reset_seq_bpip_batch_timeout_cnt(ffi_hw, regmap);
        self.reset_ldb_rcp_dur(ffi_hw, regmap);
        self.reset_ldg_req_dur(ffi_hw, regmap);
        self.reset_ldg_rcp_dur(ffi_hw, regmap);
        self.reset_mmacc_sxt_rcp_dur(ffi_hw, regmap);
        self.reset_mmacc_sxt_req_dur(ffi_hw, regmap);
        self.reset_mmacc_sxt_cmd_wait_b_dur(ffi_hw, regmap);
        self.reset_pep_inst_cnt(ffi_hw, regmap);
        self.reset_pep_ack_cnt(ffi_hw, regmap);
    }
    #[allow(unused)]
    pub fn reset_seq_ld_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_ld_ack_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_seq_cmux_not_full_batch_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_cmux_not_full_batch_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_seq_bpip_batch_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_bpip_batch_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_seq_bpip_batch_flush_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_bpip_batch_flush_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_seq_bpip_batch_timeout_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("Runtime::pep_seq_bpip_batch_timeout_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_ldb_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ldb_rcp_dur")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_ldg_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ldg_req_dur")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_ldg_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ldg_rcp_dur")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_mmacc_sxt_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_mmacc_sxt_rcp_dur")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_mmacc_sxt_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_mmacc_sxt_req_dur")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_mmacc_sxt_cmd_wait_b_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_mmacc_sxt_cmd_wait_b_dur")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_pep_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_inst_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pep_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pep_ack_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
}

#[derive(Default)]
pub struct PeMemInfo {
    addr: u64,
    data: [u32; 4],
}
impl std::fmt::Debug for PeMemInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{addr: {:x}, data: {:0>8x?}}}", self.addr, self.data)
    }
}

#[derive(Debug, Default)]
pub struct InfoPeMem {
    /// PEM load input instruction counter (Could be reset by user)
    pem_load_inst_cnt: u32,
    /// PEM load instruction acknowledge counter (Could be reset by user)
    pem_load_ack_cnt: u32,
    /// PEM store input instruction counter (Could be reset by user)
    pem_store_inst_cnt: u32,
    /// PEM store instruction acknowledge counter (Could be reset by user)
    pem_store_ack_cnt: u32,
    /// PEM load first addr/data
    pem_ld_info: [PeMemInfo; 2],
    /// PEM store first addr/data
    pem_st_info: [PeMemInfo; 2],
}
impl FromRtl for InfoPeMem {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Info structure have method to update
        // Instead of redifine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

/// Add facilites once created to update/reset some fields
impl InfoPeMem {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_pem_load_inst_cnt(ffi_hw, regmap);
        self.update_pem_load_ack_cnt(ffi_hw, regmap);
        self.update_pem_store_inst_cnt(ffi_hw, regmap);
        self.update_pem_store_ack_cnt(ffi_hw, regmap);
        self.update_pem_ld_info(ffi_hw, regmap, 0);
        self.update_pem_ld_info(ffi_hw, regmap, 1);
        //self.update_pem_st_info(ffi_hw, regmap, 0);
        //self.update_pem_st_info(ffi_hw, regmap, 1);
    }

    pub fn update_pem_load_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_load_inst_cnt")
            .expect("Unknow register, check regmap definition");
        self.pem_load_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pem_load_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_load_ack_cnt")
            .expect("Unknow register, check regmap definition");
        self.pem_load_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pem_store_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_store_inst_cnt")
            .expect("Unknow register, check regmap definition");
        self.pem_store_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pem_store_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_store_ack_cnt")
            .expect("Unknow register, check regmap definition");
        self.pem_store_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pem_ld_info(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
        pc_idx: usize,
    ) {
        // Update addr field
        self.pem_ld_info[pc_idx].addr = ["msb", "lsb"]
            .iter()
            .map(|n| {
                let reg_name = format!("Runtime::pem_load_info_1_pc{pc_idx}_{n}");
                let reg = regmap
                    .register()
                    .get(&reg_name)
                    .expect("Unknow register, check regmap definition");
                ffi_hw.read_reg(*reg.offset() as u64)
            })
            .fold(0_u64, |acc, v| (acc << u32::BITS) + v as u64);

        // Update value field
        (0..4).for_each(|i| {
            let reg_name = format!("Runtime::pem_load_info_0_pc{pc_idx}_{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknow register, check regmap definition");
            self.pem_ld_info[pc_idx].data[i] = ffi_hw.read_reg(*reg.offset() as u64);
        });
    }

    pub fn update_pem_st_info(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
        pc_idx: usize,
    ) {
        // Update addr field
        self.pem_st_info[pc_idx].addr = ["msb", "lsb"]
            .iter()
            .map(|n| {
                let reg_name = format!("Runtime::pem_store_info_1_pc{pc_idx}_{n}");
                let reg = regmap
                    .register()
                    .get(&reg_name)
                    .expect("Unknow register, check regmap definition");
                ffi_hw.read_reg(*reg.offset() as u64)
            })
            .fold(0_u64, |acc, v| (acc << u32::BITS) + v as u64);

        // Update value field
        (0..4).for_each(|i| {
            let reg_name = format!("Runtime::pem_store_info_0_pc{pc_idx}_{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknow register, check regmap definition");
            self.pem_st_info[pc_idx].data[i] = ffi_hw.read_reg(*reg.offset() as u64);
        });
    }

    #[allow(unused)]
    pub fn reset(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.reset_pem_load_inst_cnt(ffi_hw, regmap);
        self.reset_pem_load_ack_cnt(ffi_hw, regmap);
        self.reset_pem_store_inst_cnt(ffi_hw, regmap);
        self.reset_pem_store_ack_cnt(ffi_hw, regmap);
    }
    #[allow(unused)]
    pub fn reset_pem_load_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_load_inst_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pem_load_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_load_ack_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pem_store_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_store_inst_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pem_store_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pem_store_ack_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
}
#[derive(Debug, Default)]
pub struct InfoPeAlu {
    /// PEA input instruction counter (Could be reset by user)
    pea_inst_cnt: u32,
    /// PEA instruction acknowledge counter (Could be reset by user)
    pea_ack_cnt: u32,
}
impl FromRtl for InfoPeAlu {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Info structure have method to update
        // Instead of redifine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

/// Add facilites once created to update/reset some fields
impl InfoPeAlu {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_pea_inst_cnt(ffi_hw, regmap);
        self.update_pea_ack_cnt(ffi_hw, regmap);
    }

    pub fn update_pea_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pea_inst_cnt")
            .expect("Unknow register, check regmap definition");
        self.pea_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pea_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pea_ack_cnt")
            .expect("Unknow register, check regmap definition");
        self.pea_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    #[allow(unused)]
    pub fn reset(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.reset_pea_inst_cnt(ffi_hw, regmap);
        self.reset_pea_ack_cnt(ffi_hw, regmap);
    }
    #[allow(unused)]
    pub fn reset_pea_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pea_inst_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pea_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::pea_ack_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
}

#[derive(Default)]
pub struct InfoIsc {
    /// ISC input instruction counter (Could be reset by user)
    isc_inst_cnt: u32,
    /// ISC instruction acknowledge sample counter (Could be reset by user)
    isc_ack_cnt: u32,

    /// ISC 4 latest instructions received ([0] is the most recent)
    isc_info: [u32; 4],
}

impl FromRtl for InfoIsc {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Info structure have method to update
        // Instead of redifine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

impl std::fmt::Debug for InfoIsc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{isc_inst_cnt: {}, isc_ack_cnt: {}, isc_info: {:x?}}}",
            self.isc_inst_cnt, self.isc_ack_cnt, self.isc_info
        )
    }
}

/// Add facilites once created to update/reset some fields
impl InfoIsc {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_isc_inst_cnt(ffi_hw, regmap);
        self.update_isc_ack_cnt(ffi_hw, regmap);
        self.update_isc_info(ffi_hw, regmap);
    }

    pub fn update_isc_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::isc_inst_cnt")
            .expect("Unknow register, check regmap definition");
        self.isc_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_isc_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::isc_ack_cnt")
            .expect("Unknow register, check regmap definition");
        self.isc_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_isc_info(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        for idx in 0..4 {
            let name = format!("Runtime::isc_info_{idx}");
            let reg = regmap
                .register()
                .get(&name)
                .expect("Unknow register, check regmap definition");
            self.isc_info[idx] = ffi_hw.read_reg(*reg.offset() as u64);
        }
    }

    #[allow(unused)]
    pub fn reset(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.reset_isc_inst_cnt(ffi_hw, regmap);
        self.reset_isc_ack_cnt(ffi_hw, regmap);
    }

    #[allow(unused)]
    pub fn reset_isc_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::isc_inst_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_isc_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("Runtime::isc_ack_cnt")
            .expect("Unknow register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
}

#[derive(Debug)]
pub struct ErrorHpu(#[allow(unused)] u16);

impl FromRtl for ErrorHpu {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let reg = regmap
            .register()
            .get("Runtime::errors")
            .expect("Unknow register, check regmap definition");
        Self(ffi_hw.read_reg(*reg.offset() as u64) as u16)
    }
}
