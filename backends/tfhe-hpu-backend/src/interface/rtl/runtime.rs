//!
//! Define structure and way to read them from register for all the
//! Hpu runtime information
use super::*;

#[derive(Debug, Default)]
pub struct InfoPePbs {
    /// Bpip used
    bpip_use: bool,
    /// Bpip use opportunism
    bpip_use_opportunism: bool,
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

    /// pe_pbs IPIP flush last pbs_in_loop
    ipip_flush_last_pbs_in_loop: u16,
    /// pe_pbs BPIP batch that waits the trigger counter (Could be reset by user)
    seq_bpip_waiting_batch_cnt: u32,
    /// pe_pbs Count batch with filled with a given number of CT (Could be reset by user)
    seq_bpip_batch_filling_cnt: [u32; 16],

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

    /// pe_pbs IPIP flush CMUX counter (Could be reset by user)
    seq_ipip_flush_cnt: u32,
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

    /// pe_pbs load BSK slice reception max duration (Could be reset by user)
    load_bsk_rcp_dur: [u32; 16],
    /// pe_pbs load KSK slice reception max duration (Could be reset by user)
    load_ksk_rcp_dur: [u32; 16],

    /// pe_pbs bsk_if req_br_loop_rp
    bskif_req_br_loop_rp: u16,
    /// pe_pbs bsk_if req_br_loop_wp
    bskif_req_br_loop_wp: u16,
    /// pe_pbs bsk_if req_prf_br_loop
    bskif_req_prf_br_loop: u16,
    /// pe_pbs bsk_if req_parity
    bskif_req_parity: u8,
    /// pe_pbs bsk_if req_assigned
    bskif_req_assigned: u8,
}

impl FromRtl for InfoPePbs {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Info structure have method to update
        // Instead of redefine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

/// Add facilities once created to update/reset some fields
impl InfoPePbs {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_bpip(ffi_hw, regmap);
        self.update_loop(ffi_hw, regmap);
        self.update_pointer0(ffi_hw, regmap);
        self.update_pointer1(ffi_hw, regmap);
        self.update_pointer2(ffi_hw, regmap);
        self.update_seq_bpip_waiting_batch_cnt(ffi_hw, regmap);
        self.update_seq_bpip_batch_filling_cnt(ffi_hw, regmap);
        self.update_seq_ld_ack_cnt(ffi_hw, regmap);
        self.update_seq_cmux_not_full_batch_cnt(ffi_hw, regmap);
        self.update_seq_bpip_batch_cnt(ffi_hw, regmap);
        self.update_seq_bpip_batch_flush_cnt(ffi_hw, regmap);
        self.update_seq_bpip_batch_timeout_cnt(ffi_hw, regmap);
        self.update_seq_ipip_flush_cnt(ffi_hw, regmap);
        self.update_ldb_rcp_dur(ffi_hw, regmap);
        self.update_ldg_req_dur(ffi_hw, regmap);
        self.update_ldg_rcp_dur(ffi_hw, regmap);
        self.update_mmacc_sxt_rcp_dur(ffi_hw, regmap);
        self.update_mmacc_sxt_req_dur(ffi_hw, regmap);
        self.update_mmacc_sxt_cmd_wait_b_dur(ffi_hw, regmap);
        self.update_pep_inst_cnt(ffi_hw, regmap);
        self.update_pep_ack_cnt(ffi_hw, regmap);
        self.update_load_bsk_rcp_dur(ffi_hw, regmap);
        self.update_load_ksk_rcp_dur(ffi_hw, regmap);
        self.update_pep_bskif_req_info_0(ffi_hw, regmap);
        self.update_pep_bskif_req_info_1(ffi_hw, regmap);
    }

    pub fn update_bpip(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg_use = regmap
            .register()
            .get("bpip::use")
            .expect("Unknown register, check regmap definition");
        let val = ffi_hw.read_reg(*reg_use.offset() as u64);
        let fields = reg_use.as_field(val);
        self.bpip_use = *fields.get("use_bpip").expect("Unknown field") == 1;
        self.bpip_use_opportunism = *fields
            .get("use_opportunism")
            .expect("Unknown field opportunism")
            == 1;
        let reg_timeout = regmap
            .register()
            .get("bpip::timeout")
            .expect("Unknown register, check regmap definition");
        self.bpip_timeout = ffi_hw.read_reg(*reg_timeout.offset() as u64);
    }

    pub fn update_loop(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_cmux_loop")
            .expect("Unknown register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.br_loop = *fields.get("br_loop").expect("Unknown field") as u16;
        self.br_loop_c = *fields.get("br_loop_c").expect("Unknown field") as u8;
        self.ks_loop = *fields.get("ks_loop").expect("Unknown field") as u16;
        self.ks_loop_c = *fields.get("ks_loop_c").expect("Unknown field") as u8;
    }
    pub fn update_pointer0(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_pointer_0")
            .expect("Unknown register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.pool_rp = *fields.get("pool_rp").expect("Unknown field") as u8;
        self.pool_wp = *fields.get("pool_wp").expect("Unknown field") as u8;
        self.ldg_pt = *fields.get("ldg_pt").expect("Unknown field") as u8;
        self.ldb_pt = *fields.get("ldb_pt").expect("Unknown field") as u8;
    }

    pub fn update_pointer1(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_pointer_1")
            .expect("Unknown register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.ks_in_rp = *fields.get("ks_in_rp").expect("Unknown field") as u8;
        self.ks_in_wp = *fields.get("ks_in_wp").expect("Unknown field") as u8;
        self.ks_out_rp = *fields.get("ks_out_rp").expect("Unknown field") as u8;
        self.ks_out_wp = *fields.get("ks_out_wp").expect("Unknown field") as u8;
    }

    pub fn update_pointer2(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_pointer_2")
            .expect("Unknown register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.pbs_in_rp = *fields.get("pbs_in_rp").expect("Unknown field") as u8;
        self.pbs_in_wp = *fields.get("pbs_in_wp").expect("Unknown field") as u8;
        self.ipip_flush_last_pbs_in_loop = *fields
            .get("ipip_flush_last_pbs_in_loop")
            .expect("Unknown field") as u16;
    }

    pub fn update_seq_bpip_waiting_batch_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_bpip_waiting_batch_cnt")
            .expect("Unknown register, check regmap definition");
        self.seq_bpip_waiting_batch_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_seq_bpip_batch_filling_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        (1..16).for_each(|i| {
            let reg_name = format!("runtime_1in3::pep_seq_bpip_batch_filling_cnt_{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.seq_bpip_batch_filling_cnt[i] = ffi_hw.read_reg(*reg.offset() as u64)
        });
    }

    pub fn update_seq_ld_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_ld_ack_cnt")
            .expect("Unknown register, check regmap definition");
        self.seq_ld_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_seq_cmux_not_full_batch_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_cmux_not_full_batch_cnt")
            .expect("Unknown register, check regmap definition");
        self.seq_cmux_not_full_batch_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_seq_bpip_batch_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_bpip_batch_cnt")
            .expect("Unknown register, check regmap definition");
        self.seq_bpip_batch_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_seq_bpip_batch_flush_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_bpip_batch_flush_cnt")
            .expect("Unknown register, check regmap definition");
        self.seq_bpip_batch_flush_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_seq_bpip_batch_timeout_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_bpip_batch_timeout_cnt")
            .expect("Unknown register, check regmap definition");
        self.seq_bpip_batch_timeout_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_seq_ipip_flush_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_ipip_flush_cnt")
            .expect("Unknown register, check regmap definition");
        self.seq_ipip_flush_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_ldb_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ldb_rcp_dur")
            .expect("Unknown register, check regmap definition");
        self.ldb_rcp_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_ldg_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ldg_req_dur")
            .expect("Unknown register, check regmap definition");
        self.ldg_req_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_ldg_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ldg_rcp_dur")
            .expect("Unknown register, check regmap definition");
        self.ldg_rcp_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_mmacc_sxt_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_mmacc_sxt_rcp_dur")
            .expect("Unknown register, check regmap definition");
        self.mmacc_sxt_rcp_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_mmacc_sxt_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_mmacc_sxt_req_dur")
            .expect("Unknown register, check regmap definition");
        self.mmacc_sxt_req_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_mmacc_sxt_cmd_wait_b_dur(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_mmacc_sxt_cmd_wait_b_dur")
            .expect("Unknown register, check regmap definition");
        self.mmacc_sxt_cmd_wait_b_dur = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_pep_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_inst_cnt")
            .expect("Unknown register, check regmap definition");
        self.pep_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_load_bsk_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        (0..16).for_each(|i| {
            let reg_name = format!("runtime_3in3::pep_load_bsk_rcp_dur_pc{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.load_bsk_rcp_dur[i] = ffi_hw.read_reg(*reg.offset() as u64)
        });
    }
    pub fn update_load_ksk_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        (0..16).for_each(|i| {
            let reg_name = format!("runtime_1in3::pep_load_ksk_rcp_dur_pc{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.load_ksk_rcp_dur[i] = ffi_hw.read_reg(*reg.offset() as u64)
        });
    }

    pub fn update_pep_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ack_cnt")
            .expect("Unknown register, check regmap definition");
        self.pep_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_pep_bskif_req_info_0(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_3in3::pep_bskif_req_info_0")
            .expect("Unknown register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.bskif_req_br_loop_rp = *fields.get("req_br_loop_rp").expect("Unknown field") as u16;
        self.bskif_req_br_loop_wp = *fields.get("req_br_loop_wp").expect("Unknown field") as u16;
    }

    pub fn update_pep_bskif_req_info_1(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_3in3::pep_bskif_req_info_1")
            .expect("Unknown register, check regmap definition");
        let val = ffi_hw.read_reg(*reg.offset() as u64);
        let fields = reg.as_field(val);
        self.bskif_req_prf_br_loop = *fields.get("req_prf_br_loop").expect("Unknown field") as u16;
        self.bskif_req_parity = *fields.get("req_parity").expect("Unknown field") as u8;
        self.bskif_req_assigned = *fields.get("req_assigned").expect("Unknown field") as u8;
    }

    #[allow(unused)]
    pub fn reset(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.reset_seq_bpip_waiting_batch_cnt(ffi_hw, regmap);
        self.reset_seq_bpip_batch_filling_cnt(ffi_hw, regmap);
        self.reset_seq_ld_ack_cnt(ffi_hw, regmap);
        self.reset_seq_cmux_not_full_batch_cnt(ffi_hw, regmap);
        self.reset_seq_bpip_batch_cnt(ffi_hw, regmap);
        self.reset_seq_bpip_batch_flush_cnt(ffi_hw, regmap);
        self.reset_seq_bpip_batch_timeout_cnt(ffi_hw, regmap);
        self.reset_seq_ipip_flush_cnt(ffi_hw, regmap);
        self.reset_ldb_rcp_dur(ffi_hw, regmap);
        self.reset_ldg_req_dur(ffi_hw, regmap);
        self.reset_ldg_rcp_dur(ffi_hw, regmap);
        self.reset_mmacc_sxt_rcp_dur(ffi_hw, regmap);
        self.reset_mmacc_sxt_req_dur(ffi_hw, regmap);
        self.reset_mmacc_sxt_cmd_wait_b_dur(ffi_hw, regmap);
        self.reset_pep_inst_cnt(ffi_hw, regmap);
        self.reset_pep_ack_cnt(ffi_hw, regmap);
        self.reset_load_bsk_rcp_dur(ffi_hw, regmap);
        self.reset_load_ksk_rcp_dur(ffi_hw, regmap);
    }
    #[allow(unused)]
    pub fn reset_seq_bpip_waiting_batch_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_bpip_waiting_batch_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_seq_bpip_batch_filling_cnt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        (1..16).for_each(|i| {
            let reg_name = format!("runtime_1in3::pep_seq_bpip_batch_filling_cnt_{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            ffi_hw.write_reg(*reg.offset() as u64, 0)
        });
    }
    #[allow(unused)]
    pub fn reset_seq_ld_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_ld_ack_cnt")
            .expect("Unknown register, check regmap definition");
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
            .get("runtime_1in3::pep_seq_cmux_not_full_batch_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_seq_bpip_batch_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_bpip_batch_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_seq_bpip_batch_flush_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_bpip_batch_flush_cnt")
            .expect("Unknown register, check regmap definition");
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
            .get("runtime_1in3::pep_seq_bpip_batch_timeout_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_seq_ipip_flush_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_seq_ipip_flush_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_ldb_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ldb_rcp_dur")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_ldg_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ldg_req_dur")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_ldg_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ldg_rcp_dur")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_mmacc_sxt_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_mmacc_sxt_rcp_dur")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_mmacc_sxt_req_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_mmacc_sxt_req_dur")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_mmacc_sxt_cmd_wait_b_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_mmacc_sxt_cmd_wait_b_dur")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_pep_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_inst_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pep_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pep_ack_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_load_bsk_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        (1..16).for_each(|i| {
            let reg_name = format!("runtime_3in3::pep_load_bsk_rcp_dur_pc{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            ffi_hw.write_reg(*reg.offset() as u64, 0);
        });
    }
    #[allow(unused)]
    pub fn reset_load_ksk_rcp_dur(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        (1..16).for_each(|i| {
            let reg_name = format!("runtime_1in3::pep_load_ksk_rcp_dur_pc{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            ffi_hw.write_reg(*reg.offset() as u64, 0);
        });
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
}
impl FromRtl for InfoPeMem {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Info structure have method to update
        // Instead of redefine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

/// Add facilities once created to update/reset some fields
impl InfoPeMem {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_pem_load_inst_cnt(ffi_hw, regmap);
        self.update_pem_load_ack_cnt(ffi_hw, regmap);
        self.update_pem_store_inst_cnt(ffi_hw, regmap);
        self.update_pem_store_ack_cnt(ffi_hw, regmap);
        self.update_pem_ld_info(ffi_hw, regmap, 0);
        self.update_pem_ld_info(ffi_hw, regmap, 1);
    }

    pub fn update_pem_load_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pem_load_inst_cnt")
            .expect("Unknown register, check regmap definition");
        self.pem_load_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pem_load_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pem_load_ack_cnt")
            .expect("Unknown register, check regmap definition");
        self.pem_load_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pem_store_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pem_store_inst_cnt")
            .expect("Unknown register, check regmap definition");
        self.pem_store_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pem_store_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pem_store_ack_cnt")
            .expect("Unknown register, check regmap definition");
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
                let reg_name = format!("runtime_1in3::pem_load_info_1_pc{pc_idx}_{n}");
                let reg = regmap
                    .register()
                    .get(&reg_name)
                    .expect("Unknown register, check regmap definition");
                ffi_hw.read_reg(*reg.offset() as u64)
            })
            .fold(0_u64, |acc, v| (acc << u32::BITS) + v as u64);

        // Update value field
        (0..4).for_each(|i| {
            let reg_name = format!("runtime_1in3::pem_load_info_0_pc{pc_idx}_{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.pem_ld_info[pc_idx].data[i] = ffi_hw.read_reg(*reg.offset() as u64);
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
            .get("runtime_1in3::pem_load_inst_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pem_load_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pem_load_ack_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pem_store_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pem_store_inst_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pem_store_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pem_store_ack_cnt")
            .expect("Unknown register, check regmap definition");
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
        // Instead of redefine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

/// Add facilities once created to update/reset some fields
impl InfoPeAlu {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_pea_inst_cnt(ffi_hw, regmap);
        self.update_pea_ack_cnt(ffi_hw, regmap);
    }

    pub fn update_pea_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pea_inst_cnt")
            .expect("Unknown register, check regmap definition");
        self.pea_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_pea_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pea_ack_cnt")
            .expect("Unknown register, check regmap definition");
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
            .get("runtime_1in3::pea_inst_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
    #[allow(unused)]
    pub fn reset_pea_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::pea_ack_cnt")
            .expect("Unknown register, check regmap definition");
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
        // Instead of redefine parsing here, use a default construct and update methods
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

/// Add facilities once created to update/reset some fields
impl InfoIsc {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_isc_inst_cnt(ffi_hw, regmap);
        self.update_isc_ack_cnt(ffi_hw, regmap);
        self.update_isc_info(ffi_hw, regmap);
    }

    pub fn update_isc_inst_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::isc_inst_cnt")
            .expect("Unknown register, check regmap definition");
        self.isc_inst_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_isc_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::isc_ack_cnt")
            .expect("Unknown register, check regmap definition");
        self.isc_ack_cnt = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_isc_info(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        for idx in 0..4 {
            let name = format!("runtime_1in3::isc_latest_instruction_{idx}");
            let reg = regmap
                .register()
                .get(&name)
                .expect("Unknown register, check regmap definition");
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
            .get("runtime_1in3::isc_inst_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }

    #[allow(unused)]
    pub fn reset_isc_ack_cnt(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("runtime_1in3::isc_ack_cnt")
            .expect("Unknown register, check regmap definition");
        ffi_hw.write_reg(*reg.offset() as u64, 0);
    }
}

#[derive(Debug, Default)]
pub struct ErrorHpu {
    error_1in3: u32,
    error_3in3: u32,
}
impl FromRtl for ErrorHpu {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Info structure have method to update
        // Instead of redefine parsing here, use a default construct and update methods
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

impl ErrorHpu {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        self.update_error_1in3(ffi_hw, regmap);
        self.update_error_3in3(ffi_hw, regmap);
    }

    pub fn update_error_1in3(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("status_1in3::error")
            .expect("Unknown register, check regmap definition");
        self.error_1in3 = ffi_hw.read_reg(*reg.offset() as u64);
    }

    pub fn update_error_3in3(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("status_3in3::error")
            .expect("Unknown register, check regmap definition");
        self.error_3in3 = ffi_hw.read_reg(*reg.offset() as u64);
    }
}
