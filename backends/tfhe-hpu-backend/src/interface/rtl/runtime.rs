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

// =====================================================================================================================
// MhDma register section
// Covers all registers defined in hpu_regif_core_mhdma_2in3.toml:
//   mhdma_system, mhdma_reset, mhdma_request (stats), mhdma_lane, mhdma_hbm_axi4_addr_2in3
// =====================================================================================================================
#[derive(Default)]
pub struct InfoMhDma {
    // --- mhdma_system ---
    lane: u32,
    timeout_notify: u32,
    timeout_read_req: u32,
    retry_max: u32,
    fsm_value: u32,
    errors: u32,
    hpu_id: [u32; 8],

    // --- mhdma_reset ---
    datapath: u32,
    monitor: u32,

    // --- mhdma_request: completion descriptors ---
    notify_req_id: u32,
    notify_req_addr: u32,
    read_request_req_id: u32,
    read_request: u32,

    // --- mhdma_request: TX statistics ---
    stat_notify: u32,
    stat_notify_ack: u32,
    stat_notify_timeout_retry: u32,
    stat_read_req_timeout_retry: u32,
    stat_read_req_seq_num_retry: u32,
    stat_nb_notify_sent: u32,
    stat_nb_ce_sent: u32,
    stat_nb_notify_ack_sent: u32,
    stat_nb_read_req_sent: u32,

    // --- mhdma_request: RX statistics ---
    stat_nb_nack_received: u32,
    stat_nb_notify_received: u32,
    stat_nb_read_req_received: u32,
    stat_nb_ce_received: u32,
    stat_nb_decoder_dropped: u32,

    // --- mhdma_request: HBM / data-path statistics ---
    stat_nb_read_to_hbm: u32,
    stat_nb_words_received_pc: [u32; 2],
    stat_nb_ce_words_received: u32,
    stat_cnt_nb_write_complete: u32,
    stat_physical_addr: [u32; 4],

    // --- mhdma_request: latency statistics ---
    stat_t_notify_to_ack: u32,
    stat_t_notify_to_ack_max: u32,
    stat_t_notify_to_ack_min: u32,
    stat_t_rr_to_ce_received: u32,
    stat_t_rr_to_ce_received_max: u32,
    stat_t_rr_to_ce_received_min: u32,
    stat_t_ce_first_to_last_pkt: u32,
    stat_t_rr_wait_words_pc: [u32; 2],
    stat_cur_notify_to_ack: u32,
    stat_t_hbm_write_latency: u32,
    stat_t_hbm_write_latency_max: u32,
    stat_t_hbm_write_latency_min: u32,

    // --- mhdma_lane ---
    lane_debug: u32,

    // --- mhdma_hbm_axi4_addr_2in3 ---
    ct_addr: [u32; 4],
}

impl std::fmt::Debug for InfoMhDma {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfoMhDma")
            // system
            .field("lane", &format_args!("{:#010x}", self.lane))
            .field("timeout_notify", &self.timeout_notify)
            .field("timeout_read_req", &self.timeout_read_req)
            .field("retry_max", &format_args!("{:#010x}", self.retry_max))
            .field("fsm_value", &format_args!("{:#010x}", self.fsm_value))
            .field("errors", &format_args!("{:#010x}", self.errors))
            .field("hpu_id", &self.hpu_id.map(|v| format!("{v:#010x}")))
            // reset
            .field("datapath", &format_args!("{:#010x}", self.datapath))
            .field("monitor", &format_args!("{:#010x}", self.monitor))
            // completion descriptors
            .field(
                "notify_req_id",
                &format_args!("{:#010x}", self.notify_req_id),
            )
            .field(
                "notify_req_addr",
                &format_args!("{:#010x}", self.notify_req_addr),
            )
            .field(
                "read_request_req_id",
                &format_args!("{:#010x}", self.read_request_req_id),
            )
            .field("read_request", &format_args!("{:#010x}", self.read_request))
            // TX stats
            .field("stat_notify", &self.stat_notify)
            .field("stat_notify_ack", &self.stat_notify_ack)
            .field("stat_notify_timeout_retry", &self.stat_notify_timeout_retry)
            .field(
                "stat_read_req_timeout_retry",
                &self.stat_read_req_timeout_retry,
            )
            .field(
                "stat_read_req_seq_num_retry",
                &self.stat_read_req_seq_num_retry,
            )
            .field("stat_nb_notify_sent", &self.stat_nb_notify_sent)
            .field("stat_nb_ce_sent", &self.stat_nb_ce_sent)
            .field("stat_nb_notify_ack_sent", &self.stat_nb_notify_ack_sent)
            .field("stat_nb_read_req_sent", &self.stat_nb_read_req_sent)
            // RX stats
            .field("stat_nb_nack_received", &self.stat_nb_nack_received)
            .field("stat_nb_notify_received", &self.stat_nb_notify_received)
            .field("stat_nb_read_req_received", &self.stat_nb_read_req_received)
            .field("stat_nb_ce_received", &self.stat_nb_ce_received)
            .field("stat_nb_decoder_dropped", &self.stat_nb_decoder_dropped)
            // HBM / data-path stats
            .field("stat_nb_read_to_hbm", &self.stat_nb_read_to_hbm)
            .field("stat_nb_words_received_pc", &self.stat_nb_words_received_pc)
            .field("stat_nb_ce_words_received", &self.stat_nb_ce_words_received)
            .field(
                "stat_cnt_nb_write_complete",
                &self.stat_cnt_nb_write_complete,
            )
            .field(
                "stat_physical_addr",
                &self.stat_physical_addr.map(|v| format!("{v:#010x}")),
            )
            // latency stats
            .field("stat_t_notify_to_ack", &self.stat_t_notify_to_ack)
            .field("stat_t_notify_to_ack_max", &self.stat_t_notify_to_ack_max)
            .field("stat_t_notify_to_ack_min", &self.stat_t_notify_to_ack_min)
            .field("stat_t_rr_to_ce_received", &self.stat_t_rr_to_ce_received)
            .field(
                "stat_t_rr_to_ce_received_max",
                &self.stat_t_rr_to_ce_received_max,
            )
            .field(
                "stat_t_rr_to_ce_received_min",
                &self.stat_t_rr_to_ce_received_min,
            )
            .field(
                "stat_t_ce_first_to_last_pkt",
                &self.stat_t_ce_first_to_last_pkt,
            )
            .field("stat_t_rr_wait_words_pc", &self.stat_t_rr_wait_words_pc)
            .field("stat_cur_notify_to_ack", &self.stat_cur_notify_to_ack)
            .field("stat_t_hbm_write_latency", &self.stat_t_hbm_write_latency)
            .field(
                "stat_t_hbm_write_latency_max",
                &self.stat_t_hbm_write_latency_max,
            )
            .field(
                "stat_t_hbm_write_latency_min",
                &self.stat_t_hbm_write_latency_min,
            )
            // lane debug
            .field("lane_debug", &format_args!("{:#010x}", self.lane_debug))
            // HBM addresses
            .field("ct_addr", &self.ct_addr.map(|v| format!("{v:#010x}")))
            .finish()
    }
}

impl FromRtl for InfoMhDma {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let mut infos = Self::default();
        infos.update(ffi_hw, regmap);
        infos
    }
}

impl InfoMhDma {
    pub fn update(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        // system
        self.update_lane(ffi_hw, regmap);
        self.update_timeout_notify(ffi_hw, regmap);
        self.update_timeout_read_req(ffi_hw, regmap);
        self.update_retry_max(ffi_hw, regmap);
        self.update_fsm_value(ffi_hw, regmap);
        self.update_errors(ffi_hw, regmap);
        self.update_hpu_id(ffi_hw, regmap);
        // reset
        self.update_datapath(ffi_hw, regmap);
        self.update_monitor(ffi_hw, regmap);
        // completion descriptors
        self.update_notify_req_id(ffi_hw, regmap);
        self.update_notify_req_addr(ffi_hw, regmap);
        self.update_read_request_req_id(ffi_hw, regmap);
        self.update_read_request(ffi_hw, regmap);
        // TX stats
        self.update_stat_notify(ffi_hw, regmap);
        self.update_stat_notify_ack(ffi_hw, regmap);
        self.update_stat_notify_timeout_retry(ffi_hw, regmap);
        self.update_stat_read_req_timeout_retry(ffi_hw, regmap);
        self.update_stat_read_req_seq_num_retry(ffi_hw, regmap);
        self.update_stat_nb_notify_sent(ffi_hw, regmap);
        self.update_stat_nb_ce_sent(ffi_hw, regmap);
        self.update_stat_nb_notify_ack_sent(ffi_hw, regmap);
        self.update_stat_nb_read_req_sent(ffi_hw, regmap);
        // RX stats
        self.update_stat_nb_nack_received(ffi_hw, regmap);
        self.update_stat_nb_notify_received(ffi_hw, regmap);
        self.update_stat_nb_read_req_received(ffi_hw, regmap);
        self.update_stat_nb_ce_received(ffi_hw, regmap);
        self.update_stat_nb_decoder_dropped(ffi_hw, regmap);
        // HBM / data-path stats
        self.update_stat_nb_read_to_hbm(ffi_hw, regmap);
        self.update_stat_nb_words_received_pc(ffi_hw, regmap);
        self.update_stat_nb_ce_words_received(ffi_hw, regmap);
        self.update_stat_cnt_nb_write_complete(ffi_hw, regmap);
        self.update_stat_physical_addr(ffi_hw, regmap);
        // latency stats
        self.update_stat_t_notify_to_ack(ffi_hw, regmap);
        self.update_stat_t_notify_to_ack_max(ffi_hw, regmap);
        self.update_stat_t_notify_to_ack_min(ffi_hw, regmap);
        self.update_stat_t_rr_to_ce_received(ffi_hw, regmap);
        self.update_stat_t_rr_to_ce_received_max(ffi_hw, regmap);
        self.update_stat_t_rr_to_ce_received_min(ffi_hw, regmap);
        self.update_stat_t_ce_first_to_last_pkt(ffi_hw, regmap);
        self.update_stat_t_rr_wait_words_pc(ffi_hw, regmap);
        self.update_stat_cur_notify_to_ack(ffi_hw, regmap);
        self.update_stat_t_hbm_write_latency(ffi_hw, regmap);
        self.update_stat_t_hbm_write_latency_max(ffi_hw, regmap);
        self.update_stat_t_hbm_write_latency_min(ffi_hw, regmap);
        // lane debug
        self.update_lane_debug(ffi_hw, regmap);
        // HBM addresses
        self.update_ct_addr(ffi_hw, regmap);
    }

    // --- mhdma_system ---
    pub fn update_lane(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_system::lane")
            .expect("Unknown register, check regmap definition");
        self.lane = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_timeout_notify(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_system::timeout_notify")
            .expect("Unknown register, check regmap definition");
        self.timeout_notify = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_timeout_read_req(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_system::timeout_read_req")
            .expect("Unknown register, check regmap definition");
        self.timeout_read_req = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_retry_max(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_system::retry_max")
            .expect("Unknown register, check regmap definition");
        self.retry_max = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_fsm_value(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_system::fsm_value")
            .expect("Unknown register, check regmap definition");
        self.fsm_value = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_errors(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_system::errors")
            .expect("Unknown register, check regmap definition");
        self.errors = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_hpu_id(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        for i in 0..8_usize {
            let reg_name = format!("mhdma_system::hpu_id_{i}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.hpu_id[i] = ffi_hw.read_reg(*reg.offset() as u64);
        }
    }

    // --- mhdma_reset ---
    pub fn update_datapath(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_reset::datapath")
            .expect("Unknown register, check regmap definition");
        self.datapath = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_monitor(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_reset::monitor")
            .expect("Unknown register, check regmap definition");
        self.monitor = ffi_hw.read_reg(*reg.offset() as u64);
    }

    // --- mhdma_request: completion descriptors ---
    pub fn update_notify_req_id(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::notify_req_id")
            .expect("Unknown register, check regmap definition");
        self.notify_req_id = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_notify_req_addr(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::notify_req_addr")
            .expect("Unknown register, check regmap definition");
        self.notify_req_addr = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_read_request_req_id(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::read_request_req_id")
            .expect("Unknown register, check regmap definition");
        self.read_request_req_id = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_read_request(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::read_request")
            .expect("Unknown register, check regmap definition");
        self.read_request = ffi_hw.read_reg(*reg.offset() as u64);
    }

    // --- mhdma_request: TX statistics ---
    pub fn update_stat_notify(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_notify")
            .expect("Unknown register, check regmap definition");
        self.stat_notify = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_notify_ack(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_notify_ack")
            .expect("Unknown register, check regmap definition");
        self.stat_notify_ack = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_notify_timeout_retry(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_notify_timeout_retry")
            .expect("Unknown register, check regmap definition");
        self.stat_notify_timeout_retry = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_read_req_timeout_retry(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_read_req_timeout_retry")
            .expect("Unknown register, check regmap definition");
        self.stat_read_req_timeout_retry = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_read_req_seq_num_retry(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_read_req_seq_num_retry")
            .expect("Unknown register, check regmap definition");
        self.stat_read_req_seq_num_retry = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_notify_sent(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_notify_sent")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_notify_sent = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_ce_sent(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_ce_sent")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_ce_sent = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_notify_ack_sent(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_notify_ack_sent")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_notify_ack_sent = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_read_req_sent(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_read_req_sent")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_read_req_sent = ffi_hw.read_reg(*reg.offset() as u64);
    }

    // --- mhdma_request: RX statistics ---
    pub fn update_stat_nb_nack_received(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_nack_received")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_nack_received = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_notify_received(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_notify_received")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_notify_received = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_read_req_received(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_read_req_received")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_read_req_received = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_ce_received(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_ce_received")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_ce_received = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_decoder_dropped(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_decoder_dropped")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_decoder_dropped = ffi_hw.read_reg(*reg.offset() as u64);
    }

    // --- mhdma_request: HBM / data-path statistics ---
    pub fn update_stat_nb_read_to_hbm(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_read_to_hbm")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_read_to_hbm = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_nb_words_received_pc(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        for (i, suffix) in ["_pc0", "_pc1"].iter().enumerate() {
            let reg_name = format!("mhdma_request::stat_nb_words_received_pc{suffix}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.stat_nb_words_received_pc[i] = ffi_hw.read_reg(*reg.offset() as u64);
        }
    }
    pub fn update_stat_nb_ce_words_received(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_nb_ce_words_received")
            .expect("Unknown register, check regmap definition");
        self.stat_nb_ce_words_received = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_cnt_nb_write_complete(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_cnt_nb_write_complete")
            .expect("Unknown register, check regmap definition");
        self.stat_cnt_nb_write_complete = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_physical_addr(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        for (i, suffix) in ["_pc0_lsb", "_pc0_msb", "_pc1_lsb", "_pc1_msb"]
            .iter()
            .enumerate()
        {
            let reg_name = format!("mhdma_request::stat_physical_addr{suffix}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.stat_physical_addr[i] = ffi_hw.read_reg(*reg.offset() as u64);
        }
    }

    // --- mhdma_request: latency statistics ---
    pub fn update_stat_t_notify_to_ack(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_notify_to_ack")
            .expect("Unknown register, check regmap definition");
        self.stat_t_notify_to_ack = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_notify_to_ack_max(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_notify_to_ack_max")
            .expect("Unknown register, check regmap definition");
        self.stat_t_notify_to_ack_max = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_notify_to_ack_min(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_notify_to_ack_min")
            .expect("Unknown register, check regmap definition");
        self.stat_t_notify_to_ack_min = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_rr_to_ce_received(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_rr_to_ce_received")
            .expect("Unknown register, check regmap definition");
        self.stat_t_rr_to_ce_received = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_rr_to_ce_received_max(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_rr_to_ce_received_max")
            .expect("Unknown register, check regmap definition");
        self.stat_t_rr_to_ce_received_max = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_rr_to_ce_received_min(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_rr_to_ce_received_min")
            .expect("Unknown register, check regmap definition");
        self.stat_t_rr_to_ce_received_min = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_ce_first_to_last_pkt(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_ce_first_to_last_pkt")
            .expect("Unknown register, check regmap definition");
        self.stat_t_ce_first_to_last_pkt = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_rr_wait_words_pc(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        for (i, suffix) in ["_pc0", "_pc1"].iter().enumerate() {
            let reg_name = format!("mhdma_request::stat_t_rr_wait_words_pc{suffix}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.stat_t_rr_wait_words_pc[i] = ffi_hw.read_reg(*reg.offset() as u64);
        }
    }
    pub fn update_stat_cur_notify_to_ack(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_cur_notify_to_ack")
            .expect("Unknown register, check regmap definition");
        self.stat_cur_notify_to_ack = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_hbm_write_latency(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_hbm_write_latency")
            .expect("Unknown register, check regmap definition");
        self.stat_t_hbm_write_latency = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_hbm_write_latency_max(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_hbm_write_latency_max")
            .expect("Unknown register, check regmap definition");
        self.stat_t_hbm_write_latency_max = ffi_hw.read_reg(*reg.offset() as u64);
    }
    pub fn update_stat_t_hbm_write_latency_min(
        &mut self,
        ffi_hw: &mut ffi::HpuHw,
        regmap: &FlatRegmap,
    ) {
        let reg = regmap
            .register()
            .get("mhdma_request::stat_t_hbm_write_latency_min")
            .expect("Unknown register, check regmap definition");
        self.stat_t_hbm_write_latency_min = ffi_hw.read_reg(*reg.offset() as u64);
    }

    // --- mhdma_lane ---
    pub fn update_lane_debug(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        let reg = regmap
            .register()
            .get("mhdma_lane::debug")
            .expect("Unknown register, check regmap definition");
        self.lane_debug = ffi_hw.read_reg(*reg.offset() as u64);
    }

    // --- mhdma_hbm_axi4_addr_2in3 ---
    pub fn update_ct_addr(&mut self, ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
        for (i, suffix) in ["_pc0_lsb", "_pc0_msb", "_pc1_lsb", "_pc1_msb"]
            .iter()
            .enumerate()
        {
            let reg_name = format!("mhdma_hbm_axi4_addr_2in3::ct{suffix}");
            let reg = regmap
                .register()
                .get(&reg_name)
                .expect("Unknown register, check regmap definition");
            self.ct_addr[i] = ffi_hw.read_reg(*reg.offset() as u64);
        }
    }
}
