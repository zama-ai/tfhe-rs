//!
//! Simple binary application that expend high-level HW parameters to PeStore configuration
//! Use offline approach to ease user-edition of generated pe-store

use hpu_sim::isc;
use tfhe::tfhe_hpu_backend::prelude::*;

/// High-level Hw Parameters structure used to derived ALUStore properties
pub struct HwParams {
    pub coef_w: usize,
    pub glwe_n: usize,
    pub glwe_k: usize,
    pub lwe_k: usize,
    pub axi_width: usize,
    pub ks_cycles: usize,
    pub br_load_cycles: usize,
    pub batch_pbs: usize,
    pub ldst_nb: usize,
    pub lin_nb: usize,
    pub pbs_nb: usize,
}

impl HwParams {
    pub fn expand(&self) -> isc::PeConfigStore {
        let mut pe_config_store = Vec::with_capacity(self.ldst_nb + self.lin_nb + self.batch_pbs);

        // LoadStore
        // Load store performance is computed as access_cycle *2
        // Take 2 as really raw approximation
        // LoadStore operation don't support early rd_unlock -> assign same value as wr_unlock
        // TODO must be refined when packing is defined
        let blwe_size = ((self.glwe_n * self.glwe_k) + 1) * self.coef_w;
        let ldst_raw_cycle = blwe_size.div_ceil(self.axi_width);
        let ldst_cycle = ldst_raw_cycle * 2;
        for i in 0..self.ldst_nb {
            let name = format!("LdSt_{i}");
            let cost = isc::PeCost::new(ldst_cycle, ldst_cycle + 1);
            let kind = isc::InstructionKind::from_name_list(&[
                hpu_asm::dop::DOpName::LD,
                hpu_asm::dop::DOpName::ST,
            ]);
            pe_config_store.push((name, isc::PeConfig::new(cost, kind, 1)));
        }

        // Linear operation
        // Linear operation performance is computed roughly as glwe_n*glwe_k
        // In practice this could be lower if multiple coefs are handle in //
        // Linear operation don't support early rd_unlock -> assign same value as wr_unlock
        let lin_cycle = self.glwe_n * self.glwe_k;
        for i in 0..self.lin_nb {
            let name = format!("Lin_{i}");
            let cost = isc::PeCost::new(lin_cycle, lin_cycle + 1);
            let kind = isc::InstructionKind::from_name_list(&[
                hpu_asm::dop::DOpName::SUBS,
                hpu_asm::dop::DOpName::SSUB,
                hpu_asm::dop::DOpName::ADDS,
                hpu_asm::dop::DOpName::MULS,
                hpu_asm::dop::DOpName::ADD,
                hpu_asm::dop::DOpName::SUB,
                hpu_asm::dop::DOpName::MAC,
            ]);
            pe_config_store.push((name, isc::PeConfig::new(cost, kind, 1)));
        }

        // KsPbs operation
        // View as PeBatch unit
        // IPIP/BPIP Mode is handle by the scheduler module
        // Thus we view the KsPbs engine as a list of batch_pbs alu with full latency each
        let kspbs_rd_cycle = self.batch_pbs * self.glwe_n * self.glwe_k;
        let kspbs_wr_cycle = self.ks_cycles + self.batch_pbs * (self.lwe_k * self.br_load_cycles);

        for i in 0..self.pbs_nb {
            let name = format!("KsPbs_{}", i);
            let cost = isc::PeCost::new(kspbs_rd_cycle, kspbs_wr_cycle);
            let kind = isc::InstructionKind::from_name_list(&[
                hpu_asm::dop::DOpName::PBS,
                hpu_asm::dop::DOpName::PBS_F,
            ]);
            pe_config_store.push((name, isc::PeConfig::new(cost, kind, self.batch_pbs)));
        }

        isc::PeConfigStore::new(pe_config_store)
    }
}

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "Generate PeStore configuration file for Hpu")]
pub struct Args {
    // HW configuration ----------------------------------------------------
    #[clap(long, value_parser, default_value_t = 44)]
    coef_w: usize,
    #[clap(long, value_parser, default_value_t = 1024)]
    glwe_n: usize,
    #[clap(long, value_parser, default_value_t = 2)]
    glwe_k: usize,
    #[clap(long, value_parser, default_value_t = 724)]
    lwe_k: usize,
    #[clap(long, value_parser, default_value_t = 512)]
    axi_width: usize,
    #[clap(long, value_parser, default_value_t = 416)]
    ks_cycles: usize,
    #[clap(long, value_parser, default_value_t = 96)]
    br_load_cycles: usize,
    #[clap(long, value_parser, default_value_t = 8)]
    batch_pbs: usize,
    #[clap(long, value_parser, default_value_t = 1)]
    ldst_nb: usize,
    #[clap(long, value_parser, default_value_t = 1)]
    lin_nb: usize,
    #[clap(long, value_parser, default_value_t = 1)]
    pbs_nb: usize,

    // File configuration ----------------------------------------------------
    /// PathName of the output configuration file
    #[clap(long, value_parser)]
    config_file: String,
}

impl From<Args> for HwParams {
    fn from(value: Args) -> Self {
        Self {
            coef_w: value.coef_w,
            glwe_n: value.glwe_n,
            glwe_k: value.glwe_k,
            lwe_k: value.lwe_k,
            axi_width: value.axi_width,
            ks_cycles: value.ks_cycles,
            br_load_cycles: value.br_load_cycles,
            batch_pbs: value.batch_pbs,
            ldst_nb: value.ldst_nb,
            lin_nb: value.lin_nb,
            pbs_nb: value.pbs_nb,
        }
    }
}

fn main() {
    let args = Args::parse();
    println!("User Options: {args:?}");

    let config_file = args.config_file.clone();
    let params: HwParams = args.into();
    let alu_store = params.expand();

    alu_store.to_ron(&config_file);
}
