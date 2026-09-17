//! Implement User-view of Hpu
//!
//! Through this interface user is able to instantiate and configure a Hpu Device
//!
//! HpuDevice is a collection of HpuNode (i.e. cluster) backed in a common structure.
//! Hpu nodes work concurrently and thus must have same configuration/parameters

use super::cache::{DynFwEntry, DynFwError};
use super::config::HpuConfig;
use super::{HpuClusterWrapped, HpuInstError, HpuVarWrapped};
use crate::entities::*;
use std::sync::Arc;

use rayon::prelude::*;
use zhc::prelude::Pipeline;

pub struct HpuDevice {
    config: Arc<HpuConfig>,
    cluster: HpuClusterWrapped,
}

impl HpuDevice {
    pub fn from_config<F>(
        config_toml: &str,
        force_reload: bool,
        gen_lut: &F,
    ) -> Result<Self, HpuInstError>
    where
        F: Fn(&HpuParameters, &[u64]) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        let config = HpuConfig::from_toml(config_toml);

        Self::new(config, force_reload, gen_lut)
    }

    pub fn new<F>(config: HpuConfig, force_reload: bool, gen_lut: &F) -> Result<Self, HpuInstError>
    where
        F: Fn(&HpuParameters, &[u64]) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        let config = Arc::new(config);
        let cluster = HpuClusterWrapped::new_wrapped(&config, force_reload, gen_lut)?;
        Ok(Self { config, cluster })
    }

    /// Convert keys (i.e. Ksk/Bsk) is the correct format
    /// Upload them in on-board memory and configure associated register entries
    /// Also use the given server key to generate required set of GlweLut
    /// Upload them in on-board memory and configure associated register entries
    pub fn init(&self, bsk: HpuLweBootstrapKeyView<u64>, ksk: HpuLweKeyswitchKeyView<u64>) {
        self.cluster.par_iter().for_each(|(_id, node)| {
            let mut node_lock = node.lock().expect("Error with backend mutex");
            // Properly reset keys
            node_lock.bsk_unset();
            node_lock.ksk_unset();

            node_lock.bsk_set(bsk.as_view());
            node_lock.ksk_set(ksk.as_view());
        })
    }

    /// Register a new dynamic fw entry in each nodes
    pub fn fw_dyn_init<F>(
        &self,
        pipeline: Pipeline,
        gen_lut: &F,
    ) -> Result<Arc<DynFwEntry>, DynFwError>
    where
        F: Fn(&HpuParameters, &[u64]) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        self.cluster.fw_dyn_init(pipeline, gen_lut)
    }
}

/// Retrieved device parameters & configuration
impl HpuDevice {
    pub fn params(&self) -> &HpuParameters {
        self.cluster.params()
    }
    pub fn config(&self) -> &HpuConfig {
        &self.config
    }

    /// Look up the zhc `Signature`/required-node-count of a given IOp. Mainly useful for
    /// tooling/benchmarks that need to introspect an IOp's expected src/dst/imm shape ahead of
    /// building a matching `HpuCmd` (which does this same lookup internally and doesn't need it
    /// specified explicitly).
    pub fn get_signature(
        &self,
        fw_mode: crate::asm::FwMode,
        opcode: crate::asm::IOpcode,
        integer_w: u16,
    ) -> crate::asm::IOpSig {
        self.cluster.get_signature(fw_mode, opcode, integer_w)
    }
}

/// Allocate new Hpu variable to hold ciphertext
/// Only here to expose function to the user. Associated logic is handled by the cluster
impl HpuDevice {
    /// Construct an Hpu variable from a vector of HpuLweCiphertext
    pub fn new_var_from(
        &self,
        ct: Vec<HpuLweCiphertextOwned<u64>>,
        spec: zhc::builder::CiphertextSpec,
        pos: Option<crate::asm::PhysId>,
    ) -> HpuVarWrapped {
        self.cluster.new_var_from(ct, spec, pos)
    }
}

impl HpuDevice {
    /// Enforce a clean state of the HPU before workload execution
    /// Currently only enforce proper state of the Ciphertext pool
    /// i.e. No already allocated Ciphertext and no fragmentation
    pub fn mem_sanitizer(&self) {
        for node in self.cluster.values() {
            node.ct_mem.reorder_pool();
        }
    }
}
