//! Implement User-view of Hpu
//!
//! Through this interface user is able to instantiate and configure a Hpu Device
//!
//! HpuDevice is a collection of HpuNode (i.e. cluster) backed in a common structure.
//! Hpu nodes work concurrently and thus must have same configuration/parameters

use super::config::HpuConfig;
use super::{HpuClusterWrapped, HpuInstError, HpuVarWrapped};
use crate::entities::*;
use std::sync::Arc;

use rayon::prelude::*;

pub struct HpuDevice {
    config: Arc<HpuConfig>,
    cluster: HpuClusterWrapped,
}

impl HpuDevice {
    pub fn from_config(config_toml: &str, force_reload: bool) -> Result<Self, HpuInstError> {
        let config = HpuConfig::from_toml(config_toml);

        Self::new(config, force_reload)
    }

    pub fn new(config: HpuConfig, force_reload: bool) -> Result<Self, HpuInstError> {
        let config = Arc::new(config);
        let cluster = HpuClusterWrapped::new_wrapped(&config, force_reload)?;
        Ok(Self { config, cluster })
    }

    /// Convert keys (i.e. Ksk/Bsk) is the correct format
    /// Upload them in on-board memory and configure associated register entries
    /// Also use the given server key to generate required set of GlweLut
    /// Upload them in on-board memory and configure associated register entries
    pub fn init<F>(
        &self,
        bsk: HpuLweBootstrapKeyView<u64>,
        ksk: HpuLweKeyswitchKeyView<u64>,
        gen_lut: &F,
    ) where
        F: Fn(&HpuParameters, &crate::asm::Pbs) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        self.cluster.par_iter().for_each(|(_id, node)| {
            let mut node_lock = node.lock().expect("Error with backend mutex");
            // Properly reset keys
            node_lock.bsk_unset();
            node_lock.ksk_unset();

            node_lock.bsk_set(bsk.as_view());
            node_lock.ksk_set(ksk.as_view());

            // Init GlweLut ciphertext
            node_lock.lut_init(gen_lut);

            // Init Fw Lut and Translation table
            node_lock.fw_init(&self.config);

            // Init HW trace offset
            node_lock.trace_init();
        })
    }
}

/// Retrieved device parameters & configuration
impl HpuDevice {
    pub fn params(&self) -> &HpuParameters {
        &self.cluster.params()
    }
    pub fn config(&self) -> &HpuConfig {
        &self.config
    }
}

/// Allocate new Hpu variable to hold ciphertext
/// Only here to expose function to the user. Associated logic is handled by the cluster
impl HpuDevice {
    /// Construct an Hpu variable from a vector of HpuLweCiphertext
    pub fn new_var_from(
        &self,
        ct: Vec<HpuLweCiphertextOwned<u64>>,
        mode: crate::asm::iop::VarMode,
        pos: Option<crate::asm::NodeId>,
    ) -> HpuVarWrapped {
        self.cluster.new_var_from(ct, mode, pos)
    }
}

impl HpuDevice {
    /// Enforce a clean state of the HPU before workload execution
    /// Currently only enforce proper state of the Ciphertext pool
    /// i.e. No already allocated Ciphertext and no fragmentation
    pub fn mem_sanitizer(&self) {
        for (_id, node) in self.cluster.iter() {
            node.ct_mem.reorder_pool();
        }
    }
}
