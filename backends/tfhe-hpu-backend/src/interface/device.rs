//! Implement User-view of Hpu
//!
//! Through this interface user is able to instantiate and configure a Hpu Device
//!
//! HpuDevice is a collection of HpuNode (i.e. cluster) backed in a common structure.
//! Hpu nodes work concurrently and thus must have same configuration/parameters

use super::cache::{DynFwEntry, DynFwError};
use super::config::HpuConfig;
use super::{HpuClusterWrapped, HpuInstError, HpuVarWrapped};
use crate::asm;
use crate::entities::*;
use std::sync::Arc;

use rayon::prelude::*;
use zhc::builder::CiphertextSpec;
use zhc::prelude::Pipeline;

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
        F: Fn(&HpuParameters, &[u64]) -> HpuGlweLookuptableOwned<u64> + Sync,
    {
        self.cluster.par_iter().for_each(|(_id, node)| {
            let mut node_lock = node.lock().expect("Error with backend mutex");
            // Properly reset keys
            node_lock.bsk_unset();
            node_lock.ksk_unset();

            node_lock.bsk_set(bsk.as_view());
            node_lock.ksk_set(ksk.as_view());

            // Init Fw
            // Upload required TfheLut
            // and IOp translation table
            node_lock.fw_init(&self.config, gen_lut);

            // Init HW trace offset
            node_lock.trace_init();

            // Init MHDMA
            node_lock.mhdma_cfg();
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
        // Common pipeline stages
        let mut pipeline = pipeline;
        let fingerprint = pipeline.get_fingerprint().clone();
        let zhc_proto = pipeline.get_prototype().clone();
        let lut_registry = pipeline.get_lut_registry().clone();
        let zhc_mh_config = pipeline.get_multi_hpu_config().clone();
        let doplang = pipeline.get_multi_doplang();

        // Generate IOpProto
        // Translate Tfhe-rs proto from zhc Op signature
        // TODO: fuse both view. Drop tfhe-rs asm impl in favor of zhc one
        let proto = {
            use zhc::builder::Type;
            use zhc::ir::Signature;
            // TODO get real value from signature or pipeline
            let ct_spec = CiphertextSpec::new(16, 2, 2); // TODO use real spec

            let native_w = ct_spec.int_size();
            let half_w = native_w / 2;
            let mh_factor = zhc_mh_config.n_hpus;

            let Signature(sig_src, sig_dst) = zhc_proto;
            let dst_mode = sig_dst
                .iter()
                .filter_map(|sig| {
                    if let Type::Ciphertext(spec) = sig {
                        Some(spec)
                    } else {
                        None
                    }
                })
                .map(|spec| {
                    if spec.int_size() == native_w {
                        asm::iop::VarMode::Native
                    } else if spec.int_size() == half_w {
                        asm::iop::VarMode::Half
                    } else if spec.int_size() == 1 {
                        asm::iop::VarMode::Bool
                    } else {
                        panic!("Unexpected Ciphertext Type");
                    }
                })
                .collect::<Vec<_>>();
            let src_mode = sig_src
                .iter()
                .filter_map(|sig| {
                    if let Type::Ciphertext(spec) = sig {
                        Some(spec)
                    } else {
                        None
                    }
                })
                .map(|spec| {
                    if spec.int_size() == native_w {
                        asm::iop::VarMode::Native
                    } else if spec.int_size() == half_w {
                        asm::iop::VarMode::Half
                    } else if spec.int_size() == 1 {
                        asm::iop::VarMode::Bool
                    } else {
                        panic!("Unexpected Ciphertext Type");
                    }
                })
                .collect::<Vec<_>>();
            let imm = sig_src
                .iter()
                .filter_map(|sig| {
                    if let Type::Plaintext(_) = sig {
                        Some(())
                    } else {
                        None
                    }
                })
                .count();
            asm::IOpProto {
                used_nodes: asm::iop::NodesMap::new(&[mh_factor]),
                dst: dst_mode,
                src: src_mode,
                imm,
            }
        };

        // Parallel over nodes
        // Each of them has its own relocation table, no recompute of the above.
        let entries = self
            .cluster
            .par_iter()
            .map(|(_id, node)| {
                let mut node_lock = node.lock().expect("Error with backend mutex");
                node_lock.fw_dyn_init(
                    fingerprint.clone(),
                    proto.clone(),
                    doplang,
                    &lut_registry,
                    gen_lut,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let all_match = entries.windows(2).all(|w| w[0].iop() == w[1].iop());
        if !all_match {
            Err(DynFwError::UnsyncView)
        } else {
            Ok(entries[0].clone())
        }
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
}

/// Allocate new Hpu variable to hold ciphertext
/// Only here to expose function to the user. Associated logic is handled by the cluster
impl HpuDevice {
    /// Construct an Hpu variable from a vector of HpuLweCiphertext
    pub fn new_var_from(
        &self,
        ct: Vec<HpuLweCiphertextOwned<u64>>,
        mode: crate::asm::iop::VarMode,
        pos: Option<crate::asm::PhysId>,
    ) -> HpuVarWrapped {
        self.cluster.new_var_from(ct, mode, pos)
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
