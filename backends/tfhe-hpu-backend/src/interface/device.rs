//! Implement User-view of Hpu backend
//! Through this interface user is able to instantiate and configure a Hpu Backend
use super::config::HpuConfig;
use super::*;
use crate::entities::*;

use std::sync::{atomic, mpsc, Arc};

pub struct HpuDevice {
    config: HpuConfig,
    pub(crate) backend: backend::HpuBackendWrapped,
    pub(crate) ct_mem: memory::CiphertextMemory,
    pub(crate) cmd_api: mpsc::Sender<cmd::HpuCmd>,
    pub(crate) params: Arc<HpuParameters>,
    bg_poll: Arc<atomic::AtomicBool>,
    bg_handles: Option<(std::thread::JoinHandle<()>, std::thread::JoinHandle<()>)>,
}

/// Provide constructor
/// Use a toml configuration file to properly construct HpuDevice
/// This configuration file contain xclbin/kernel information and associated register map
/// definition
impl HpuDevice {
    pub fn from_config(config_toml: &str) -> Self {
        let config = HpuConfig::from_toml(config_toml);

        Self::new(config)
    }

    pub fn new(config: HpuConfig) -> Self {
        // Create backend
        let (backend, cmd_api) = backend::HpuBackendWrapped::new_wrapped(&config);

        // Get ref to ct_memory and associated params
        let (ct_mem, params) = {
            let be = backend.lock().unwrap();
            (be.ct_mem.clone(), be.params.clone())
        };
        let mut device = Self {
            config,
            backend,
            ct_mem,
            cmd_api,
            params: Arc::new(params),
            bg_poll: Arc::new(atomic::AtomicBool::new(false)),
            bg_handles: None,
        };

        // Start polling thread in the background
        device.run_polling();
        device
    }
}

impl Drop for HpuDevice {
    fn drop(&mut self) {
        // Required background polling thread to stop
        // This enable proper release of the associated HpuBackend
        self.bg_poll.store(false, atomic::Ordering::SeqCst);

        if let Some((workq_handle, ackq_handle)) = self.bg_handles.take() {
            workq_handle
                .join()
                .expect("Work_queue Background thread failed to stop properly");
            ackq_handle
                .join()
                .expect("Ack_queue Background thread failed to stop properly");
        }
    }
}

/// Retrieved Hw parameters & configuration
impl HpuDevice {
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }
    pub fn config(&self) -> &HpuConfig {
        &self.config
    }
}

/// Global Key setup
impl HpuDevice {
    /// Convert keys (i.e. Ksk/Bsk) is the correct format
    /// Upload them in on-board memory and configure associated register entries
    /// Also use the given server key to generate required set of GlweLut
    /// Upload them in on-board memory and configure associated register entries
    // TODO fixdeps
    pub fn init<F>(
        &self,
        bsk: HpuLweBootstrapKeyOwned<u64>,
        ksk: HpuLweKeyswitchKeyOwned<u64>,
        gen_lut: F,
    ) where
        F: Fn(HpuParameters, &crate::asm::Pbs) -> HpuGlweLookuptableOwned<u64>,
    {
        // print HPU version
        #[cfg(feature = "hw-v80")]
        {
            let mut backend = self.backend.lock().unwrap();
            let (major, minor) = backend.get_hpu_version();
            tracing::info!("HPU version -> {}.{}", major, minor);

            if major >= 2 && minor >= 3 {
                backend.map_bar_reg().unwrap();
            }
        }

        // Properly reset keys
        self.bsk_unset();
        self.ksk_unset();

        self.bsk_set(bsk);
        self.ksk_set(ksk);

        // Init GlweLut ciphertext
        self.lut_init(gen_lut);

        // Init Fw Lut and Translation table
        self.fw_init();

        // Init HW trace offset
        self.trace_init();
    }

    /// Enforce a cleaan state of the HPU before workload execution
    /// Currently only enforce proper state of the Ciphertext pool
    /// i.e. No already allocated Ciphertext and no fragmentation
    pub fn mem_sanitizer(&self) {
        // Lock underlying backend
        let backend = self.backend.lock().unwrap();

        // Triggered Ciphertext pool defragmentation
        backend.ct_mem.reorder_pool();
    }
}
/// Bootstrapping Key handling
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuDevice {
    pub fn bsk_unset(&self) {
        let mut backend = self.backend.lock().unwrap();
        backend.bsk_unset();
    }
    pub fn bsk_set(&self, bsk: HpuLweBootstrapKeyOwned<u64>) {
        let mut backend = self.backend.lock().unwrap();
        backend.bsk_set(bsk);
    }
    pub fn bsk_is_set(&self) -> bool {
        let backend = self.backend.lock().unwrap();
        backend.bsk_is_set()
    }
}

/// KeyswitchKey handling
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuDevice {
    pub fn ksk_unset(&self) {
        let mut backend = self.backend.lock().unwrap();
        backend.ksk_unset();
    }
    pub fn ksk_set(&self, ksk: HpuLweKeyswitchKeyOwned<u64>) {
        let mut backend = self.backend.lock().unwrap();
        backend.ksk_set(ksk);
    }
    pub fn ksk_is_set(&self) -> bool {
        let backend = self.backend.lock().unwrap();
        backend.ksk_is_set()
    }
}

/// GlweLut/ Fw handling
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuDevice {
    pub(crate) fn lut_init<F>(&self, gen_lut: F)
    where
        F: Fn(HpuParameters, &crate::asm::Pbs) -> HpuGlweLookuptableOwned<u64>,
    {
        let mut backend = self.backend.lock().unwrap();
        backend.lut_init(gen_lut)
    }
    pub fn fw_init(&self) {
        let mut backend = self.backend.lock().unwrap();
        backend.fw_init(&self.config);
    }
    pub fn trace_init(&self) {
        let mut backend = self.backend.lock().unwrap();
        backend.trace_init();
    }
}

/// Allocate new Hpu variable to hold ciphertext
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuDevice {
    /// Construct an Hpu variable from a vector of HpuLweCiphertext
    pub fn new_var_from(
        &self,
        ct: Vec<HpuLweCiphertextOwned<u64>>,
        mode: crate::asm::iop::VarMode,
    ) -> HpuVarWrapped {
        HpuVarWrapped::new_from(
            self.ct_mem.clone(),
            self.cmd_api.clone(),
            self.params.clone(),
            ct,
            mode,
        )
    }
}

/// Spawn a background thread that handle periodically update HW state
/// WARN: Variable still required lock on HpuBackend for allocation. Thus ensure to release the lock
/// periodically NB: This should be replaced by Irq when available
impl HpuDevice {
    fn run_polling(&mut self) {
        let backend = self.backend.clone();
        let bg_poll = self.bg_poll.clone();
        let tick = std::time::Duration::from_micros(self.config.fpga.polling_us);

        if bg_poll.load(atomic::Ordering::SeqCst) {
            // background threads already running
            // -> nothing to do
            return;
        };

        bg_poll.store(true, atomic::Ordering::SeqCst);
        let bg_workq = (bg_poll.clone(), backend.clone());
        let bg_ackq = (bg_poll.clone(), backend.clone());
        self.bg_handles = Some((
            std::thread::spawn(move || {
                while bg_workq.0.load(atomic::Ordering::SeqCst) {
                    std::thread::sleep(tick);
                    {
                        let mut be = bg_workq.1.lock().unwrap();
                        be.flush_workq().expect("Hpu encounter internal error");
                    }
                }
            }),
            std::thread::spawn(move || {
                while bg_ackq.0.load(atomic::Ordering::SeqCst) {
                    std::thread::sleep(tick);
                    {
                        let mut be = bg_ackq.1.lock().unwrap();
                        be.flush_ackq().expect("Hpu encounter internal error");
                    }
                }
            }),
        ));
    }
}
