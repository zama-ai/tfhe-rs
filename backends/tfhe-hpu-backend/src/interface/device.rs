//! Implement User-view of Hpu backend
//! Through this interface user is able to instanciate and configure a Hpu Backend
use super::config::HpuConfig;
use super::*;
use crate::entities::*;

use std::sync::{atomic, Arc};

pub struct HpuDevice {
    config: HpuConfig,
    pub(crate) backend: backend::HpuBackendWrapped,
    bg_poll: Arc<atomic::AtomicBool>,
    bg_handle: Option<std::thread::JoinHandle<()>>,
}

/// Provide constructor
/// Use a toml configuration file to properly construct HpuDevice
/// This configuration file contain xclbin/kernel informations and associated register map
/// definition
impl HpuDevice {
    pub fn from_config(config_toml: &str) -> Self {
        let config = HpuConfig::from_toml(config_toml);

        Self::new(config)
    }

    pub fn new(config: HpuConfig) -> Self {
        let backend = backend::HpuBackendWrapped::new_wrapped(&config);
        let mut device = Self {
            config,
            backend,
            bg_poll: Arc::new(atomic::AtomicBool::new(false)),
            bg_handle: None,
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

        if let Some(handle) = self.bg_handle.take() {
            handle
                .join()
                .expect("Background thread failed to stop properly");
        }
    }
}

/// Retrieved Hw parameters
impl HpuDevice {
    pub fn params(&self) -> HpuParameters {
        self.backend.lock().unwrap().params.clone()
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
        F: Fn(HpuParameters, crate::asm::Pbs) -> HpuGlweLookuptableOwned<u64>,
    {
        // Properly reset keys
        self.bsk_unset();
        self.ksk_unset();

        self.bsk_set(bsk);
        self.ksk_set(ksk);

        // Init GlweLut ciphertext
        self.lut_init(gen_lut);

        // Init Fw Lut and Translation table
        self.fw_init();
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
        F: Fn(HpuParameters, crate::asm::Pbs) -> HpuGlweLookuptableOwned<u64>,
    {
        let mut backend = self.backend.lock().unwrap();
        backend.lut_init(gen_lut)
    }
    pub fn fw_init(&self) {
        let mut backend = self.backend.lock().unwrap();
        backend.fw_init(&self.config);
    }
}

/// Allocate new Hpu variable to hold ciphertext
/// Only here to expose function to the user. Associated logic is handled by the backend
impl HpuDevice {
    /// Construct an Hpu variable from a vector of HpuLweCiphertext
    pub fn new_var_from(&self, ct: Vec<HpuLweCiphertextOwned<u64>>) -> HpuVarWrapped {
        HpuVarWrapped::new_from(self.backend.clone(), ct)
    }
}

/// Spawn a background thread that handle periodically update HW state
/// WARN: Variable still required lock on HpuBackend for allocation. Thus ensure to relase the lock
/// periodically NB: This should be replaced by Irq when available
impl HpuDevice {
    fn run_polling(&mut self) {
        let backend = self.backend.clone();
        let bg_poll = self.bg_poll.clone();
        let tick = std::time::Duration::from_micros(self.config.fpga.polling_us);

        if bg_poll.load(atomic::Ordering::SeqCst) {
            // background thread already running
            // -> nothing to do
            return;
        };

        bg_poll.store(true, atomic::Ordering::SeqCst);
        self.bg_handle = Some(std::thread::spawn(move || {
            while bg_poll.load(atomic::Ordering::SeqCst) {
                std::thread::sleep(tick);
                {
                    let mut be = backend.lock().unwrap();
                    be.run_step().expect("Hpu encounter internal error");
                }
            }
        }));
    }
}
