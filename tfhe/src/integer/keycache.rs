use crate::integer::{ClientKey, IntegerKeyKind, ServerKey};
use crate::shortint::atomic_pattern::AtomicPatternParameters;

#[cfg(feature = "hpu")]
use std::sync::{Mutex, OnceLock};
#[cfg(feature = "hpu")]
use tfhe_hpu_backend::prelude::*;

#[derive(Default)]
pub struct IntegerKeyCache {
    #[cfg(feature = "hpu")]
    hpu_device: OnceLock<Mutex<HpuDevice>>,
}

impl IntegerKeyCache {
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "hpu")]
            hpu_device: OnceLock::new(),
        }
    }

    pub fn get_from_params<P>(&self, params: P, key_kind: IntegerKeyKind) -> (ClientKey, ServerKey)
    where
        P: Into<AtomicPatternParameters>,
    {
        let cache = &crate::shortint::keycache::KEY_CACHE;

        let keys = cache.get_from_param(params);
        let (client_key, server_key) = (keys.client_key(), keys.server_key());

        let client_key = ClientKey::from(client_key.clone());
        let server_key = match key_kind {
            IntegerKeyKind::Radix => {
                ServerKey::new_radix_server_key_from_shortint(server_key.clone())
            }
            IntegerKeyKind::CRT => ServerKey::new_crt_server_key_from_shortint(server_key.clone()),
        };

        // For cargo nextest which runs in separate processes we load keys once per process, this
        // allows to remove the copy loaded in the keycache to avoid OOM errors, the nice effect of
        // linux file caching is that the keys will still be in RAM most likely, not requiring re
        // re-reading from file for all processes.
        if let Ok(val) = std::env::var("TFHE_RS_CLEAR_IN_MEMORY_KEY_CACHE") {
            if val == "1" {
                cache.clear_in_memory_cache()
            }
        }

        (client_key, server_key)
    }

    #[cfg(feature = "hpu")]
    pub fn get_hpu_device<P>(&self, param: P) -> &Mutex<HpuDevice>
    where
        P: Into<crate::shortint::AtomicPatternParameters> + crate::keycache::NamedParam + Clone,
    {
        let hpu_device = self.hpu_device.get_or_init(|| {
            // Instantiate HpuDevice --------------------------------------------------
            let hpu_device = {
                let config_file = ShellString::new(
                    "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string(),
                );
                HpuDevice::from_config(&config_file.expand())
            };
            // Check compatibility with key
            let hpu_pbs_params =
                crate::shortint::parameters::KeySwitch32PBSParameters::from(hpu_device.params());
            assert_eq!(
                param.clone().into(),
                crate::shortint::AtomicPatternParameters::from(hpu_pbs_params),
                "Error: Current Hpu device isn't compatible with {}",
                param.name()
            );

            // Get current client key
            let (cks, _) = self.get_from_params(param, IntegerKeyKind::Radix);
            // Generate associated compressed ServerKey
            let sks_compressed = super::CompressedServerKey::new_radix_compressed_server_key(&cks);

            // Init Hpu device with server key and firmware
            crate::integer::hpu::init_device(&hpu_device, sks_compressed).expect("Invalid key");
            Mutex::new(hpu_device)
        });

        // Sanitize memory to prevent side-effect between tests
        hpu_device.lock().unwrap().mem_sanitizer();

        hpu_device
    }
}

pub static KEY_CACHE: IntegerKeyCache = IntegerKeyCache::new();
