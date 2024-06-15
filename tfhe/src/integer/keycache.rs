use crate::integer::wopbs::WopbsKey;
use crate::integer::{ClientKey, IntegerKeyKind, ServerKey};
use crate::shortint::{PBSParameters, WopbsParameters};
use lazy_static::lazy_static;

#[derive(Default)]
pub struct IntegerKeyCache;

impl IntegerKeyCache {
    pub fn get_from_params<P>(&self, params: P, key_kind: IntegerKeyKind) -> (ClientKey, ServerKey)
    where
        P: Into<PBSParameters>,
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
}

#[derive(Default)]
pub struct WopbsKeyCache;

impl WopbsKeyCache {
    pub fn get_from_params<P>(&self, (pbs_params, wopbs_params): (P, WopbsParameters)) -> WopbsKey
    where
        P: Into<PBSParameters>,
    {
        let cache = &crate::shortint::keycache::KEY_CACHE_WOPBS;
        let shortint_wops_key = cache.get_from_param((pbs_params, wopbs_params));

        // For cargo nextest which runs in separate processes we load keys once per process, this
        // allows to remove the copy loaded in the keycache to avoid OOM errors, the nice effect of
        // linux file caching is that the keys will still be in RAM most likely, not requiring re
        // re-reading from file for all processes.
        if let Ok(val) = std::env::var("TFHE_RS_CLEAR_IN_MEMORY_KEY_CACHE") {
            if val == "1" {
                cache.clear_in_memory_cache()
            }
        }

        WopbsKey::from(shortint_wops_key.wopbs_key().clone())
    }
}

lazy_static! {
    pub static ref KEY_CACHE: IntegerKeyCache = IntegerKeyCache;
    pub static ref KEY_CACHE_WOPBS: WopbsKeyCache = WopbsKeyCache;
}
