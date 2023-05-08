use crate::shortint::Parameters;
use once_cell::sync::Lazy;
use crate::integer::wopbs::WopbsKey;
use crate::integer::{ClientKey, ServerKey};

#[derive(Default)]
pub struct IntegerKeyCache;

impl IntegerKeyCache {
    pub fn get_from_params(&self, params: Parameters) -> (ClientKey, ServerKey) {
        let keys = crate::shortint::keycache::KEY_CACHE.get_from_param(params);
        let (client_key, server_key) = (keys.client_key(), keys.server_key());

        let client_key = ClientKey::from(client_key.clone());
        let server_key = ServerKey::from_shortint(&client_key, server_key.clone());

        (client_key, server_key)
    }

    pub fn get_shortint_from_params(
        &self,
        params: Parameters,
    ) -> (crate::shortint::ClientKey, crate::shortint::ServerKey) {
        let keys = crate::shortint::keycache::KEY_CACHE.get_from_param(params);
        (keys.client_key().clone(), keys.server_key().clone())
    }
}

#[derive(Default)]
pub struct WopbsKeyCache;

impl WopbsKeyCache {
    pub fn get_from_params(&self, params: (Parameters, Parameters)) -> WopbsKey {
        let shortint_wops_key = crate::shortint::keycache::KEY_CACHE_WOPBS.get_from_param(params);
        WopbsKey::from(shortint_wops_key.wopbs_key().clone())
    }
}

pub static KEY_CACHE: Lazy<IntegerKeyCache> = Lazy::new(|| Default::default());
pub static KEY_CACHE_WOPBS: Lazy<WopbsKeyCache> = Lazy::new(|| Default::default());
