use crate::shortint::{PBSParameters, WopbsParameters};
use lazy_static::lazy_static;

use crate::integer::wopbs::WopbsKey;
use crate::integer::{ClientKey, IntegerKeyKind, ServerKey};

#[derive(Default)]
pub struct IntegerKeyCache;

impl IntegerKeyCache {
    pub fn get_from_params<P>(&self, params: P, key_kind: IntegerKeyKind) -> (ClientKey, ServerKey)
    where
        P: Into<PBSParameters>,
    {
        let keys = crate::shortint::keycache::KEY_CACHE.get_from_param(params);
        let (client_key, server_key) = (keys.client_key(), keys.server_key());

        let client_key = ClientKey::from(client_key.clone());
        let server_key = match key_kind {
            IntegerKeyKind::Radix => {
                ServerKey::new_radix_server_key_from_shortint(server_key.clone())
            }
            IntegerKeyKind::CRT => ServerKey::new_crt_server_key_from_shortint(server_key.clone()),
        };

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
        let shortint_wops_key =
            crate::shortint::keycache::KEY_CACHE_WOPBS.get_from_param((pbs_params, wopbs_params));
        WopbsKey::from(shortint_wops_key.wopbs_key().clone())
    }
}

lazy_static! {
    pub static ref KEY_CACHE: IntegerKeyCache = IntegerKeyCache;
    pub static ref KEY_CACHE_WOPBS: WopbsKeyCache = WopbsKeyCache;
}
