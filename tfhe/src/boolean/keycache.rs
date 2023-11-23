use crate::boolean::parameters::*;
use crate::boolean::{ClientKey, ServerKey};
use crate::keycache::*;
use crate::named_params_impl;
use lazy_static::*;

named_params_impl!( BooleanParameters =>
    DEFAULT_PARAMETERS,
    DEFAULT_PARAMETERS_KS_PBS,
    PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS,
    TFHE_LIB_PARAMETERS
);

impl From<BooleanParameters> for (ClientKey, ServerKey) {
    fn from(param: BooleanParameters) -> Self {
        let cks = ClientKey::new(&param);
        let sks = ServerKey::new(&cks);
        (cks, sks)
    }
}

pub struct Keycache {
    inner: ImplKeyCache<BooleanParameters, (ClientKey, ServerKey), FileStorage>,
}

impl Default for Keycache {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new(
                "../keys/boolean/client_server".to_string(),
            )),
        }
    }
}

pub struct SharedKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
}

impl SharedKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
}

impl Keycache {
    pub fn get_from_param(&self, param: BooleanParameters) -> SharedKey {
        SharedKey {
            inner: self.inner.get(param),
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

lazy_static! {
    pub static ref KEY_CACHE: Keycache = Keycache::default();
}
