use wasm_bindgen::prelude::*;

use crate::high_level_api as hlapi;

use crate::js_on_wasm_api::high_level_api::config::TfheConfig;
use crate::js_on_wasm_api::high_level_api::{catch_panic, catch_panic_result, into_js_error};

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct TfheClientKey(pub(crate) hlapi::ClientKey);

#[wasm_bindgen]
impl TfheClientKey {
    #[wasm_bindgen]
    pub fn generate(config: &TfheConfig) -> Result<TfheClientKey, JsError> {
        catch_panic(|| Self(hlapi::ClientKey::generate(config.0.clone())))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheClientKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

// Wasm cannot generate a normal server key, only a compressed one
#[wasm_bindgen]
pub struct TfheCompressedServerKey(pub(crate) hlapi::CompressedServerKey);

#[wasm_bindgen]
impl TfheCompressedServerKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfheCompressedServerKey, JsError> {
        catch_panic(|| Self(hlapi::CompressedServerKey::new(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheCompressedServerKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

#[wasm_bindgen]
pub struct TfhePublicKey(pub(crate) hlapi::PublicKey);

#[wasm_bindgen]
impl TfhePublicKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfhePublicKey, JsError> {
        catch_panic_result(|| {
            if matches!(
                client_key.0.integer_key.encryption_type(),
                crate::shortint::EncryptionKeyChoice::Big
            ) {
                return Err(JsError::new(
                    "TfhePublicKey is only compatible with 'small' encryption type",
                ));
            }

            Ok(Self(hlapi::PublicKey::new(&client_key.0)))
        })
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfhePublicKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

#[wasm_bindgen]
pub struct TfheCompressedPublicKey(pub(crate) hlapi::CompressedPublicKey);

#[wasm_bindgen]
impl TfheCompressedPublicKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfheCompressedPublicKey, JsError> {
        catch_panic(|| Self(hlapi::CompressedPublicKey::new(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn decompress(&self) -> Result<TfhePublicKey, JsError> {
        catch_panic(|| TfhePublicKey(self.0.clone().decompress()))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheCompressedPublicKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}
