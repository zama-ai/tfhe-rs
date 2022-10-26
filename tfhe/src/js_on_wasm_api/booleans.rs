use bincode;
use wasm_bindgen::prelude::*;

use super::seeder;

use std::panic::set_hook;

#[wasm_bindgen]
pub struct BooleanCiphertext(pub(crate) crate::boolean::ciphertext::Ciphertext);

#[wasm_bindgen]
pub struct BooleanClientKey(pub(crate) crate::boolean::client_key::ClientKey);

#[wasm_bindgen]
pub struct BooleanEngine(pub(crate) crate::boolean::engine::CpuBooleanEngine);

#[wasm_bindgen]
pub struct BooleanParameters(pub(crate) crate::boolean::parameters::BooleanParameters);

#[wasm_bindgen]
pub struct BooleanSerializer;

#[wasm_bindgen]
pub enum BooleanParameterSet {
    Default,
    TfheLib,
}

impl TryFrom<u32> for BooleanParameterSet {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BooleanParameterSet::Default),
            1 => Ok(BooleanParameterSet::TfheLib),
            _ => Err(format!(
                "Invalid value '{value}' for BooleansParametersSet, use \
                BooleanParameterSet constants"
            )),
        }
    }
}

#[wasm_bindgen]
impl BooleanClientKey {
    #[wasm_bindgen]
    pub fn get_boolean_parameters(parameter_choice: u32) -> Result<BooleanParameters, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        let parameter_choice = BooleanParameterSet::try_from(parameter_choice)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))?;

        match parameter_choice {
            BooleanParameterSet::Default => Ok(crate::boolean::parameters::DEFAULT_PARAMETERS),
            BooleanParameterSet::TfheLib => Ok(crate::boolean::parameters::TFHE_LIB_PARAMETERS),
        }
        .map(BooleanParameters)
    }

    #[wasm_bindgen]
    pub fn new_boolean_parameters(
        lwe_dimension: usize,
        glwe_dimension: usize,
        polynomial_size: usize,
        lwe_modular_std_dev: f64,
        glwe_modular_std_dev: f64,
        pbs_base_log: usize,
        pbs_level: usize,
        ks_base_log: usize,
        ks_level: usize,
    ) -> BooleanParameters {
        use crate::core_crypto::prelude::*;
        BooleanParameters(crate::boolean::parameters::BooleanParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_modular_std_dev: StandardDev(lwe_modular_std_dev),
            glwe_modular_std_dev: StandardDev(glwe_modular_std_dev),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
        })
    }

    #[wasm_bindgen]
    pub fn new_client_key_from_seed_and_parameters(
        seed_high_bytes: u64,
        seed_low_bytes: u64,
        parameters: &BooleanParameters,
    ) -> BooleanClientKey {
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed: u128 = (seed_high_bytes << 64) | seed_low_bytes;

        let constant_seeder = Box::new(seeder::ConstantSeeder::new(
            crate::core_crypto::commons::math::random::Seed(seed),
        ));

        let mut tmp_boolean_engine = crate::boolean::engine::CpuBooleanEngine::new(constant_seeder);

        BooleanClientKey(tmp_boolean_engine.create_client_key(parameters.0.to_owned()))
    }
}

#[wasm_bindgen]
impl BooleanSerializer {
    #[wasm_bindgen]
    pub fn serialize_boolean_ciphertext(
        ciphertext: &BooleanCiphertext,
    ) -> Result<Vec<u8>, JsError> {
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_boolean_ciphertext(buffer: &[u8]) -> Result<BooleanCiphertext, JsError> {
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(BooleanCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_boolean_client_key(client_key: &BooleanClientKey) -> Result<Vec<u8>, JsError> {
        bincode::serialize(&client_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_boolean_client_key(buffer: &[u8]) -> Result<BooleanClientKey, JsError> {
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(BooleanClientKey)
    }
}

#[wasm_bindgen]
impl BooleanEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(seeder: crate::JsFunctionSeeder) -> BooleanEngine {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanEngine(crate::boolean::engine::CpuBooleanEngine::new(Box::new(
            seeder,
        )))
    }

    #[wasm_bindgen]
    pub fn new_client_key(&mut self, parameters: &BooleanParameters) -> BooleanClientKey {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanClientKey(self.0.create_client_key(parameters.0.to_owned()))
    }

    #[wasm_bindgen]
    pub fn encrypt(&mut self, client_key: &BooleanClientKey, message: bool) -> BooleanCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanCiphertext(self.0.encrypt(message, &client_key.0))
    }

    #[wasm_bindgen]
    pub fn trivial_encrypt(&mut self, message: bool) -> BooleanCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanCiphertext(self.0.trivial_encrypt(message))
    }

    #[wasm_bindgen]
    pub fn decrypt(&mut self, client_key: &BooleanClientKey, ct: &BooleanCiphertext) -> bool {
        self.0.decrypt(&ct.0, &client_key.0)
    }
}
