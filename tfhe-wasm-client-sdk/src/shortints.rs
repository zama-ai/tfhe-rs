use bincode;
use wasm_bindgen::prelude::*;

use super::seeder;

use std::panic::set_hook;

#[wasm_bindgen]
pub struct ShortintCiphertext(pub(crate) tfhe::shortint::ciphertext::Ciphertext);

#[wasm_bindgen]
pub struct ShortintClientKey(pub(crate) tfhe::shortint::ClientKey);

#[wasm_bindgen]
pub struct ShortintEngine(pub(crate) tfhe::shortint::engine::ShortintEngine);

#[wasm_bindgen]
pub struct ShortintParameters(pub(crate) tfhe::shortint::Parameters);

#[wasm_bindgen]
impl ShortintClientKey {
    #[wasm_bindgen]
    pub fn get_shortint_parameters(
        message_bits: usize,
        carry_bits: usize,
    ) -> Result<ShortintParameters, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        match (message_bits, carry_bits) {
            (1, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_0),
            (1, 1) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_1),
            (2, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_0),
            (1, 2) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_2),
            (2, 1) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_1),
            (3, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_0),
            (1, 3) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_3),
            (2, 2) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2),
            (3, 1) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_1),
            (4, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0),
            (1, 4) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_4),
            (2, 3) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_3),
            (3, 2) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_2),
            (4, 1) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_1),
            (5, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_5_CARRY_0),
            (1, 5) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_5),
            (2, 4) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_4),
            (3, 3) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3),
            (4, 2) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_2),
            (5, 1) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_5_CARRY_1),
            (6, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_6_CARRY_0),
            (1, 6) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_6),
            (2, 5) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_5),
            (3, 4) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_4),
            (4, 3) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_3),
            (5, 2) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_5_CARRY_2),
            (6, 1) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_6_CARRY_1),
            (7, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_7_CARRY_0),
            (1, 7) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_7),
            (2, 6) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_6),
            (3, 5) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_5),
            (4, 4) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4),
            (5, 3) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_5_CARRY_3),
            (6, 2) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_6_CARRY_2),
            (7, 1) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_7_CARRY_1),
            (8, 0) => Ok(tfhe::shortint::parameters::PARAM_MESSAGE_8_CARRY_0),
            _ => Err(wasm_bindgen::JsError::new(
                format!(
                "No parameters for {message_bits} bits of message and {carry_bits} bits of carry"
            )
                .as_str(),
            )),
        }
        .map(ShortintParameters)
    }

    #[wasm_bindgen]
    pub fn new_shortint_parameters(
        lwe_dimension: usize,
        glwe_dimension: usize,
        polynomial_size: usize,
        lwe_modular_std_dev: f64,
        glwe_modular_std_dev: f64,
        pbs_base_log: usize,
        pbs_level: usize,
        ks_base_log: usize,
        ks_level: usize,
        pfks_level: usize,
        pfks_base_log: usize,
        pfks_modular_std_dev: f64,
        cbs_level: usize,
        cbs_base_log: usize,
        message_modulus: usize,
        carry_modulus: usize,
    ) -> ShortintParameters {
        use tfhe::core_crypto::prelude::*;
        ShortintParameters(tfhe::shortint::Parameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_modular_std_dev: StandardDev(lwe_modular_std_dev),
            glwe_modular_std_dev: StandardDev(glwe_modular_std_dev),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            pfks_level: DecompositionLevelCount(pfks_level),
            pfks_base_log: DecompositionBaseLog(pfks_base_log),
            pfks_modular_std_dev: StandardDev(pfks_modular_std_dev),
            cbs_level: DecompositionLevelCount(cbs_level),
            cbs_base_log: DecompositionBaseLog(cbs_base_log),
            message_modulus: tfhe::shortint::parameters::MessageModulus(message_modulus),
            carry_modulus: tfhe::shortint::parameters::CarryModulus(carry_modulus),
        })
    }

    #[wasm_bindgen]
    pub fn new_client_key_from_seed_and_parameters(
        seed_high_bytes: u64,
        seed_low_bytes: u64,
        parameters: &ShortintParameters,
    ) -> Result<ShortintClientKey, JsError> {
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed: u128 = (seed_high_bytes << 64) | seed_low_bytes;

        let constant_seeder = Box::new(seeder::ConstantSeeder::new(
            tfhe::core_crypto::commons::math::random::Seed(seed),
        ));

        let mut tmp_shortint_engine = tfhe::shortint::engine::ShortintEngine::new(constant_seeder);

        tmp_shortint_engine
            .new_client_key(parameters.0.to_owned())
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(ShortintClientKey)
    }
}

#[wasm_bindgen]
pub struct Serializer;

#[wasm_bindgen]
impl Serializer {
    #[wasm_bindgen]
    pub fn serialize_shortint_ciphertext(
        ciphertext: &ShortintCiphertext,
    ) -> Result<Vec<u8>, JsError> {
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_shortint_ciphertext(buffer: &[u8]) -> Result<ShortintCiphertext, JsError> {
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(ShortintCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_shortint_client_key(
        client_key: &ShortintClientKey,
    ) -> Result<Vec<u8>, JsError> {
        bincode::serialize(&client_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_shortint_client_key(buffer: &[u8]) -> Result<ShortintClientKey, JsError> {
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(ShortintClientKey)
    }
}

#[wasm_bindgen]
impl ShortintEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(seeder: crate::JsFunctionSeeder) -> ShortintEngine {
        set_hook(Box::new(console_error_panic_hook::hook));
        ShortintEngine(tfhe::shortint::engine::ShortintEngine::new(Box::new(
            seeder,
        )))
    }

    #[wasm_bindgen]
    pub fn new_client_key(
        &mut self,
        parameters: &ShortintParameters,
    ) -> Result<ShortintClientKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        self.0
            .new_client_key(parameters.0.to_owned())
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(ShortintClientKey)
    }

    #[wasm_bindgen]
    pub fn encrypt(
        &mut self,
        client_key: &ShortintClientKey,
        message: u64,
    ) -> Result<ShortintCiphertext, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        self.0
            .encrypt(&client_key.0, message)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(ShortintCiphertext)
    }

    #[wasm_bindgen]
    pub fn decrypt(
        &mut self,
        client_key: &ShortintClientKey,
        ct: &ShortintCiphertext,
    ) -> Result<u64, JsError> {
        self.0
            .decrypt(&client_key.0, &ct.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
    }
}
