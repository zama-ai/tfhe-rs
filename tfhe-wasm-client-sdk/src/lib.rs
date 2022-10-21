#![allow(clippy::boxed_local)]
use wasm_bindgen::prelude::*;

pub mod core_crypto;
pub use core_crypto::*;

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

mod seeder {
    use js_sys::{Function, Uint8Array};
    use std::panic;
    use tfhe::core_crypto::commons::math::random::Seed;
    use tfhe::core_crypto::prelude::Seeder;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsValue;

    const SEED_BYTES_COUNT: usize = 16;

    #[wasm_bindgen]
    pub struct JsFunctionSeeder {
        js_func: Function,
        buffer: [u8; SEED_BYTES_COUNT],
    }

    #[wasm_bindgen]
    impl JsFunctionSeeder {
        #[wasm_bindgen(constructor)]
        pub fn new(js_func: Function) -> JsFunctionSeeder {
            panic::set_hook(Box::new(console_error_panic_hook::hook));
            let buffer = [0u8; SEED_BYTES_COUNT];
            JsFunctionSeeder { js_func, buffer }
        }
    }

    impl Seeder for JsFunctionSeeder {
        fn seed(&mut self) -> Seed {
            let output = self.js_func.call0(&JsValue::NULL).unwrap();
            let array = Uint8Array::new(&output);
            if array.length() as usize != SEED_BYTES_COUNT {
                panic!("The seeder function must return a Uint8Array of size 16.");
            }
            array.copy_to(&mut self.buffer);
            let seed = u128::from_le_bytes(self.buffer);
            Seed(seed)
        }

        fn is_available() -> bool
        where
            Self: Sized,
        {
            true
        }
    }
}
pub use seeder::*;
