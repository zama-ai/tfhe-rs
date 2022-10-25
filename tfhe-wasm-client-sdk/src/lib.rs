use bincode;
use wasm_bindgen::prelude::*;

pub mod core_crypto;
pub use core_crypto::*;

pub mod shortints;
pub use shortints::*;

pub mod booleans;
pub use booleans::*;

use std::panic::set_hook;

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

    pub struct ConstantSeeder {
        seed: Seed,
    }

    impl ConstantSeeder {
        pub fn new(seed: Seed) -> Self {
            Self { seed }
        }
    }

    impl Seeder for ConstantSeeder {
        fn seed(&mut self) -> Seed {
            self.seed
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
