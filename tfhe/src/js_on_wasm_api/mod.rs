#[cfg(feature = "shortints-client-js-wasm-api")]
pub mod shortints;
#[cfg(feature = "shortints-client-js-wasm-api")]
pub use shortints::*;

#[cfg(feature = "booleans-client-js-wasm-api")]
pub mod booleans;
#[cfg(feature = "booleans-client-js-wasm-api")]
pub use booleans::*;

pub(self) mod js_wasm_seeder {
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::prelude::Seeder;

    const SEED_BYTES_COUNT: usize = 16;

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
