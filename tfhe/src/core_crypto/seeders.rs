//! This module contains methods to get a random seed.
//!
//! Seeding depends on the underlying OS/hardware. Here, many strategies are proposed to (securely)
//! obtain a seed. A random seed is useful to have compressed keys and is used as a prerequisite
//! for cryptographically secure pseudo random number generators.

pub use crate::core_crypto::commons::math::random::Seeder;
#[cfg(all(target_os = "macos", not(feature = "__wasm_api")))]
pub use tfhe_csprng::seeders::AppleSecureEnclaveSeeder;
#[cfg(all(target_arch = "x86_64", not(feature = "__wasm_api")))]
pub use tfhe_csprng::seeders::RdseedSeeder;
#[cfg(all(target_family = "unix", not(feature = "__wasm_api")))]
pub use tfhe_csprng::seeders::UnixSeeder;

#[cfg(feature = "__wasm_api")]
mod wasm_seeder {
    use crate::core_crypto::commons::math::random::{Seed, Seeder};
    // This is used for web interfaces
    use getrandom::getrandom;

    pub(super) struct WasmSeeder {}

    impl Seeder for WasmSeeder {
        fn seed(&mut self) -> Seed {
            let mut buffer = [0u8; 16];
            getrandom(&mut buffer).unwrap();

            Seed(u128::from_le_bytes(buffer))
        }

        fn is_available() -> bool
        where
            Self: Sized,
        {
            true
        }
    }
}

/// Return an available boxed [`Seeder`] prioritizing hardware entropy sources.
///
/// # Note
///
/// When the `rdseed` CPU feature is detected on `x86_64` CPUs the rdseed seeder is
/// prioritized.
///
/// On macOS the next seeder to be prioritized uses Apple's [`Randomization
/// Service`](`https://developer.apple.com/documentation/security/randomization_services?language=objc`)
/// calling [`SecRandomCopyBytes`](`https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc`).
///
/// On Unix platforms, `/dev/random` is used as a fallback and the quality of the generated seeds
/// depends on the particular implementation of the platform your code is running on.
///
/// For the wasm32 target the [`getrandom`](`https://docs.rs/getrandom/latest/getrandom/`)
/// js random number generator is used as a source of
/// [`cryptographically random numbers per the W3C documentation`](`https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues`).
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
///
/// let first_seed = seeder.seed();
/// let second_seed = seeder.seed();
/// assert_ne!(first_seed, second_seed);
/// ```
pub fn new_seeder() -> Box<dyn Seeder> {
    let mut seeder: Option<Box<dyn Seeder>> = None;

    let err_msg;

    #[cfg(not(feature = "__wasm_api"))]
    {
        #[cfg(target_arch = "x86_64")]
        {
            if RdseedSeeder::is_available() {
                seeder = Some(Box::new(RdseedSeeder::new()));
            }
        }

        // This Seeder is normally always available on macOS, so we enable it by default when on
        // that platform
        #[cfg(target_os = "macos")]
        {
            if seeder.is_none() && AppleSecureEnclaveSeeder::is_available() {
                seeder = Some(Box::new(AppleSecureEnclaveSeeder));
            }
        }

        #[cfg(target_family = "unix")]
        {
            if seeder.is_none() && UnixSeeder::is_available() {
                seeder = Some(Box::new(UnixSeeder::new(0)));
            }
        }

        err_msg = "No compatible seeder for current machine found.";
    }

    #[cfg(feature = "__wasm_api")]
    {
        if seeder.is_none() && wasm_seeder::WasmSeeder::is_available() {
            seeder = Some(Box::new(wasm_seeder::WasmSeeder {}));
        }

        err_msg = "No compatible seeder found. Consider changing browser or dev environment";
    }

    seeder.expect(err_msg)
}
