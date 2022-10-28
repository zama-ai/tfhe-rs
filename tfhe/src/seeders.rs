use crate::core_crypto::commons::math::random::Seeder;
#[cfg(target_os = "macos")]
use concrete_csprng::seeders::AppleSecureEnclaveSeeder;
#[cfg(feature = "seeder_x86_64_rdseed")]
use concrete_csprng::seeders::RdseedSeeder;
#[cfg(feature = "seeder_unix")]
use concrete_csprng::seeders::UnixSeeder;

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

pub fn new_seeder() -> Box<dyn Seeder> {
    let mut seeder: Option<Box<dyn Seeder>> = None;

    let err_msg;

    #[cfg(not(feature = "__wasm_api"))]
    {
        #[cfg(feature = "seeder_x86_64_rdseed")]
        {
            if RdseedSeeder::is_available() {
                seeder = Some(Box::new(RdseedSeeder));
            }
        }

        // This Seeder is normally always available on macOS, so we enable it by default when on
        // that platform
        #[cfg(target_os = "macos")]
        {
            if seeder.is_none() && AppleSecureEnclaveSeeder::is_available() {
                seeder = Some(Box::new(AppleSecureEnclaveSeeder))
            }
        }

        #[cfg(feature = "seeder_unix")]
        {
            if seeder.is_none() && UnixSeeder::is_available() {
                seeder = Some(Box::new(UnixSeeder::new(0)));
            }
        }

        #[cfg(not(feature = "__c_api"))]
        {
            err_msg = "Unable to instantiate a seeder, make sure to enable a seeder feature \
    like seeder_unix for example on unix platforms.";
        }

        #[cfg(feature = "__c_api")]
        {
            err_msg = "No compatible seeder for current machine found.";
        }
    }

    #[cfg(feature = "__wasm_api")]
    {
        if seeder.is_none() && wasm_seeder::WasmSeeder::is_available() {
            seeder = Some(Box::new(wasm_seeder::WasmSeeder {}))
        }

        err_msg = "No compatible seeder found. Consider changing browser or dev environment";
    }

    seeder.expect(err_msg)
}
