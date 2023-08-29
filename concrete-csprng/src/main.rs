//! This program uses the concrete csprng to generate an infinite stream of random bytes on
//! the program stdout. For testing purpose.
#[cfg(feature = "generator_x86_64_aesni")]
use concrete_csprng::generators::AesniRandomGenerator as ActivatedRandomGenerator;
#[cfg(feature = "generator_aarch64_aes")]
use concrete_csprng::generators::NeonAesRandomGenerator as ActivatedRandomGenerator;
#[cfg(all(
    not(feature = "generator_x86_64_aesni"),
    not(feature = "generator_aarch64_aes"),
    feature = "generator_fallback"
))]
use concrete_csprng::generators::SoftwareRandomGenerator as ActivatedRandomGenerator;

use concrete_csprng::generators::RandomGenerator;

#[cfg(target_os = "macos")]
use concrete_csprng::seeders::AppleSecureEnclaveSeeder as ActivatedSeeder;
#[cfg(all(not(target_os = "macos"), feature = "seeder_x86_64_rdseed"))]
use concrete_csprng::seeders::RdseedSeeder as ActivatedSeeder;
#[cfg(all(
    not(target_os = "macos"),
    not(feature = "seeder_x86_64_rdseed"),
    feature = "seeder_unix"
))]
use concrete_csprng::seeders::UnixSeeder as ActivatedSeeder;

use concrete_csprng::seeders::Seeder;

use std::io::prelude::*;
use std::io::stdout;

pub fn main() {
    // Ugly hack to be able to use UnixSeeder
    #[cfg(all(
        not(target_os = "macos"),
        not(feature = "seeder_x86_64_rdseed"),
        feature = "seeder_unix"
    ))]
    let new_seeder = || ActivatedSeeder::new(0);
    #[cfg(not(all(
        not(target_os = "macos"),
        not(feature = "seeder_x86_64_rdseed"),
        feature = "seeder_unix"
    )))]
    let new_seeder = || ActivatedSeeder;

    let mut seeder = new_seeder();
    let mut generator = ActivatedRandomGenerator::new(seeder.seed());
    let mut stdout = stdout();
    let mut buffer = [0u8; 16];
    loop {
        buffer
            .iter_mut()
            .zip(&mut generator)
            .for_each(|(b, g)| *b = g);
        stdout.write_all(&buffer).unwrap();
    }
}
