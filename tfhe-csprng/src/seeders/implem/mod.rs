#[cfg(target_os = "macos")]
mod apple_secure_enclave_seeder;
#[cfg(target_os = "macos")]
pub use apple_secure_enclave_seeder::AppleSecureEnclaveSeeder;

#[cfg(feature = "seeder_x86_64_rdseed")]
mod rdseed;
#[cfg(feature = "seeder_x86_64_rdseed")]
pub use rdseed::RdseedSeeder;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use unix::UnixSeeder;
