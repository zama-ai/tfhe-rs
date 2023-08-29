#[cfg(target_os = "macos")]
mod apple_secure_enclave_seeder;
#[cfg(target_os = "macos")]
pub use apple_secure_enclave_seeder::AppleSecureEnclaveSeeder;

#[cfg(feature = "seeder_x86_64_rdseed")]
mod rdseed;
#[cfg(feature = "seeder_x86_64_rdseed")]
pub use rdseed::RdseedSeeder;

#[cfg(feature = "seeder_unix")]
mod unix;
#[cfg(feature = "seeder_unix")]
pub use unix::UnixSeeder;
