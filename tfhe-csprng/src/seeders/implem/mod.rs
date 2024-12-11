#[cfg(target_os = "macos")]
mod apple_secure_enclave_seeder;
#[cfg(target_os = "macos")]
pub use apple_secure_enclave_seeder::AppleSecureEnclaveSeeder;

#[cfg(target_arch = "x86_64")]
mod rdseed;
#[cfg(target_arch = "x86_64")]
pub use rdseed::RdseedSeeder;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use unix::UnixSeeder;
