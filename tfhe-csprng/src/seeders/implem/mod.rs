#[cfg(target_os = "macos")]
mod apple_secure_enclave_seeder;
#[cfg(target_os = "macos")]
pub use apple_secure_enclave_seeder::AppleSecureEnclaveSeeder;

#[cfg(target_arch = "x86_64")]
mod rdseed;
#[cfg(target_arch = "x86_64")]
pub use rdseed::RdseedSeeder;

#[cfg(any(target_family = "unix", target_os = "windows"))]
mod unix;
#[cfg(any(target_family = "unix", target_os = "windows"))]
pub use unix::UnixSeeder;
