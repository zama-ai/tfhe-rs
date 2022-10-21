#![doc(hidden)]

// ----------------------------------------------------------------------------------- SPECIFICATION
pub use super::specification::engines::*;
pub use super::specification::entities::*;

// --------------------------------------------------------------------------------- DEFAULT BACKEND
#[cfg(feature = "backend_default")]
pub use super::backends::default::engines::*;
#[cfg(feature = "backend_default")]
pub use super::backends::default::entities::*;

// --------------------------------------------------------------------------------- FFT BACKEND
#[cfg(feature = "backend_fft")]
pub use super::backends::fft::engines::*;
#[cfg(feature = "backend_fft")]
pub use super::backends::fft::entities::*;

// ------------------------------------------------------------------------------------ CUDA BACKEND
#[cfg(feature = "backend_cuda")]
pub use super::backends::cuda::engines::*;
#[cfg(feature = "backend_cuda")]
pub use super::backends::cuda::entities::*;

// -------------------------------------------------------------------------------- COMMONS REEXPORT
pub use super::specification::dispersion::*;
pub use super::specification::key_kinds::*;
pub use super::specification::parameters::*;
pub use super::specification::*;

// --------------------------------------------------------------------------------- CSPRNG REEXPORT
// Re-export the different seeders of the `concrete-csprng` crate, which are needed to construct
// default engines.
#[cfg(target_os = "macos")]
pub use concrete_csprng::seeders::AppleSecureEnclaveSeeder;
#[cfg(feature = "seeder_x86_64_rdseed")]
pub use concrete_csprng::seeders::RdseedSeeder;
pub use concrete_csprng::seeders::Seeder;
#[cfg(feature = "seeder_unix")]
pub use concrete_csprng::seeders::UnixSeeder;
