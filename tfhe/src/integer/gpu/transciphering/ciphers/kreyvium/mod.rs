mod fast_fhe;
#[cfg(all(test, feature = "gpu"))]
mod test;

use crate::integer::gpu::server_key::CudaKreyviumState;

pub type CudaFastKreyviumState = CudaKreyviumState;
