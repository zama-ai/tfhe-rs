mod fast_fhe;
#[cfg(test)]
mod test;

use crate::integer::gpu::server_key::CudaKreyviumState;

pub type CudaFastKreyviumState = CudaKreyviumState;
