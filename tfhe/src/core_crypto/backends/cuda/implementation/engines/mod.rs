//! A module containing the [engines](crate::core_crypto::specification::engines) exposed by
//! the cuda backend.

use crate::core_crypto::backends::cuda::private::device::GpuIndex;

use std::error::Error;
use std::fmt::{Display, Formatter};

mod cuda_engine;
pub use cuda_engine::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedMemoryAmount(pub usize);

#[derive(Debug)]
pub enum CudaError {
    DeviceNotFound,
    SharedMemoryNotFound(GpuIndex),
    NotEnoughDeviceMemory(GpuIndex),
    InvalidDeviceIndex(GpuIndex),
    UnspecifiedDeviceError(GpuIndex),
    PolynomialSizeNotSupported,
    GlweDimensionNotSupported,
    BaseLogNotSupported,
}
impl Display for CudaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CudaError::DeviceNotFound => {
                write!(f, "No GPU detected on the machine.")
            }
            CudaError::SharedMemoryNotFound(gpu_index) => {
                write!(f, "No shared memory detected on the GPU #{}.", gpu_index.0)
            }
            CudaError::NotEnoughDeviceMemory(gpu_index) => {
                write!(
                    f,
                    "The GPU #{} does not have enough global memory to hold all the data.",
                    gpu_index.0
                )
            }
            CudaError::InvalidDeviceIndex(gpu_index) => {
                write!(
                    f,
                    "The specified GPU index, {}, does not exist.",
                    gpu_index.0
                )
            }
            CudaError::PolynomialSizeNotSupported => {
                write!(
                    f,
                    "The polynomial size should be a power of 2. Values strictly lower than \
                512, and strictly greater than 8192, are not supported."
                )
            }
            CudaError::GlweDimensionNotSupported => {
                write!(f, "The only supported GLWE dimension is 1.")
            }
            CudaError::BaseLogNotSupported => {
                write!(f, "The base log has to be lower or equal to 16.")
            }
            CudaError::UnspecifiedDeviceError(gpu_index) => {
                write!(f, "Unspecified device error on GPU #{}.", gpu_index.0)
            }
        }
    }
}

impl Error for CudaError {}

macro_rules! check_glwe_dim {
    ($glwe_dimension: ident) => {
        if $glwe_dimension.0 != 1 {
            return Err(CudaError::GlweDimensionNotSupported.into());
        }
    };
}

macro_rules! check_base_log {
    ($base_log: ident) => {
        if $base_log.0 > 16 {
            return Err(CudaError::BaseLogNotSupported.into());
        }
    };
}

pub(crate) use {check_base_log, check_glwe_dim};
