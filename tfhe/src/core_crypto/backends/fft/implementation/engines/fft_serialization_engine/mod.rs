use crate::core_crypto::specification::engines::sealed::AbstractEngineSeal;
use crate::core_crypto::specification::engines::AbstractEngine;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of FHE operations, due to the FFT implementation.
#[derive(Debug)]
pub enum FftSerializationError {
    Serialization(bincode::Error),
    Deserialization(bincode::Error),
    UnsupportedVersion,
}

impl Display for FftSerializationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FftSerializationError::Serialization(bincode_error) => {
                write!(f, "Failed to serialize entity: {bincode_error}")
            }
            FftSerializationError::Deserialization(bincode_error) => {
                write!(f, "Failed to deserialize entity: {bincode_error}")
            }
            FftSerializationError::UnsupportedVersion => {
                write!(
                    f,
                    "The version used to serialize the entity is not supported."
                )
            }
        }
    }
}

impl Error for FftSerializationError {}

/// The serialization engine exposed by the fft backend.
pub struct FftSerializationEngine;

impl AbstractEngineSeal for FftSerializationEngine {}

impl AbstractEngine for FftSerializationEngine {
    type EngineError = FftSerializationError;
    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(FftSerializationEngine)
    }
}

mod deserialization;
mod serialization;
