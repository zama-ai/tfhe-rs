use crate::core_crypto::prelude::sealed::AbstractEngineSeal;
use crate::core_crypto::prelude::AbstractEngine;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the executions of the `DefaultSerializationEngine` operations.
#[derive(Debug)]
pub enum DefaultSerializationError {
    Serialization(bincode::Error),
    Deserialization(bincode::Error),
    UnsupportedVersion,
}

#[allow(unused_variables)]
#[allow(unreachable_patterns)]
impl Display for DefaultSerializationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultSerializationError::Serialization(bincode_error) => {
                write!(f, "Failed to serialize entity: {bincode_error}")
            }
            DefaultSerializationError::Deserialization(bincode_error) => {
                write!(f, "Failed to deserialize entity: {bincode_error}")
            }
            DefaultSerializationError::UnsupportedVersion => {
                write!(
                    f,
                    "The version used to serialize the entity is not supported."
                )
            }
        }
    }
}

impl Error for DefaultSerializationError {}

pub struct DefaultSerializationEngine;

impl AbstractEngineSeal for DefaultSerializationEngine {}

impl AbstractEngine for DefaultSerializationEngine {
    type EngineError = DefaultSerializationError;
    type Parameters = ();

    fn new(_parameter: Self::Parameters) -> Result<Self, Self::EngineError>
    where
        Self: Sized,
    {
        Ok(DefaultSerializationEngine)
    }
}

mod entity_deserialization;
mod entity_serialization;
