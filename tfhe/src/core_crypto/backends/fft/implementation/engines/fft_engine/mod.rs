use crate::core_crypto::prelude::PolynomialSize;
use dyn_stack::DynStack;

use crate::core_crypto::specification::engines::sealed::AbstractEngineSeal;
use crate::core_crypto::specification::engines::AbstractEngine;
use core::mem::MaybeUninit;

/// Error that can occur in the execution of FHE operations by the [`FftEngine`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FftError {
    UnsupportedPolynomialSize,
}

impl core::fmt::Display for FftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FftError::UnsupportedPolynomialSize => f.write_str(
                "The Concrete-FFT backend only supports polynomials of sizes that are powers of two \
                    and greater than or equal to 32.",
            ),
        }
    }
}

impl std::error::Error for FftError {}

impl FftError {
    pub fn perform_fft_checks(polynomial_size: PolynomialSize) -> Result<(), FftError> {
        if polynomial_size.0.is_power_of_two() && polynomial_size.0 >= 32 {
            Ok(())
        } else {
            Err(FftError::UnsupportedPolynomialSize)
        }
    }
}

/// The main engine exposed by the Concrete-FFT backend.
pub struct FftEngine {
    memory: Vec<MaybeUninit<u8>>,
}

impl FftEngine {
    pub(crate) fn resize(&mut self, capacity: usize) {
        self.memory.resize_with(capacity, MaybeUninit::uninit);
    }

    pub(crate) fn stack(&mut self) -> DynStack<'_> {
        DynStack::new(&mut self.memory)
    }
}

impl AbstractEngineSeal for FftEngine {}
impl AbstractEngine for FftEngine {
    type EngineError = FftError;
    type Parameters = ();

    fn new(_parameter: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(FftEngine { memory: Vec::new() })
    }
}

mod lwe_bootstrap_key_conversion;
mod lwe_ciphertext_discarding_bit_extraction;
mod lwe_ciphertext_discarding_bootstrap;
mod lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing;

// mod ggsw_ciphertext_conversion;
// mod ggsw_ciphertext_discarding_conversion;
// mod glwe_ciphertext_ggsw_ciphertext_discarding_external_product;
// mod glwe_ciphertexts_ggsw_ciphertext_fusing_cmux;
// mod lwe_ciphertext_discarding_circuit_bootstrap_boolean;
