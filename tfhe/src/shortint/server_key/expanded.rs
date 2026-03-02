use crate::core_crypto::prelude::*;

use super::{GenericServerKey, ModulusSwitchConfiguration, ShortintBootstrappingKey};
use crate::shortint::atomic_pattern::expanded::ExpandedAtomicPatternServerKey;
use crate::shortint::noise_squashing::Shortint128BootstrappingKey;

pub type ShortintExpandedServerKey = GenericServerKey<ExpandedAtomicPatternServerKey>;

/// Bootstrapping Key with elements in the standard (i.e not fourier) domain
#[derive(PartialEq)]
pub enum ShortintExpandedBootstrappingKey<Scalar, ModSwitchScalar>
where
    Scalar: UnsignedInteger,
    ModSwitchScalar: UnsignedInteger,
{
    Classic {
        bsk: LweBootstrapKey<Vec<Scalar>>,
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<ModSwitchScalar>,
    },
    MultiBit {
        bsk: LweMultiBitBootstrapKey<Vec<Scalar>>,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

impl<Scalar, ModSwitchScalar> ShortintExpandedBootstrappingKey<Scalar, ModSwitchScalar>
where
    Scalar: UnsignedInteger,
    ModSwitchScalar: UnsignedInteger,
{
    pub fn glwe_dimension(&self) -> GlweDimension {
        match self {
            Self::Classic { bsk, .. } => bsk.glwe_size().to_glwe_dimension(),
            Self::MultiBit { bsk, .. } => bsk.glwe_size().to_glwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic { bsk, .. } => bsk.polynomial_size(),
            Self::MultiBit { bsk, .. } => bsk.polynomial_size(),
        }
    }
}

impl<ModSwitchScalar> ShortintExpandedBootstrappingKey<u64, ModSwitchScalar>
where
    ModSwitchScalar: UnsignedInteger,
{
    pub fn into_fourier(self) -> ShortintBootstrappingKey<ModSwitchScalar> {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let mut fourier_bsk = FourierLweBootstrapKey::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                );
                par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
                ShortintBootstrappingKey::Classic {
                    bsk: fourier_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                bsk,
                thread_count,
                deterministic_execution,
            } => {
                let mut fourier_bsk = FourierLweMultiBitBootstrapKeyOwned::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                    bsk.grouping_factor(),
                );
                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                }
            }
        }
    }
}

impl<ModSwitchScalar> ShortintExpandedBootstrappingKey<u128, ModSwitchScalar>
where
    ModSwitchScalar: UnsignedInteger,
{
    pub fn into_fourier(self) -> Shortint128BootstrappingKey<ModSwitchScalar> {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let mut fourier_bsk = Fourier128LweBootstrapKeyOwned::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                );
                par_convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk, &mut fourier_bsk);
                Shortint128BootstrappingKey::Classic {
                    bsk: fourier_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                bsk,
                thread_count,
                deterministic_execution,
            } => {
                let mut fourier_bsk = Fourier128LweMultiBitBootstrapKey::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                    bsk.grouping_factor(),
                );

                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128(
                    &bsk,
                    &mut fourier_bsk,
                );

                Shortint128BootstrappingKey::MultiBit {
                    bsk: fourier_bsk,
                    thread_count,
                    deterministic_execution,
                }
            }
        }
    }
}

impl ShortintExpandedServerKey {
    pub fn glwe_dimension(&self) -> GlweDimension {
        match &self.atomic_pattern {
            ExpandedAtomicPatternServerKey::Standard(std) => std.bootstrapping_key.glwe_dimension(),
            ExpandedAtomicPatternServerKey::KeySwitch32(ks32) => {
                ks32.bootstrapping_key.glwe_dimension()
            }
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match &self.atomic_pattern {
            ExpandedAtomicPatternServerKey::Standard(std) => {
                std.bootstrapping_key.polynomial_size()
            }
            ExpandedAtomicPatternServerKey::KeySwitch32(ks32) => {
                ks32.bootstrapping_key.polynomial_size()
            }
        }
    }
}
