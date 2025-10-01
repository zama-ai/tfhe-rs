pub mod lwe_keyswitch;
pub mod lwe_multi_bit_programmable_bootstrap;
pub mod lwe_packing_keyswitch;
pub mod lwe_programmable_bootstrap;
pub mod modulus_switch;
pub mod traits;

pub use lwe_keyswitch::NoiseSimulationLweKeyswitchKey;
pub use lwe_packing_keyswitch::NoiseSimulationLwePackingKeyswitchKey;
pub use lwe_programmable_bootstrap::{
    NoiseSimulationLweFourier128Bsk, NoiseSimulationLweFourierBsk,
};

use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLweBootstrapResult, AllocateLweMultiBitBlindRotateResult, LweUncorrelatedAdd,
    LweUncorrelatedSub, ScalarMul, ScalarMulAssign,
};
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, GlweDimension, LweDimension, PolynomialSize,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoiseSimulationModulus {
    NativeU128,
    Other(u128),
}

impl NoiseSimulationModulus {
    pub fn from_ciphertext_modulus<Scalar: UnsignedInteger>(
        modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let modulus_scalar_bits = modulus.associated_scalar_bits();

        assert!(
            modulus_scalar_bits <= 128,
            "Unsupported bit width: {modulus_scalar_bits}",
        );

        if modulus.is_native_modulus() {
            if modulus_scalar_bits == 128 {
                Self::NativeU128
            } else {
                Self::Other(1 << modulus_scalar_bits)
            }
        } else {
            Self::Other(modulus.get_custom_modulus())
        }
    }

    pub fn from_ciphertext_modulus_log(modulus_log: CiphertextModulusLog) -> Self {
        assert!(
            modulus_log.0 <= 128,
            "Unsupported bit width: {modulus_log:?}",
        );

        if modulus_log.0 == 128 {
            Self::NativeU128
        } else {
            Self::Other(1 << modulus_log.0)
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            Self::NativeU128 => 2.0f64.powi(128),
            Self::Other(val) => *val as f64,
        }
    }
}

// Avoids fields to be public/accessible in the noise_simulation module to make sure all functions
// use constructors
mod simulation_ciphertexts {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct NoiseSimulationLwe {
        lwe_dimension: LweDimension,
        variance: Variance,
        modulus: NoiseSimulationModulus,
    }

    impl NoiseSimulationLwe {
        pub fn new(
            lwe_dimension: LweDimension,
            variance: Variance,
            modulus: NoiseSimulationModulus,
        ) -> Self {
            Self {
                lwe_dimension,
                variance,
                modulus,
            }
        }

        pub fn lwe_dimension(&self) -> LweDimension {
            self.lwe_dimension
        }

        pub fn variance(&self) -> Variance {
            self.variance
        }

        pub fn modulus(&self) -> NoiseSimulationModulus {
            self.modulus
        }
    }

    impl<Scalar: CastInto<f64>> ScalarMul<Scalar> for NoiseSimulationLwe {
        type Output = Self;
        type SideResources = ();

        fn scalar_mul(
            &self,
            rhs: Scalar,
            side_resources: &mut Self::SideResources,
        ) -> Self::Output {
            let mut output = *self;
            output.scalar_mul_assign(rhs, side_resources);
            output
        }
    }

    impl<Scalar: CastInto<f64>> ScalarMulAssign<Scalar> for NoiseSimulationLwe {
        type SideResources = ();

        fn scalar_mul_assign(&mut self, rhs: Scalar, _side_resources: &mut Self::SideResources) {
            let rhs: f64 = rhs.cast_into();
            self.variance.0 *= rhs.powi(2);
        }
    }

    impl<'rhs> LweUncorrelatedAdd<&'rhs Self> for NoiseSimulationLwe {
        type Output = Self;
        type SideResources = ();

        fn lwe_uncorrelated_add(
            &self,
            rhs: &'rhs Self,
            _side_resources: &mut Self::SideResources,
        ) -> Self::Output {
            assert_eq!(self.lwe_dimension(), rhs.lwe_dimension());
            assert_eq!(self.modulus(), rhs.modulus());

            Self::Output::new(
                self.lwe_dimension(),
                Variance(self.variance().0 + rhs.variance().0),
                self.modulus(),
            )
        }
    }

    impl<'rhs> LweUncorrelatedSub<&'rhs Self> for NoiseSimulationLwe {
        type Output = Self;
        type SideResources = ();

        fn lwe_uncorrelated_sub(
            &self,
            rhs: &'rhs Self,
            _side_resources: &mut Self::SideResources,
        ) -> Self::Output {
            assert_eq!(self.lwe_dimension(), rhs.lwe_dimension());
            assert_eq!(self.modulus(), rhs.modulus());

            Self::Output::new(
                self.lwe_dimension(),
                Variance(self.variance().0 + rhs.variance().0),
                self.modulus(),
            )
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct NoiseSimulationGlwe {
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        variance_per_occupied_slot: Variance,
        modulus: NoiseSimulationModulus,
    }

    impl NoiseSimulationGlwe {
        pub fn new(
            glwe_dimension: GlweDimension,
            polynomial_size: PolynomialSize,
            variance_per_occupied_slot: Variance,
            modulus: NoiseSimulationModulus,
        ) -> Self {
            Self {
                glwe_dimension,
                polynomial_size,
                variance_per_occupied_slot,
                modulus,
            }
        }

        pub fn into_lwe(self) -> NoiseSimulationLwe {
            let lwe_dimension = self
                .glwe_dimension()
                .to_equivalent_lwe_dimension(self.polynomial_size());
            NoiseSimulationLwe {
                lwe_dimension,
                variance: self.variance_per_occupied_slot(),
                modulus: self.modulus(),
            }
        }

        pub fn glwe_dimension(&self) -> GlweDimension {
            self.glwe_dimension
        }

        pub fn polynomial_size(&self) -> PolynomialSize {
            self.polynomial_size
        }

        pub fn variance_per_occupied_slot(&self) -> Variance {
            self.variance_per_occupied_slot
        }

        pub fn modulus(&self) -> NoiseSimulationModulus {
            self.modulus
        }
    }

    impl AllocateLweBootstrapResult for NoiseSimulationGlwe {
        type Output = NoiseSimulationLwe;
        type SideResources = ();

        fn allocate_lwe_bootstrap_result(
            &self,
            _side_resources: &mut Self::SideResources,
        ) -> Self::Output {
            let lwe_dimension = self
                .glwe_dimension()
                .to_equivalent_lwe_dimension(self.polynomial_size());

            Self::Output {
                lwe_dimension,
                variance: self.variance_per_occupied_slot(),
                modulus: self.modulus(),
            }
        }
    }

    impl AllocateLweMultiBitBlindRotateResult for NoiseSimulationGlwe {
        type Output = NoiseSimulationLwe;
        type SideResources = ();

        fn allocate_lwe_multi_bit_blind_rotate_result(
            &self,
            _side_resources: &mut Self::SideResources,
        ) -> Self::Output {
            let lwe_dimension = self
                .glwe_dimension()
                .to_equivalent_lwe_dimension(self.polynomial_size());

            Self::Output {
                lwe_dimension,
                variance: self.variance_per_occupied_slot(),
                modulus: self.modulus(),
            }
        }
    }
}

pub use simulation_ciphertexts::{NoiseSimulationGlwe, NoiseSimulationLwe};
