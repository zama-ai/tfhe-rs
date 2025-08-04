use super::traits::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::noise_formulas::lwe_keyswitch::{
    keyswitch_additive_variance_132_bits_security_gaussian,
    keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_packing_keyswitch::{
    packing_keyswitch_additive_variance_132_bits_security_gaussian,
    packing_keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap::{
    pbs_variance_132_bits_security_gaussian_fft_mul,
    pbs_variance_132_bits_security_tuniform_fft_mul,
};
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap_128::{
    pbs_128_variance_132_bits_security_gaussian_fft_mul,
    pbs_128_variance_132_bits_security_tuniform_fft_mul,
};
use crate::core_crypto::commons::noise_formulas::modulus_switch::modulus_switch_additive_variance;
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, GlweSize, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::container::Container;
use crate::core_crypto::entities::lwe_keyswitch_key::LweKeyswitchKey;
use crate::core_crypto::entities::lwe_packing_keyswitch_key::LwePackingKeyswitchKey;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::c64;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;

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

        if modulus_scalar_bits == 128 {
            if modulus.is_native_modulus() {
                Self::NativeU128
            } else {
                Self::Other(modulus.get_custom_modulus())
            }
        } else {
            Self::Other(1u128 << modulus_scalar_bits)
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

    fn scalar_mul(&self, rhs: Scalar, side_resources: &mut Self::SideResources) -> Self::Output {
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

#[derive(Clone, Copy)]
pub struct NoiseSimulationLweKsk {
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    noise_distribution: DynamicDistribution<u64>,
    output_modulus: NoiseSimulationModulus,
}

impl NoiseSimulationLweKsk {
    pub fn new(
        input_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise_distribution: DynamicDistribution<u64>,
        output_modulus: NoiseSimulationModulus,
    ) -> Self {
        Self {
            input_lwe_dimension,
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            noise_distribution,
            output_modulus,
        }
    }

    pub fn matches_actual_ksk<Scalar: UnsignedInteger, C: Container<Element = Scalar>>(
        &self,
        lwe_ksk: &LweKeyswitchKey<C>,
    ) -> bool {
        let Self {
            input_lwe_dimension,
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
            noise_distribution: _,
            output_modulus,
        } = *self;

        let ksk_input_lwe_dimension = lwe_ksk.input_key_lwe_dimension();
        let ksk_output_lwe_dimension = lwe_ksk.output_key_lwe_dimension();
        let ksk_decomp_base_log = lwe_ksk.decomposition_base_log();
        let ksk_decomp_level_count = lwe_ksk.decomposition_level_count();
        let ksk_output_modulus =
            NoiseSimulationModulus::from_ciphertext_modulus(lwe_ksk.ciphertext_modulus());

        input_lwe_dimension == ksk_input_lwe_dimension
            && output_lwe_dimension == ksk_output_lwe_dimension
            && decomposition_base_log == ksk_decomp_base_log
            && decomposition_level_count == ksk_decomp_level_count
            && output_modulus == ksk_output_modulus
    }
}

impl AllocateKeyswtichResult for NoiseSimulationLweKsk {
    type Output = NoiseSimulationLwe;
    type SideResources = ();

    fn allocate_keyswitch_result(&self, _side_resources: &mut Self::SideResources) -> Self::Output {
        Self::Output {
            lwe_dimension: self.output_lwe_dimension,
            variance: Variance(-2.0f64.powi(128)),
            modulus: self.output_modulus,
        }
    }
}

impl Keyswitch<NoiseSimulationLwe, NoiseSimulationLwe> for NoiseSimulationLweKsk {
    type SideResources = ();

    fn keyswitch(
        &self,
        input: &NoiseSimulationLwe,
        output: &mut NoiseSimulationLwe,
        _side_resources: &mut Self::SideResources,
    ) {
        assert_eq!(input.lwe_dimension, self.input_lwe_dimension);

        let ks_additive_var = match self.noise_distribution {
            DynamicDistribution::Gaussian(_) => {
                keyswitch_additive_variance_132_bits_security_gaussian(
                    self.input_lwe_dimension,
                    self.output_lwe_dimension,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                    input.modulus.as_f64(),
                    self.output_modulus.as_f64(),
                )
            }
            DynamicDistribution::TUniform(_) => {
                keyswitch_additive_variance_132_bits_security_tuniform(
                    self.input_lwe_dimension,
                    self.output_lwe_dimension,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                    input.modulus.as_f64(),
                    self.output_modulus.as_f64(),
                )
            }
        };

        output.lwe_dimension = self.output_lwe_dimension;
        output.variance = Variance(input.variance.0 + ks_additive_var.0);
        output.modulus = self.output_modulus;
    }
}

impl AllocateStandardPBSModSwitchResult for NoiseSimulationLwe {
    type Output = Self;
    type SideResources = ();

    fn allocate_standard_mod_switch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        Self {
            lwe_dimension: self.lwe_dimension,
            variance: Variance(-2.0f64.powi(128)),
            modulus: self.modulus(),
        }
    }
}

impl StandardPBSModSwitch<Self> for NoiseSimulationLwe {
    type SideResources = ();

    fn standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Self,
        _side_resources: &mut Self::SideResources,
    ) {
        let simulation_after_mod_switch_modulus =
            NoiseSimulationModulus::from_ciphertext_modulus_log(output_modulus_log);

        let input_modulus_f64 = self.modulus().as_f64();
        let output_modulus_f64 = simulation_after_mod_switch_modulus.as_f64();

        assert!(output_modulus_f64 < input_modulus_f64);

        let mod_switch_additive_variance = modulus_switch_additive_variance(
            self.lwe_dimension,
            input_modulus_f64,
            output_modulus_f64,
        );

        output.lwe_dimension = self.lwe_dimension;
        // Mod switched but the noise is to be interpreted with respect to the input modulus, as
        // strictly the operation adding the noise is the rounding under the original rounding
        output.modulus = self.modulus;
        output.variance = Variance(self.variance.0 + mod_switch_additive_variance.0)
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

impl AllocateBootstrapResult for NoiseSimulationGlwe {
    type Output = NoiseSimulationLwe;
    type SideResources = ();

    fn allocate_bootstrap_result(&self, _side_resources: &mut Self::SideResources) -> Self::Output {
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

#[derive(Clone, Copy)]
pub struct NoiseSimulationLweFourier128Bsk {
    input_lwe_dimension: LweDimension,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: DynamicDistribution<u128>,
    modulus: NoiseSimulationModulus,
}

impl NoiseSimulationLweFourier128Bsk {
    pub fn new(
        input_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        noise_distribution: DynamicDistribution<u128>,
        modulus: NoiseSimulationModulus,
    ) -> Self {
        Self {
            input_lwe_dimension,
            output_glwe_size,
            output_polynomial_size,
            decomp_base_log,
            decomp_level_count,
            noise_distribution,
            modulus,
        }
    }

    pub fn matches_actual_bsk<C: Container<Element = f64>>(
        &self,
        lwe_bsk: &Fourier128LweBootstrapKey<C>,
    ) -> bool {
        let Self {
            input_lwe_dimension,
            output_glwe_size: glwe_size,
            output_polynomial_size: polynomial_size,
            decomp_base_log,
            decomp_level_count,
            noise_distribution: _,
            modulus: _,
        } = *self;

        let bsk_input_lwe_dimension = lwe_bsk.input_lwe_dimension();
        let bsk_glwe_size = lwe_bsk.glwe_size();
        let bsk_polynomial_size = lwe_bsk.polynomial_size();
        let bsk_decomp_base_log = lwe_bsk.decomposition_base_log();
        let bsk_decomp_level_count = lwe_bsk.decomposition_level_count();

        input_lwe_dimension == bsk_input_lwe_dimension
            && glwe_size == bsk_glwe_size
            && polynomial_size == bsk_polynomial_size
            && decomp_base_log == bsk_decomp_base_log
            && decomp_level_count == bsk_decomp_level_count
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    pub fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn noise_distribution(&self) -> DynamicDistribution<u128> {
        self.noise_distribution
    }

    pub fn modulus(&self) -> NoiseSimulationModulus {
        self.modulus
    }
}

impl StandardFft128Bootstrap<NoiseSimulationLwe, NoiseSimulationLwe, NoiseSimulationGlwe>
    for NoiseSimulationLweFourier128Bsk
{
    type SideResources = ();

    fn standard_fft_128_pbs(
        &self,
        input: &NoiseSimulationLwe,
        output: &mut NoiseSimulationLwe,
        accumulator: &NoiseSimulationGlwe,
        _side_resources: &mut Self::SideResources,
    ) {
        assert_eq!(self.input_lwe_dimension(), input.lwe_dimension());
        assert_eq!(
            self.output_glwe_size(),
            accumulator.glwe_dimension().to_glwe_size()
        );
        assert_eq!(self.output_polynomial_size(), accumulator.polynomial_size());
        assert_eq!(self.modulus(), accumulator.modulus());

        let br_additive_variance = match self.noise_distribution() {
            DynamicDistribution::Gaussian(_) => {
                pbs_128_variance_132_bits_security_gaussian_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    // Current PBS 128 implem has 104 bits of equivalent mantissa
                    104.0f64,
                    self.modulus().as_f64(),
                )
            }
            DynamicDistribution::TUniform(_) => {
                pbs_128_variance_132_bits_security_tuniform_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    // Current PBS 128 implem has 104 bits of equivalent mantissa
                    104.0f64,
                    self.modulus().as_f64(),
                )
            }
        };

        let output_lwe_dimension = self
            .output_glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.output_polynomial_size());

        output.lwe_dimension = output_lwe_dimension;
        output.variance =
            Variance(accumulator.variance_per_occupied_slot().0 + br_additive_variance.0);
        output.modulus = accumulator.modulus;
    }
}

#[derive(Clone, Copy)]
pub struct NoiseSimulationLweFourierBsk {
    input_lwe_dimension: LweDimension,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: DynamicDistribution<u64>,
    modulus: NoiseSimulationModulus,
}

impl NoiseSimulationLweFourierBsk {
    pub fn new(
        input_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        noise_distribution: DynamicDistribution<u64>,
        modulus: NoiseSimulationModulus,
    ) -> Self {
        Self {
            input_lwe_dimension,
            output_glwe_size,
            output_polynomial_size,
            decomp_base_log,
            decomp_level_count,
            noise_distribution,
            modulus,
        }
    }

    pub fn matches_actual_bsk<C: Container<Element = c64>>(
        &self,
        lwe_bsk: &FourierLweBootstrapKey<C>,
    ) -> bool {
        let Self {
            input_lwe_dimension,
            output_glwe_size: glwe_size,
            output_polynomial_size: polynomial_size,
            decomp_base_log,
            decomp_level_count,
            noise_distribution: _,
            modulus: _,
        } = *self;

        let bsk_input_lwe_dimension = lwe_bsk.input_lwe_dimension();
        let bsk_glwe_size = lwe_bsk.glwe_size();
        let bsk_polynomial_size = lwe_bsk.polynomial_size();
        let bsk_decomp_base_log = lwe_bsk.decomposition_base_log();
        let bsk_decomp_level_count = lwe_bsk.decomposition_level_count();

        input_lwe_dimension == bsk_input_lwe_dimension
            && glwe_size == bsk_glwe_size
            && polynomial_size == bsk_polynomial_size
            && decomp_base_log == bsk_decomp_base_log
            && decomp_level_count == bsk_decomp_level_count
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    pub fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn noise_distribution(&self) -> DynamicDistribution<u64> {
        self.noise_distribution
    }

    pub fn modulus(&self) -> NoiseSimulationModulus {
        self.modulus
    }
}

impl StandardFftBootstrap<NoiseSimulationLwe, NoiseSimulationLwe, NoiseSimulationGlwe>
    for NoiseSimulationLweFourierBsk
{
    type SideResources = ();

    fn standard_fft_pbs(
        &self,
        input: &NoiseSimulationLwe,
        output: &mut NoiseSimulationLwe,
        accumulator: &NoiseSimulationGlwe,
        _side_resources: &mut Self::SideResources,
    ) {
        assert_eq!(self.input_lwe_dimension(), input.lwe_dimension());
        assert_eq!(
            self.output_glwe_size(),
            accumulator.glwe_dimension().to_glwe_size()
        );
        assert_eq!(self.output_polynomial_size(), accumulator.polynomial_size());
        assert_eq!(self.modulus(), accumulator.modulus());

        let br_additive_variance = match self.noise_distribution() {
            DynamicDistribution::Gaussian(_) => pbs_variance_132_bits_security_gaussian_fft_mul(
                self.input_lwe_dimension(),
                self.output_glwe_size().to_glwe_dimension(),
                self.output_polynomial_size(),
                self.decomp_base_log(),
                self.decomp_level_count(),
                self.modulus().as_f64(),
            ),
            DynamicDistribution::TUniform(_) => pbs_variance_132_bits_security_tuniform_fft_mul(
                self.input_lwe_dimension(),
                self.output_glwe_size().to_glwe_dimension(),
                self.output_polynomial_size(),
                self.decomp_base_log(),
                self.decomp_level_count(),
                self.modulus().as_f64(),
            ),
        };

        let output_lwe_dimension = self
            .output_glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.output_polynomial_size());

        output.lwe_dimension = output_lwe_dimension;
        output.variance =
            Variance(accumulator.variance_per_occupied_slot().0 + br_additive_variance.0);
        output.modulus = accumulator.modulus;
    }
}

#[derive(Clone, Copy)]
pub struct NoiseSimulationLwePackingKeyswitchKey {
    input_lwe_dimension: LweDimension,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    noise_distribution: DynamicDistribution<u128>,
    modulus: NoiseSimulationModulus,
}

impl NoiseSimulationLwePackingKeyswitchKey {
    pub fn new(
        input_lwe_dimension: LweDimension,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        noise_distribution: DynamicDistribution<u128>,
        modulus: NoiseSimulationModulus,
    ) -> Self {
        Self {
            input_lwe_dimension,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            noise_distribution,
            modulus,
        }
    }

    pub fn matches_actual_pksk<Scalar: UnsignedInteger, KeyCont: Container<Element = Scalar>>(
        &self,
        pksk: &LwePackingKeyswitchKey<KeyCont>,
    ) -> bool {
        let Self {
            input_lwe_dimension,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            noise_distribution: _,
            modulus,
        } = *self;

        let pksk_input_lwe_dimension = pksk.input_key_lwe_dimension();
        let pksk_decomp_base_log = pksk.decomposition_base_log();
        let pksk_decomp_level_count = pksk.decomposition_level_count();
        let pksk_output_glwe_size = pksk.output_glwe_size();
        let pksk_output_polynomial_size = pksk.output_key_polynomial_size();
        let pksk_modulus =
            NoiseSimulationModulus::from_ciphertext_modulus(pksk.ciphertext_modulus());

        input_lwe_dimension == pksk_input_lwe_dimension
            && decomp_base_log == pksk_decomp_base_log
            && decomp_level_count == pksk_decomp_level_count
            && output_glwe_size == pksk_output_glwe_size
            && output_polynomial_size == pksk_output_polynomial_size
            && modulus == pksk_modulus
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    pub fn noise_distribution(&self) -> DynamicDistribution<u128> {
        self.noise_distribution
    }

    pub fn modulus(&self) -> NoiseSimulationModulus {
        self.modulus
    }
}

impl AllocatePackingKeyswitchResult for NoiseSimulationLwePackingKeyswitchKey {
    type Output = NoiseSimulationGlwe;
    type SideResources = ();

    fn allocate_packing_keyswitch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        Self::Output {
            glwe_dimension: self.output_glwe_size().to_glwe_dimension(),
            polynomial_size: self.output_polynomial_size(),
            variance_per_occupied_slot: Variance(-2.0f64.powi(128)),
            modulus: self.modulus,
        }
    }
}

impl LwePackingKeyswitch<[&NoiseSimulationLwe], NoiseSimulationGlwe>
    for NoiseSimulationLwePackingKeyswitchKey
{
    type SideResources = ();

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &[&NoiseSimulationLwe],
        output: &mut NoiseSimulationGlwe,
        _side_resources: &mut Self::SideResources,
    ) {
        let mut input_iter = input.iter();
        let input = input_iter.next().unwrap();

        let mut lwe_to_pack = 1;

        assert!(input_iter.inspect(|_| lwe_to_pack += 1).all(|x| x == input));

        assert_eq!(input.lwe_dimension(), self.input_lwe_dimension());

        let packing_ks_additive_var = match self.noise_distribution() {
            DynamicDistribution::Gaussian(_) => {
                packing_keyswitch_additive_variance_132_bits_security_gaussian(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    lwe_to_pack.into(),
                    self.modulus().as_f64(),
                )
            }
            DynamicDistribution::TUniform(_) => {
                packing_keyswitch_additive_variance_132_bits_security_tuniform(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    lwe_to_pack.into(),
                    self.modulus().as_f64(),
                )
            }
        };

        output.glwe_dimension = self.output_glwe_size().to_glwe_dimension();
        output.polynomial_size = self.output_polynomial_size();
        output.variance_per_occupied_slot =
            Variance(input.variance().0 + packing_ks_additive_var.0);
        output.modulus = self.modulus();
    }
}
