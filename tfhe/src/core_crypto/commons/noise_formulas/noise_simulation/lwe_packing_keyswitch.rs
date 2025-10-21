use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::noise_formulas::lwe_packing_keyswitch::{
    packing_keyswitch_additive_variance_132_bits_security_gaussian,
    packing_keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLwePackingKeyswitchResult, LwePackingKeyswitch,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::{
    NoiseSimulationGlwe, NoiseSimulationLwe, NoiseSimulationModulus,
    NoiseSimulationNoiseDistribution, NoiseSimulationNoiseDistributionKind,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::container::Container;
use crate::core_crypto::entities::lwe_packing_keyswitch_key::LwePackingKeyswitchKey;

#[derive(Clone, Copy)]
pub struct NoiseSimulationLwePackingKeyswitchKey {
    input_lwe_dimension: LweDimension,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    noise_distribution: NoiseSimulationNoiseDistribution,
    modulus: NoiseSimulationModulus,
}

impl NoiseSimulationLwePackingKeyswitchKey {
    pub fn new(
        input_lwe_dimension: LweDimension,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
        noise_distribution: NoiseSimulationNoiseDistribution,
        modulus: NoiseSimulationModulus,
    ) -> Self {
        Self {
            input_lwe_dimension,
            decomp_base_log,
            decomp_level_count,
            output_glwe_dimension,
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
            output_glwe_dimension,
            output_polynomial_size,
            noise_distribution: _,
            modulus,
        } = *self;

        let pksk_input_lwe_dimension = pksk.input_key_lwe_dimension();
        let pksk_decomp_base_log = pksk.decomposition_base_log();
        let pksk_decomp_level_count = pksk.decomposition_level_count();
        let pksk_output_glwe_dimension = pksk.output_key_glwe_dimension();
        let pksk_output_polynomial_size = pksk.output_key_polynomial_size();
        let pksk_modulus =
            NoiseSimulationModulus::from_ciphertext_modulus(pksk.ciphertext_modulus());

        input_lwe_dimension == pksk_input_lwe_dimension
            && decomp_base_log == pksk_decomp_base_log
            && decomp_level_count == pksk_decomp_level_count
            && output_glwe_dimension == pksk_output_glwe_dimension
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

    pub fn output_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_dimension
    }

    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    pub fn noise_distribution(&self) -> NoiseSimulationNoiseDistribution {
        self.noise_distribution
    }

    pub fn modulus(&self) -> NoiseSimulationModulus {
        self.modulus
    }
}

impl AllocateLwePackingKeyswitchResult for NoiseSimulationLwePackingKeyswitchKey {
    type Output = NoiseSimulationGlwe;
    type SideResources = ();

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        Self::Output::new(
            self.output_glwe_dimension(),
            self.output_polynomial_size(),
            Variance(f64::NAN),
            self.modulus,
        )
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
        let first_input = input_iter.next().unwrap();

        // Check first input is compatible with us
        assert_eq!(first_input.lwe_dimension(), self.input_lwe_dimension());
        // Check all inputs are the same as first input
        assert!(input_iter.all(|x| x == first_input));

        let lwe_to_pack = input.len() as f64;

        let packing_ks_additive_var = match self.noise_distribution().kind() {
            NoiseSimulationNoiseDistributionKind::Gaussian => {
                packing_keyswitch_additive_variance_132_bits_security_gaussian(
                    self.input_lwe_dimension(),
                    self.output_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    lwe_to_pack,
                    self.modulus().as_f64(),
                )
            }
            NoiseSimulationNoiseDistributionKind::TUniform => {
                packing_keyswitch_additive_variance_132_bits_security_tuniform(
                    self.input_lwe_dimension(),
                    self.output_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    lwe_to_pack,
                    self.modulus().as_f64(),
                )
            }
        };

        *output = NoiseSimulationGlwe::new(
            self.output_glwe_dimension(),
            self.output_polynomial_size(),
            Variance(first_input.variance().0 + packing_ks_additive_var.0),
            self.modulus(),
        );
    }
}
