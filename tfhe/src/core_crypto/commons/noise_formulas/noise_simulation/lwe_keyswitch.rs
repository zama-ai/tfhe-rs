use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::noise_formulas::lwe_keyswitch::{
    keyswitch_additive_variance_132_bits_security_gaussian,
    keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLweKeyswitchResult, LweKeyswitch,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::{
    NoiseSimulationLwe, NoiseSimulationModulus,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, LweDimension,
};
use crate::core_crypto::commons::traits::container::Container;
use crate::core_crypto::entities::lwe_keyswitch_key::LweKeyswitchKey;

#[derive(Clone, Copy)]
pub struct NoiseSimulationLweKeyswitchKey {
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    noise_distribution: DynamicDistribution<u64>,
    output_modulus: NoiseSimulationModulus,
}

impl NoiseSimulationLweKeyswitchKey {
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

impl AllocateLweKeyswitchResult for NoiseSimulationLweKeyswitchKey {
    type Output = NoiseSimulationLwe;
    type SideResources = ();

    fn allocate_lwe_keyswitch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        Self::Output::new(
            self.output_lwe_dimension,
            Variance(f64::NAN),
            self.output_modulus,
        )
    }
}

impl LweKeyswitch<NoiseSimulationLwe, NoiseSimulationLwe> for NoiseSimulationLweKeyswitchKey {
    type SideResources = ();

    fn lwe_keyswitch(
        &self,
        input: &NoiseSimulationLwe,
        output: &mut NoiseSimulationLwe,
        _side_resources: &mut Self::SideResources,
    ) {
        assert_eq!(input.lwe_dimension(), self.input_lwe_dimension);

        let ks_additive_var = match self.noise_distribution {
            DynamicDistribution::Gaussian(_) => {
                keyswitch_additive_variance_132_bits_security_gaussian(
                    self.input_lwe_dimension,
                    self.output_lwe_dimension,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                    input.modulus().as_f64(),
                    self.output_modulus.as_f64(),
                )
            }
            DynamicDistribution::TUniform(_) => {
                keyswitch_additive_variance_132_bits_security_tuniform(
                    self.input_lwe_dimension,
                    self.output_lwe_dimension,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                    input.modulus().as_f64(),
                    self.output_modulus.as_f64(),
                )
            }
        };

        *output = NoiseSimulationLwe::new(
            self.output_lwe_dimension,
            Variance(input.variance().0 + ks_additive_var.0),
            self.output_modulus,
        );
    }
}
