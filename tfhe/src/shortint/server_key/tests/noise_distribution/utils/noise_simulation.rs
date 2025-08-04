pub use crate::core_crypto::commons::noise_formulas::noise_simulation::*;

use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::noise_formulas::generalized_modulus_switch::generalized_modulus_switch_additive_variance;
use crate::core_crypto::commons::noise_formulas::traits::{
    AllocateDriftTechniqueStandardModSwitchResult, AllocateStandardModSwitchResult,
    DriftTechniqueStandardModSwitch,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, DynamicDistribution, LweDimension,
};
use crate::shortint::client_key::ClientKey;
use crate::shortint::parameters::{
    AtomicPatternParameters, NoiseSquashingCompressionParameters, NoiseSquashingParameters,
};
use crate::shortint::server_key::ModulusSwitchNoiseReductionKey;

impl NoiseSimulationLwe {
    pub fn encrypt(key: &ClientKey, _msg: u64) -> Self {
        let (encryption_key, encryption_noise_distribution) = key.encryption_key_and_noise();
        let enc_var = match encryption_noise_distribution {
            DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
            DynamicDistribution::TUniform(tuniform) => {
                tuniform.variance(key.parameters().ciphertext_modulus().raw_modulus_float())
            }
        };

        Self::new(
            encryption_key.lwe_dimension(),
            enc_var,
            NoiseSimulationModulus::from_ciphertext_modulus(key.parameters().ciphertext_modulus()),
        )
    }
}

impl NoiseSimulationLweKsk {
    // We can't really build a key from an already generated key as we need to know what the noise
    // distribution is.
    pub fn new_from_atomic_pattern_parameters(params: AtomicPatternParameters) -> Self {
        // KeySwitch from big key to small key
        Self::new(
            params
                .glwe_dimension()
                .to_equivalent_lwe_dimension(params.polynomial_size()),
            params.lwe_dimension(),
            params.ks_base_log(),
            params.ks_level(),
            params.lwe_noise_distribution(),
            match params {
                AtomicPatternParameters::Standard(pbsparameters) => {
                    NoiseSimulationModulus::from_ciphertext_modulus(
                        pbsparameters.ciphertext_modulus(),
                    )
                }
                AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                    NoiseSimulationModulus::from_ciphertext_modulus(
                        key_switch32_pbsparameters.post_keyswitch_ciphertext_modulus(),
                    )
                }
            },
        )
    }
}

#[derive(Clone, Copy)]
pub struct NoiseSimulationDriftTechniqueKey {
    lwe_dimension: LweDimension,
    noise_distribution: DynamicDistribution<u64>,
    modulus: NoiseSimulationModulus,
}

impl NoiseSimulationDriftTechniqueKey {
    pub fn new_from_atomic_pattern_parameters(params: AtomicPatternParameters) -> Self {
        Self {
            lwe_dimension: params.lwe_dimension(),
            noise_distribution: params.lwe_noise_distribution(),
            modulus: match params {
                AtomicPatternParameters::Standard(pbsparameters) => {
                    NoiseSimulationModulus::from_ciphertext_modulus(
                        pbsparameters.ciphertext_modulus(),
                    )
                }
                AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                    NoiseSimulationModulus::from_ciphertext_modulus(
                        key_switch32_pbsparameters.post_keyswitch_ciphertext_modulus(),
                    )
                }
            },
        }
    }

    pub fn matches_actual_drift_key<Scalar: UnsignedInteger>(
        &self,
        drift_key: &ModulusSwitchNoiseReductionKey<Scalar>,
    ) -> bool {
        let Self {
            lwe_dimension,
            noise_distribution: _,
            modulus,
        } = *self;

        let drift_key_lwe_dimension = drift_key.modulus_switch_zeros.lwe_size().to_lwe_dimension();
        let drift_key_modulus = NoiseSimulationModulus::from_ciphertext_modulus(
            drift_key.modulus_switch_zeros.ciphertext_modulus(),
        );

        lwe_dimension == drift_key_lwe_dimension && modulus == drift_key_modulus
    }
}

impl AllocateDriftTechniqueStandardModSwitchResult for NoiseSimulationDriftTechniqueKey {
    type AfterDriftOutput = NoiseSimulationLwe;
    type AfterMsOutput = NoiseSimulationLwe;
    type SideResources = ();

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        let after_drift =
            NoiseSimulationLwe::new(self.lwe_dimension, Variance(f64::INFINITY), self.modulus);
        let after_ms = after_drift.allocate_standard_mod_switch_result(side_resources);
        (after_drift, after_ms)
    }
}

impl DriftTechniqueStandardModSwitch<NoiseSimulationLwe, NoiseSimulationLwe, NoiseSimulationLwe>
    for NoiseSimulationDriftTechniqueKey
{
    type SideResources = ();

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &NoiseSimulationLwe,
        after_drift_technique: &mut NoiseSimulationLwe,
        after_mod_switch: &mut NoiseSimulationLwe,
        _side_resources: &mut Self::SideResources,
    ) {
        assert_eq!(self.modulus, input.modulus());

        let simulation_after_mod_switch_modulus =
            NoiseSimulationModulus::from_ciphertext_modulus_log(output_modulus_log);

        let drift_technique_added_var = match self.noise_distribution {
            DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
            DynamicDistribution::TUniform(tuniform) => tuniform.variance(self.modulus.as_f64()),
        };

        *after_drift_technique = NoiseSimulationLwe::new(
            input.lwe_dimension(),
            Variance(input.variance().0 + drift_technique_added_var.0),
            input.modulus(),
        );

        let before_ms_modulus_f64 = after_drift_technique.modulus().as_f64();
        let after_ms_modulus_f64 = simulation_after_mod_switch_modulus.as_f64();

        assert!(after_ms_modulus_f64 < before_ms_modulus_f64);

        *after_mod_switch = NoiseSimulationLwe::new(
            after_drift_technique.lwe_dimension(),
            Variance(
                after_drift_technique.variance().0
                    + generalized_modulus_switch_additive_variance(
                        after_drift_technique.lwe_dimension(),
                        before_ms_modulus_f64,
                        after_ms_modulus_f64,
                    )
                    .0,
            ),
            after_drift_technique.modulus(),
        );
    }
}

impl NoiseSimulationLweFourier128Bsk {
    // We can't really build a key from an already generated key as we need to know what the noise
    // distribution is.
    pub fn new_from_parameters(
        params: AtomicPatternParameters,
        noise_squashing_params: NoiseSquashingParameters,
    ) -> Self {
        Self::new(
            params.lwe_dimension(),
            noise_squashing_params.glwe_dimension().to_glwe_size(),
            noise_squashing_params.polynomial_size(),
            noise_squashing_params.decomp_base_log(),
            noise_squashing_params.decomp_level_count(),
            noise_squashing_params.glwe_noise_distribution(),
            NoiseSimulationModulus::from_ciphertext_modulus(
                noise_squashing_params.ciphertext_modulus(),
            ),
        )
    }
}

impl NoiseSimulationLweFourierBsk {
    // We can't really build a key from an already generated key as we need to know what the noise
    // distribution is.
    pub fn new_from_atomic_pattern_parameters(params: AtomicPatternParameters) -> Self {
        Self::new(
            params.lwe_dimension(),
            params.glwe_dimension().to_glwe_size(),
            params.polynomial_size(),
            params.pbs_base_log(),
            params.pbs_level(),
            params.glwe_noise_distribution(),
            NoiseSimulationModulus::from_ciphertext_modulus(params.ciphertext_modulus()),
        )
    }
}

impl NoiseSimulationLwePackingKeyswitchKey {
    pub fn new_from_params(
        noise_squashing_params: NoiseSquashingParameters,
        noise_squashing_compression_params: NoiseSquashingCompressionParameters,
    ) -> Self {
        let squashing_lwe_dim = noise_squashing_params
            .glwe_dimension()
            .to_equivalent_lwe_dimension(noise_squashing_params.polynomial_size());

        Self::new(
            squashing_lwe_dim,
            noise_squashing_compression_params.packing_ks_base_log,
            noise_squashing_compression_params.packing_ks_level,
            noise_squashing_compression_params
                .packing_ks_glwe_dimension
                .to_glwe_size(),
            noise_squashing_compression_params.packing_ks_polynomial_size,
            noise_squashing_compression_params.packing_ks_key_noise_distribution,
            NoiseSimulationModulus::from_ciphertext_modulus(
                noise_squashing_compression_params.ciphertext_modulus,
            ),
        )
    }
}
