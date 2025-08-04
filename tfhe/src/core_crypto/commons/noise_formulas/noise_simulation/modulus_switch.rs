use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::noise_formulas::modulus_switch::modulus_switch_additive_variance;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateStandardModSwitchResult, StandardModSwitch,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::{
    NoiseSimulationLwe, NoiseSimulationModulus,
};
use crate::core_crypto::commons::parameters::CiphertextModulusLog;

impl AllocateStandardModSwitchResult for NoiseSimulationLwe {
    type Output = Self;
    type SideResources = ();

    fn allocate_standard_mod_switch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        Self {
            lwe_dimension: self.lwe_dimension,
            variance: Variance(f64::INFINITY),
            modulus: self.modulus(),
        }
    }
}

impl StandardModSwitch<Self> for NoiseSimulationLwe {
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

        *output = Self::new(
            self.lwe_dimension,
            Variance(self.variance.0 + mod_switch_additive_variance.0),
            // Mod switched but the noise is to be interpreted with respect to the input modulus,
            // as strictly the operation adding the noise is the rounding under the
            // original modulus
            self.modulus,
        );
    }
}
