use super::NoiseSquashingPrivateKey;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use crate::core_crypto::algorithms::lwe_keyswitch::keyswitch_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::{
    generate_programmable_bootstrap_glwe_lut,
    programmable_bootstrap_f128_lwe_ciphertext_mem_optimized,
    programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement,
};
use crate::core_crypto::entities::{Fourier128LweBootstrapKeyOwned, LweCiphertext};
use crate::core_crypto::fft_impl::fft128::math::fft::Fft128;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::shortint::backward_compatibility::noise_squashing::NoiseSquashingKeyVersions;
use crate::shortint::ciphertext::{Ciphertext, SquashedNoiseCiphertext};
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{compute_delta, PaddingBit};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, MessageModulus, ModulusSwitchNoiseReductionParams,
    PBSOrder, PBSParameters,
};
use crate::shortint::server_key::{
    ModulusSwitchNoiseReductionKey, ModulusSwitchNoiseReductionKeyConformanceParams, ServerKey,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingKeyVersions)]
pub struct NoiseSquashingKey {
    pub(super) bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    pub(super) modulus_switch_noise_reduction_key: Option<ModulusSwitchNoiseReductionKey>,
    pub(super) message_modulus: MessageModulus,
    pub(super) carry_modulus: CarryModulus,
    pub(super) output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl ClientKey {
    pub fn new_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> NoiseSquashingKey {
        let pbs_parameters = self
            .parameters
            .pbs_parameters()
            .expect("NoiseSquashingKey generation requires PBSParameters");

        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        let (bootstrapping_key, modulus_switch_noise_reduction_key) =
            ShortintEngine::with_thread_local_mut(|engine| {
                let std_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
                    &self.lwe_secret_key,
                    noise_squashing_private_key.post_noise_squashing_secret_key(),
                    noise_squashing_parameters.decomp_base_log,
                    noise_squashing_parameters.decomp_level_count,
                    noise_squashing_parameters.glwe_noise_distribution,
                    noise_squashing_parameters.ciphertext_modulus,
                    &mut engine.encryption_generator,
                );

                let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
                    std_bsk.input_lwe_dimension(),
                    std_bsk.glwe_size(),
                    std_bsk.polynomial_size(),
                    std_bsk.decomposition_base_log(),
                    std_bsk.decomposition_level_count(),
                );

                par_convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bsk, &mut fbsk);

                let modulus_switch_noise_reduction_key = noise_squashing_parameters
                    .modulus_switch_noise_reduction_params
                    .map(|p| {
                        ModulusSwitchNoiseReductionKey::new(
                            p,
                            &self.lwe_secret_key,
                            engine,
                            pbs_parameters.ciphertext_modulus(),
                            pbs_parameters.lwe_noise_distribution(),
                        )
                    });

                (fbsk, modulus_switch_noise_reduction_key)
            });

        NoiseSquashingKey {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            output_ciphertext_modulus: noise_squashing_parameters.ciphertext_modulus,
            message_modulus: noise_squashing_parameters.message_modulus,
            carry_modulus: noise_squashing_parameters.carry_modulus,
        }
    }
}

impl NoiseSquashingKey {
    pub fn new(
        client_key: &ClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        client_key.new_noise_squashing_key(noise_squashing_private_key)
    }

    pub fn squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: &ServerKey,
    ) -> SquashedNoiseCiphertext {
        let ct_noise_level = ciphertext.noise_level();
        assert!(
            src_server_key
                .max_noise_level
                .validate(ct_noise_level)
                .is_ok(),
            "squash_ciphertext_noise requires the input Ciphertext to have at most {:?} noise \
                got {:?}.",
            src_server_key.max_noise_level,
            ct_noise_level
        );
        assert_eq!(
            ciphertext.message_modulus, self.message_modulus,
            "Mismatched MessageModulus between Ciphertext {:?} and NoiseSquashingKey {:?}.",
            ciphertext.message_modulus, self.message_modulus,
        );
        assert_eq!(
            ciphertext.carry_modulus, self.carry_modulus,
            "Mismatched CarryModulus between Ciphertext {:?} and NoiseSquashingKey {:?}.",
            ciphertext.carry_modulus, self.carry_modulus,
        );

        self.unchecked_squash_ciphertext_noise(ciphertext, src_server_key)
    }

    pub fn unchecked_squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: &ServerKey,
    ) -> SquashedNoiseCiphertext {
        let mut lwe_before_noise_squashing = match src_server_key.pbs_order {
            // Under the big key, first need to keyswitch
            PBSOrder::KeyswitchBootstrap => {
                let mut after_ks_ct = LweCiphertext::new(
                    0u64,
                    src_server_key.key_switching_key.output_lwe_size(),
                    src_server_key.key_switching_key.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(
                    &src_server_key.key_switching_key,
                    &ciphertext.ct,
                    &mut after_ks_ct,
                );
                after_ks_ct
            }
            // Under the small key, no need to keyswitch
            PBSOrder::BootstrapKeyswitch => ciphertext.ct.clone(),
        };

        let lwe_ciphertext_to_squash_noise = match &self.modulus_switch_noise_reduction_key {
            Some(key) => {
                let br_input_modulus_log = self
                    .bootstrapping_key
                    .polynomial_size()
                    .to_blind_rotation_input_modulus_log();
                key.improve_modulus_switch_noise(
                    &mut lwe_before_noise_squashing,
                    br_input_modulus_log,
                );

                lwe_before_noise_squashing
            }
            None => lwe_before_noise_squashing,
        };

        let output_lwe_size = self.bootstrapping_key.output_lwe_dimension().to_lwe_size();
        let output_message_modulus = self.message_modulus;
        let output_carry_modulus = self.carry_modulus;
        let output_ciphertext_modulus = self.output_ciphertext_modulus;

        let mut res = SquashedNoiseCiphertext::new_zero(
            output_lwe_size,
            output_ciphertext_modulus,
            output_message_modulus,
            output_carry_modulus,
        );

        let bsk_glwe_size = self.bootstrapping_key.glwe_size();
        let bsk_polynomial_size = self.bootstrapping_key.polynomial_size();

        let fft = Fft128::new(bsk_polynomial_size);
        let fft = fft.as_view();

        let mem_requirement =
            programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement::<u128>(
                bsk_glwe_size,
                bsk_polynomial_size,
                fft,
            )
            .unwrap()
            .try_unaligned_bytes_required()
            .unwrap();

        // CarryModulus set to 1, as the output ciphertext does not have a carry space, mod == 1,
        // means carry max == 0
        let delta = compute_delta(
            output_ciphertext_modulus,
            output_message_modulus,
            output_carry_modulus,
            PaddingBit::Yes,
        );

        let output_cleartext_space = output_message_modulus.0 * output_carry_modulus.0;

        let id_lut = generate_programmable_bootstrap_glwe_lut(
            bsk_polynomial_size,
            bsk_glwe_size,
            output_cleartext_space.try_into().unwrap(),
            output_ciphertext_modulus,
            delta,
            |x| x,
        );

        ShortintEngine::with_thread_local_mut(|engine| {
            let buffers = &mut engine.computation_buffers;
            buffers.resize(mem_requirement);

            programmable_bootstrap_f128_lwe_ciphertext_mem_optimized(
                &lwe_ciphertext_to_squash_noise,
                res.lwe_ciphertext_mut(),
                &id_lut,
                &self.bootstrapping_key,
                fft,
                buffers.stack(),
            );
        });

        res.set_degree(ciphertext.degree);

        res
    }
}

#[derive(Clone, Copy)]
pub struct NoiseSquashingKeyConformanceParams {
    pub bootstrapping_key_params: LweBootstrapKeyConformanceParams<u128>,
    pub modulus_switch_noise_reduction_params: Option<ModulusSwitchNoiseReductionParams>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

impl TryFrom<(PBSParameters, NoiseSquashingParameters)> for NoiseSquashingKeyConformanceParams {
    type Error = crate::Error;

    fn try_from(
        (pbs_params, noise_squashing_params): (PBSParameters, NoiseSquashingParameters),
    ) -> Result<Self, Self::Error> {
        if pbs_params.message_modulus() != noise_squashing_params.message_modulus
            || pbs_params.carry_modulus() != noise_squashing_params.carry_modulus
        {
            return Err(crate::Error::new(format!(
                "Incompatible MessageModulus (PBS {:?}, NoiseSquashing {:?}) \
                or CarryModulus (PBS {:?}, NoiseSquashing {:?}) \
                when creating NoiseSquashingKeyConformanceParams",
                pbs_params.message_modulus(),
                noise_squashing_params.message_modulus,
                pbs_params.carry_modulus(),
                noise_squashing_params.carry_modulus
            )));
        }

        Ok(Self {
            bootstrapping_key_params: LweBootstrapKeyConformanceParams {
                input_lwe_dimension: pbs_params.lwe_dimension(),
                output_glwe_size: noise_squashing_params.glwe_dimension.to_glwe_size(),
                polynomial_size: noise_squashing_params.polynomial_size,
                decomp_base_log: noise_squashing_params.decomp_base_log,
                decomp_level_count: noise_squashing_params.decomp_level_count,
                ciphertext_modulus: noise_squashing_params.ciphertext_modulus,
            },
            modulus_switch_noise_reduction_params: noise_squashing_params
                .modulus_switch_noise_reduction_params,
            message_modulus: noise_squashing_params.message_modulus,
            carry_modulus: noise_squashing_params.carry_modulus,
        })
    }
}

impl ParameterSetConformant for NoiseSquashingKey {
    type ParameterSet = NoiseSquashingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        let Self::ParameterSet {
            bootstrapping_key_params: expected_bootstrapping_key_params,
            modulus_switch_noise_reduction_params: expected_modulus_switch_noise_reduction_params,
            message_modulus: expected_message_modulus,
            carry_modulus: expected_carry_modulus,
        } = parameter_set;

        let modulus_switch_key_ok = match (
            modulus_switch_noise_reduction_key,
            expected_modulus_switch_noise_reduction_params,
        ) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(_), None) => false,
            (Some(key), Some(params)) => {
                let mod_switch_conformance_params =
                    ModulusSwitchNoiseReductionKeyConformanceParams {
                        modulus_switch_noise_reduction_params: *params,
                        lwe_dimension: bootstrapping_key.input_lwe_dimension(),
                    };

                key.is_conformant(&mod_switch_conformance_params)
            }
        };

        modulus_switch_key_ok
            && bootstrapping_key.is_conformant(expected_bootstrapping_key_params)
            && *output_ciphertext_modulus == expected_bootstrapping_key_params.ciphertext_modulus
            && *message_modulus == *expected_message_modulus
            && *carry_modulus == *expected_carry_modulus
    }
}
