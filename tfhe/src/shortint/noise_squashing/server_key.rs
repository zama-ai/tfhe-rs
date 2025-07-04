use super::NoiseSquashingPrivateKey;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use crate::core_crypto::algorithms::lwe_keyswitch::keyswitch_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::{
    blind_rotate_f128_lwe_ciphertext_mem_optimized,
    blind_rotate_f128_lwe_ciphertext_mem_optimized_requirement,
    generate_programmable_bootstrap_glwe_lut,
};
use crate::core_crypto::entities::{Fourier128LweBootstrapKeyOwned, LweCiphertext};
use crate::core_crypto::fft_impl::fft128::math::fft::Fft128;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::shortint::atomic_pattern::{AtomicPattern, AtomicPatternParameters};
use crate::shortint::backward_compatibility::noise_squashing::NoiseSquashingKeyVersions;
use crate::shortint::ciphertext::{Ciphertext, SquashedNoiseCiphertext};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{compute_delta, PaddingBit};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, MessageModulus, ModulusSwitchType, PBSOrder, PBSParameters,
};
use crate::shortint::server_key::{
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKeyConformanceParams, ServerKey,
    StandardServerKeyView,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingKeyVersions)]
pub struct NoiseSquashingKey {
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl ClientKey {
    pub fn new_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> NoiseSquashingKey {
        let AtomicPatternClientKey::Standard(std_cks) = &self.atomic_pattern else {
            panic!("Only the standard atomic pattern supports noise squashing")
        };

        let pbs_parameters = std_cks.parameters;

        assert_eq!(
            pbs_parameters.message_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .message_modulus,
            "Incompatible MessageModulus ClientKey {:?}, NoiseSquashingPrivateKey {:?}.",
            pbs_parameters.message_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .message_modulus,
        );
        assert_eq!(
            pbs_parameters.carry_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .carry_modulus,
            "Incompatible CarryModulus ClientKey {:?}, NoiseSquashingPrivateKey {:?}",
            pbs_parameters.carry_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .carry_modulus,
        );

        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        let (bootstrapping_key, modulus_switch_noise_reduction_key) =
            ShortintEngine::with_thread_local_mut(|engine| {
                let std_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
                    &std_cks.lwe_secret_key,
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
                    .to_modulus_switch_configuration(
                        &std_cks.lwe_secret_key,
                        pbs_parameters.ciphertext_modulus(),
                        pbs_parameters.lwe_noise_distribution(),
                        engine,
                    );

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

    pub fn from_raw_parts(
        bootstrapping_key: Fourier128LweBootstrapKeyOwned,
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<u64>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> Self {
        Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        Fourier128LweBootstrapKeyOwned,
        ModulusSwitchConfiguration<u64>,
        MessageModulus,
        CarryModulus,
        CoreCiphertextModulus<u128>,
    ) {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        (
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        )
    }

    pub fn squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: &ServerKey,
    ) -> SquashedNoiseCiphertext {
        self.checked_squash_ciphertext_noise(ciphertext, src_server_key)
            .unwrap()
    }

    pub fn checked_squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: &ServerKey,
    ) -> crate::Result<SquashedNoiseCiphertext> {
        let ct_noise_level = ciphertext.noise_level();
        if src_server_key
            .max_noise_level
            .validate(ct_noise_level)
            .is_err()
        {
            return Err(crate::error!(
                "squash_ciphertext_noise requires the input Ciphertext to have at most {:?} noise \
                got {:?}.",
                src_server_key.max_noise_level,
                ct_noise_level
            ));
        }

        if ciphertext.message_modulus != self.message_modulus {
            return Err(crate::error!(
                "Mismatched MessageModulus between Ciphertext {:?} and NoiseSquashingKey {:?}.",
                ciphertext.message_modulus,
                self.message_modulus,
            ));
        }

        if ciphertext.carry_modulus != self.carry_modulus {
            return Err(crate::error!(
                "Mismatched CarryModulus between Ciphertext {:?} and NoiseSquashingKey {:?}.",
                ciphertext.carry_modulus,
                self.carry_modulus,
            ));
        }

        // For the moment, noise squashing is only implemented for the Standard AP
        let src_server_key: StandardServerKeyView =
            src_server_key.as_view().try_into().map_err(|_| {
                crate::error!(
                    "Noise squashing is not supported by the selected atomic pattern ({:?})",
                    src_server_key.atomic_pattern.kind()
                )
            })?;

        Ok(self.unchecked_squash_ciphertext_noise(ciphertext, src_server_key))
    }

    pub fn unchecked_squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: StandardServerKeyView,
    ) -> SquashedNoiseCiphertext {
        let lwe_before_noise_squashing = match src_server_key.atomic_pattern.pbs_order {
            // Under the big key, first need to keyswitch
            PBSOrder::KeyswitchBootstrap => {
                let mut after_ks_ct = LweCiphertext::new(
                    0u64,
                    src_server_key
                        .atomic_pattern
                        .key_switching_key
                        .output_lwe_size(),
                    src_server_key
                        .atomic_pattern
                        .key_switching_key
                        .ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(
                    &src_server_key.atomic_pattern.key_switching_key,
                    &ciphertext.ct,
                    &mut after_ks_ct,
                );
                after_ks_ct
            }
            // Under the small key, no need to keyswitch
            PBSOrder::BootstrapKeyswitch => ciphertext.ct.clone(),
        };

        let br_input_modulus_log = self
            .bootstrapping_key
            .polynomial_size()
            .to_blind_rotation_input_modulus_log();

        let lwe_ciphertext_to_squash_noise = self
            .modulus_switch_noise_reduction_key
            .lwe_ciphertext_modulus_switch(&lwe_before_noise_squashing, br_input_modulus_log);

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

        let mem_requirement = blind_rotate_f128_lwe_ciphertext_mem_optimized_requirement::<u128>(
            bsk_glwe_size,
            bsk_polynomial_size,
            fft,
        )
        .unwrap()
        .try_unaligned_bytes_required()
        .unwrap();

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
            let buffers = engine.get_computation_buffers();
            buffers.resize(mem_requirement);

            blind_rotate_f128_lwe_ciphertext_mem_optimized(
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

    pub fn bootstrapping_key(&self) -> &Fourier128LweBootstrapKeyOwned {
        &self.bootstrapping_key
    }

    pub fn modulus_switch_noise_reduction_key(
        &self,
    ) -> &ModulusSwitchConfiguration<u64> {
        &self.modulus_switch_noise_reduction_key
    }

    pub fn message_modulus(&self) -> MessageModulus {
        self.message_modulus
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        self.carry_modulus
    }

    pub fn output_ciphertext_modulus(&self) -> CoreCiphertextModulus<u128> {
        self.output_ciphertext_modulus
    }
}

#[derive(Clone, Copy)]
pub struct NoiseSquashingKeyConformanceParams {
    pub bootstrapping_key_params: LweBootstrapKeyConformanceParams<u128>,
    pub modulus_switch_noise_reduction_params: ModulusSwitchType,
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

impl TryFrom<(AtomicPatternParameters, NoiseSquashingParameters)>
    for NoiseSquashingKeyConformanceParams
{
    type Error = crate::Error;

    fn try_from(
        (ap_params, noise_squashing_params): (AtomicPatternParameters, NoiseSquashingParameters),
    ) -> Result<Self, Self::Error> {
        match ap_params {
            AtomicPatternParameters::Standard(pbs_params) => {
                (pbs_params, noise_squashing_params).try_into()
            }
            AtomicPatternParameters::KeySwitch32(_) => Err(crate::Error::from(
                "Noise squashing is not supported by the KS32 Atomic Pattern",
            )),
        }
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
            (ModulusSwitchConfiguration::Standard, ModulusSwitchType::Standard) => true,
            (
                ModulusSwitchConfiguration::CenteredMeanNoiseReduction,
                ModulusSwitchType::CenteredMeanNoiseReduction,
            ) => true,
            (
                ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(key),
                ModulusSwitchType::DriftTechniqueNoiseReduction(params),
            ) => {
                let mod_switch_conformance_params =
                    ModulusSwitchNoiseReductionKeyConformanceParams {
                        modulus_switch_noise_reduction_params: *params,
                        lwe_dimension: bootstrapping_key.input_lwe_dimension(),
                    };

                key.is_conformant(&mod_switch_conformance_params)
            }
            (_, _) => false,
        };

        modulus_switch_key_ok
            && bootstrapping_key.is_conformant(expected_bootstrapping_key_params)
            && *output_ciphertext_modulus == expected_bootstrapping_key_params.ciphertext_modulus
            && *message_modulus == *expected_message_modulus
            && *carry_modulus == *expected_carry_modulus
    }
}
