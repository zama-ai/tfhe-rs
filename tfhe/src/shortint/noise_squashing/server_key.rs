use super::atomic_pattern::standard::StandardAtomicPatternNoiseSquashingKey;
use super::atomic_pattern::{AtomicPatternNoiseSquashingKey, NoiseSquashingAtomicPattern};
use super::NoiseSquashingPrivateKey;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use crate::core_crypto::commons::math::random::Uniform;
use crate::core_crypto::entities::Fourier128LweBootstrapKeyOwned;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::fft128_lwe_multi_bit_bootstrap_key::Fourier128LweMultiBitBootstrapKeyOwned;
use crate::core_crypto::prelude::{
    par_allocate_and_generate_new_lwe_multi_bit_bootstrap_key,
    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128, CastFrom, Container,
    DynamicDistribution, Encryptable, GlweSize, LweSecretKey,
    MultiBitBootstrapKeyConformanceParams, ThreadCount, UnsignedInteger,
};
use crate::shortint::atomic_pattern::AtomicPatternParameters;
use crate::shortint::backward_compatibility::noise_squashing::{
    GenericNoiseSquashingKeyVersions, Shortint128BootstrappingKeyVersions,
};
use crate::shortint::ciphertext::{Ciphertext, SquashedNoiseCiphertext};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, KeySwitch32PBSParameters, MessageModulus,
    ModulusSwitchType, PBSParameters,
};
use crate::shortint::prelude::{LweDimension, PolynomialSize};
use crate::shortint::server_key::{
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKeyConformanceParams, ServerKey,
    UnsupportedOperation,
};
use crate::shortint::AtomicPatternKind;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// A 128b bootstrapping key that can be used for the noise squashing operation
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(Shortint128BootstrappingKeyVersions)]
pub enum Shortint128BootstrappingKey<Scalar>
where
    Scalar: UnsignedInteger,
{
    Classic {
        bsk: Fourier128LweBootstrapKeyOwned,
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<Scalar>,
    },
    MultiBit {
        bsk: Fourier128LweMultiBitBootstrapKeyOwned,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

impl<Scalar> Shortint128BootstrappingKey<Scalar>
where
    Scalar: UnsignedInteger,
{
    pub(crate) fn new<InputKeyCont>(
        input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
        ciphertext_modulus: CoreCiphertextModulus<Scalar>,
        lwe_noise_distribution: DynamicDistribution<Scalar>,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self
    where
        InputKeyCont: Container<Element = Scalar> + Sync,
        Scalar: Encryptable<Uniform, DynamicDistribution<Scalar>> + CastFrom<usize>,
    {
        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        match noise_squashing_parameters {
            NoiseSquashingParameters::Classic(params) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    let std_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
                        input_lwe_secret_key,
                        noise_squashing_private_key.post_noise_squashing_secret_key(),
                        params.decomp_base_log,
                        params.decomp_level_count,
                        params.glwe_noise_distribution,
                        params.ciphertext_modulus,
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

                    let modulus_switch_noise_reduction_key = params
                        .modulus_switch_noise_reduction_params
                        .to_modulus_switch_configuration(
                            input_lwe_secret_key,
                            ciphertext_modulus,
                            lwe_noise_distribution,
                            engine,
                        );

                    Self::Classic {
                        bsk: fbsk,
                        modulus_switch_noise_reduction_key,
                    }
                })
            }
            NoiseSquashingParameters::MultiBit(params) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    let std_bsk = par_allocate_and_generate_new_lwe_multi_bit_bootstrap_key(
                        input_lwe_secret_key,
                        noise_squashing_private_key.post_noise_squashing_secret_key(),
                        params.decomp_base_log,
                        params.decomp_level_count,
                        params.grouping_factor,
                        params.glwe_noise_distribution,
                        params.ciphertext_modulus,
                        &mut engine.encryption_generator,
                    );

                    let mut fbsk = Fourier128LweMultiBitBootstrapKeyOwned::new(
                        std_bsk.input_lwe_dimension(),
                        std_bsk.glwe_size(),
                        std_bsk.polynomial_size(),
                        std_bsk.decomposition_base_log(),
                        std_bsk.decomposition_level_count(),
                        std_bsk.grouping_factor(),
                    );

                    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128(
                        &std_bsk, &mut fbsk,
                    );

                    let thread_count = ShortintEngine::get_thread_count_for_multi_bit_pbs(
                        input_lwe_secret_key.lwe_dimension(),
                        params.glwe_dimension,
                        params.polynomial_size,
                        params.decomp_base_log,
                        params.decomp_level_count,
                        params.grouping_factor,
                    );

                    Self::MultiBit {
                        bsk: fbsk,
                        thread_count,
                        deterministic_execution: params.deterministic_execution,
                    }
                })
            }
        }
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic { bsk, .. } => bsk.output_lwe_dimension(),
            Self::MultiBit { bsk, .. } => bsk.output_lwe_dimension(),
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        match self {
            Self::Classic { bsk, .. } => bsk.glwe_size(),
            Self::MultiBit { bsk, .. } => bsk.glwe_size(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic { bsk, .. } => bsk.polynomial_size(),
            Self::MultiBit { bsk, .. } => bsk.polynomial_size(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Shortint128BootstrappingKeyConformanceParams {
    Classic {
        bootstrapping_key_params: LweBootstrapKeyConformanceParams<u128>,
        modulus_switch_noise_reduction_params: ModulusSwitchType,
    },
    MultiBit {
        bootstrapping_key_params: MultiBitBootstrapKeyConformanceParams<u128>,
    },
}

impl<Scalar> ParameterSetConformant for Shortint128BootstrappingKey<Scalar>
where
    Scalar: UnsignedInteger,
{
    type ParameterSet = Shortint128BootstrappingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (
                Self::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                },
                Shortint128BootstrappingKeyConformanceParams::Classic {
                    bootstrapping_key_params: expected_bootstrapping_key_params,
                    modulus_switch_noise_reduction_params:
                        expected_modulus_switch_noise_reduction_params,
                },
            ) => {
                let lwe_dimension = bsk.input_lwe_dimension();

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
                                lwe_dimension,
                            };

                        key.is_conformant(&mod_switch_conformance_params)
                    }
                    (_, _) => false,
                };

                modulus_switch_key_ok && bsk.is_conformant(expected_bootstrapping_key_params)
            }
            (
                Self::MultiBit { bsk, .. },
                Shortint128BootstrappingKeyConformanceParams::MultiBit {
                    bootstrapping_key_params: expected_bootstrapping_key_params,
                },
            ) => bsk.is_conformant(expected_bootstrapping_key_params),
            _ => false,
        }
    }
}

/// A server key that can be used for any noise squashing atomic patterns
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(GenericNoiseSquashingKeyVersions)]
pub struct GenericNoiseSquashingKey<AP> {
    atomic_pattern: AP,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

pub type NoiseSquashingKey = GenericNoiseSquashingKey<AtomicPatternNoiseSquashingKey>;
pub type StandardNoiseSquashingKey =
    GenericNoiseSquashingKey<StandardAtomicPatternNoiseSquashingKey>;
pub type NoiseSquashingKeyView<'key> =
    GenericNoiseSquashingKey<&'key AtomicPatternNoiseSquashingKey>;
pub type StandardNoiseSquashingKeyView<'key> =
    GenericNoiseSquashingKey<&'key StandardAtomicPatternNoiseSquashingKey>;

pub type ExpandedNoiseSquashingKey =
    GenericNoiseSquashingKey<super::atomic_pattern::ExpandedAtomicPatternNoiseSquashingKey>;

impl<'key> TryFrom<NoiseSquashingKeyView<'key>> for StandardNoiseSquashingKeyView<'key> {
    type Error = UnsupportedOperation;

    fn try_from(value: NoiseSquashingKeyView<'key>) -> Result<Self, Self::Error> {
        let AtomicPatternNoiseSquashingKey::Standard(atomic_pattern) = value.atomic_pattern else {
            return Err(UnsupportedOperation);
        };

        Ok(Self {
            atomic_pattern,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            output_ciphertext_modulus: value.output_ciphertext_modulus,
        })
    }
}

impl ClientKey {
    pub fn new_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> NoiseSquashingKey {
        let compute_parameters = self.parameters();

        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        assert_eq!(
            compute_parameters.message_modulus(),
            noise_squashing_parameters.message_modulus(),
            "Incompatible MessageModulus ClientKey {:?}, NoiseSquashingPrivateKey {:?}.",
            compute_parameters.message_modulus(),
            noise_squashing_parameters.message_modulus(),
        );
        assert_eq!(
            compute_parameters.carry_modulus(),
            noise_squashing_parameters.carry_modulus(),
            "Incompatible CarryModulus ClientKey {:?}, NoiseSquashingPrivateKey {:?}",
            compute_parameters.carry_modulus(),
            noise_squashing_parameters.carry_modulus(),
        );

        let atomic_pattern =
            AtomicPatternNoiseSquashingKey::new(&self.atomic_pattern, noise_squashing_private_key);

        NoiseSquashingKey {
            atomic_pattern,
            message_modulus: noise_squashing_parameters.message_modulus(),
            carry_modulus: noise_squashing_parameters.carry_modulus(),
            output_ciphertext_modulus: noise_squashing_parameters.ciphertext_modulus(),
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

    pub fn as_view(&self) -> NoiseSquashingKeyView<'_> {
        GenericNoiseSquashingKey {
            atomic_pattern: &self.atomic_pattern,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            output_ciphertext_modulus: self.output_ciphertext_modulus,
        }
    }
}

impl StandardNoiseSquashingKeyView<'_> {
    pub fn bootstrapping_key(&self) -> &Shortint128BootstrappingKey<u64> {
        self.atomic_pattern.bootstrapping_key()
    }
}

impl<AP> GenericNoiseSquashingKey<AP> {
    pub fn from_raw_parts(
        atomic_pattern: AP,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> Self {
        Self {
            atomic_pattern,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        AP,
        MessageModulus,
        CarryModulus,
        CoreCiphertextModulus<u128>,
    ) {
        let Self {
            atomic_pattern,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        (
            atomic_pattern,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        )
    }

    pub fn atomic_pattern(&self) -> &AP {
        &self.atomic_pattern
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

impl<AP: NoiseSquashingAtomicPattern> GenericNoiseSquashingKey<AP> {
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

        self.atomic_pattern.squash_ciphertext_noise(
            ciphertext,
            src_server_key.as_view(),
            self.message_modulus,
            self.carry_modulus,
            self.output_ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct NoiseSquashingKeyConformanceParams {
    pub(super) pbs_params: Shortint128BootstrappingKeyConformanceParams,
    pub(super) atomic_pattern: AtomicPatternKind,
    pub(super) message_modulus: MessageModulus,
    pub(super) carry_modulus: CarryModulus,
    pub(super) output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl TryFrom<(PBSParameters, NoiseSquashingParameters)>
    for Shortint128BootstrappingKeyConformanceParams
{
    type Error = crate::Error;

    fn try_from(
        (pbs_params, noise_squashing_params): (PBSParameters, NoiseSquashingParameters),
    ) -> Result<Self, Self::Error> {
        if pbs_params.message_modulus() != noise_squashing_params.message_modulus()
            || pbs_params.carry_modulus() != noise_squashing_params.carry_modulus()
        {
            return Err(crate::Error::new(format!(
                "Incompatible MessageModulus (PBS {:?}, NoiseSquashing {:?}) \
                or CarryModulus (PBS {:?}, NoiseSquashing {:?}) \
                when creating Shortint128BootstrappingKeyConformanceParams",
                pbs_params.message_modulus(),
                noise_squashing_params.message_modulus(),
                pbs_params.carry_modulus(),
                noise_squashing_params.carry_modulus()
            )));
        }

        Ok(match noise_squashing_params {
            NoiseSquashingParameters::Classic(params) => Self::Classic {
                bootstrapping_key_params: LweBootstrapKeyConformanceParams {
                    input_lwe_dimension: pbs_params.lwe_dimension(),
                    output_glwe_size: params.glwe_dimension.to_glwe_size(),
                    polynomial_size: params.polynomial_size,
                    decomp_base_log: params.decomp_base_log,
                    decomp_level_count: params.decomp_level_count,
                    ciphertext_modulus: params.ciphertext_modulus,
                },
                modulus_switch_noise_reduction_params: params.modulus_switch_noise_reduction_params,
            },
            NoiseSquashingParameters::MultiBit(params) => Self::MultiBit {
                bootstrapping_key_params: MultiBitBootstrapKeyConformanceParams {
                    input_lwe_dimension: pbs_params.lwe_dimension(),
                    output_glwe_size: params.glwe_dimension.to_glwe_size(),
                    polynomial_size: params.polynomial_size,
                    decomp_base_log: params.decomp_base_log,
                    decomp_level_count: params.decomp_level_count,
                    grouping_factor: params.grouping_factor,
                    ciphertext_modulus: params.ciphertext_modulus,
                },
            },
        })
    }
}

impl TryFrom<(KeySwitch32PBSParameters, NoiseSquashingParameters)>
    for Shortint128BootstrappingKeyConformanceParams
{
    type Error = crate::Error;

    fn try_from(
        (pbs_params, noise_squashing_params): (KeySwitch32PBSParameters, NoiseSquashingParameters),
    ) -> Result<Self, Self::Error> {
        if pbs_params.message_modulus() != noise_squashing_params.message_modulus()
            || pbs_params.carry_modulus() != noise_squashing_params.carry_modulus()
        {
            return Err(crate::Error::new(format!(
                "Incompatible MessageModulus (PBS {:?}, NoiseSquashing {:?}) \
                or CarryModulus (PBS {:?}, NoiseSquashing {:?}) \
                when creating Shortint128BootstrappingKeyConformanceParams",
                pbs_params.message_modulus(),
                noise_squashing_params.message_modulus(),
                pbs_params.carry_modulus(),
                noise_squashing_params.carry_modulus()
            )));
        }

        Ok(match noise_squashing_params {
            NoiseSquashingParameters::Classic(params) => Self::Classic {
                bootstrapping_key_params: LweBootstrapKeyConformanceParams {
                    input_lwe_dimension: pbs_params.lwe_dimension(),
                    output_glwe_size: params.glwe_dimension.to_glwe_size(),
                    polynomial_size: params.polynomial_size,
                    decomp_base_log: params.decomp_base_log,
                    decomp_level_count: params.decomp_level_count,
                    ciphertext_modulus: params.ciphertext_modulus,
                },
                modulus_switch_noise_reduction_params: params.modulus_switch_noise_reduction_params,
            },
            NoiseSquashingParameters::MultiBit(params) => Self::MultiBit {
                bootstrapping_key_params: MultiBitBootstrapKeyConformanceParams {
                    input_lwe_dimension: pbs_params.lwe_dimension(),
                    output_glwe_size: params.glwe_dimension.to_glwe_size(),
                    polynomial_size: params.polynomial_size,
                    decomp_base_log: params.decomp_base_log,
                    decomp_level_count: params.decomp_level_count,
                    grouping_factor: params.grouping_factor,
                    ciphertext_modulus: params.ciphertext_modulus,
                },
            },
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
        if ap_params.message_modulus() != noise_squashing_params.message_modulus()
            || ap_params.carry_modulus() != noise_squashing_params.carry_modulus()
        {
            return Err(crate::Error::new(format!(
                "Incompatible MessageModulus (PBS {:?}, NoiseSquashing {:?}) \
                or CarryModulus (PBS {:?}, NoiseSquashing {:?}) \
                when creating NoiseSquashingKeyConformanceParams",
                ap_params.message_modulus(),
                noise_squashing_params.message_modulus(),
                ap_params.carry_modulus(),
                noise_squashing_params.carry_modulus()
            )));
        }

        let noise_squashing_pbs_params = match ap_params {
            AtomicPatternParameters::Standard(pbs_params) => {
                (pbs_params, noise_squashing_params).try_into()?
            }
            AtomicPatternParameters::KeySwitch32(ks32_params) => {
                (ks32_params, noise_squashing_params).try_into()?
            }
        };

        Ok(Self {
            pbs_params: noise_squashing_pbs_params,
            atomic_pattern: ap_params.atomic_pattern(),
            message_modulus: ap_params.message_modulus(),
            carry_modulus: ap_params.carry_modulus(),
            output_ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        })
    }
}

impl ParameterSetConformant for NoiseSquashingKey {
    type ParameterSet = NoiseSquashingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            atomic_pattern,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        let bsk_conformant = match (atomic_pattern, parameter_set.atomic_pattern) {
            (AtomicPatternNoiseSquashingKey::Standard(std_nsk), AtomicPatternKind::Standard(_)) => {
                std_nsk
                    .bootstrapping_key()
                    .is_conformant(&parameter_set.pbs_params)
            }
            (
                AtomicPatternNoiseSquashingKey::KeySwitch32(ks32_nsk),
                AtomicPatternKind::KeySwitch32,
            ) => ks32_nsk
                .bootstrapping_key()
                .is_conformant(&parameter_set.pbs_params),
            _ => false,
        };

        bsk_conformant
            && *output_ciphertext_modulus == parameter_set.output_ciphertext_modulus
            && *message_modulus == parameter_set.message_modulus
            && *carry_modulus == parameter_set.carry_modulus
    }
}
