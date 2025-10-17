#[cfg(feature = "boolean")]
pub mod boolean_params {
    use crate::utilities::CryptoParametersRecord;
    use tfhe::boolean::parameters::{
        DEFAULT_PARAMETERS, DEFAULT_PARAMETERS_KS_PBS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    };

    pub fn benchmark_32bits_parameters() -> Vec<(String, CryptoParametersRecord<u32>)> {
        [
            ("BOOLEAN_DEFAULT_PARAMS", DEFAULT_PARAMETERS),
            (
                "BOOLEAN_TFHE_LIB_PARAMS",
                PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
            ),
            ("BOOLEAN_DEFAULT_PARAMS_KS_PBS", DEFAULT_PARAMETERS_KS_PBS),
        ]
        .iter()
        .map(|(name, params)| (name.to_string(), params.to_owned().into()))
        .collect()
    }
}

#[cfg(feature = "boolean")]
pub use boolean_params::*;

#[cfg(feature = "shortint")]
pub mod shortint_params {
    use crate::params_aliases::*;
    use std::collections::HashMap;
    use std::env;
    use std::sync::OnceLock;
    use tfhe::core_crypto::prelude::{DynamicDistribution, LweBskGroupingFactor};
    use tfhe::shortint::{
        AtomicPatternParameters, CarryModulus, ClassicPBSParameters, MessageModulus,
        MultiBitPBSParameters,
    };

    pub const SHORTINT_BENCH_PARAMS_TUNIFORM: [ClassicPBSParameters; 4] = [
        BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
    ];

    pub const SHORTINT_BENCH_PARAMS_GAUSSIAN: [ClassicPBSParameters; 4] = [
        BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    ];

    pub const SHORTINT_BENCH_PARAMS_TUNIFORM_DOCUMENTATION: [ClassicPBSParameters; 8] = [
        BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        BENCH_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        BENCH_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
    ];

    #[cfg(feature = "gpu")]
    pub const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 6] = [
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    ];

    #[cfg(feature = "gpu")]
    pub const SHORTINT_MULTI_BIT_BENCH_PARAMS_DOCUMENTATION: [(&str, MultiBitPBSParameters); 6] = [
        (
            "BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64",
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        ),
        (
            "BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64",
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ),
        (
            "BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64",
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        ),
        (
            "BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128",
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        ),
        (
            "BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128",
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ),
        (
            "BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128",
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        ),
    ];

    #[cfg(not(feature = "gpu"))]
    pub const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 6] = [
        BENCH_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    ];

    #[cfg(not(feature = "gpu"))]
    pub const SHORTINT_MULTI_BIT_BENCH_PARAMS_DOCUMENTATION: [(&str, MultiBitPBSParameters); 8] = [
        // Message_1_carry_1 2M64 and 2M128 are exactly the same, so we run one variant only
        // otherwise we would get a panic due to unicity rules of benchmark IDs/
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        ),
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ),
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        ),
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        ),
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        ),
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ),
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        ),
        (
            "BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128",
            BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
        ),
    ];

    #[cfg(feature = "internal-keycache")]
    pub mod shortint_params_keycache {
        use super::*;
        use crate::utilities::{get_param_type, CryptoParametersRecord, ParamType};
        use tfhe::keycache::NamedParam;

        pub fn benchmark_parameters() -> Vec<(String, CryptoParametersRecord<u64>)> {
            match get_parameters_set() {
                ParametersSet::Default => {
                    let iterator = match get_param_type() {
                        ParamType::ClassicalDocumentation => {
                            SHORTINT_BENCH_PARAMS_TUNIFORM_DOCUMENTATION
                                .iter()
                                .chain([].iter()) // Use an empty iterator to return the same type
                                                  // as the fallback case
                        }

                        _ => SHORTINT_BENCH_PARAMS_TUNIFORM
                            .iter()
                            .chain(SHORTINT_BENCH_PARAMS_GAUSSIAN.iter()),
                    };
                    iterator
                        .map(|params| {
                            (
                                params.name(),
                                <ClassicPBSParameters as Into<AtomicPatternParameters>>::into(
                                    *params,
                                )
                                .to_owned()
                                .into(),
                            )
                        })
                        .collect()
                }
                ParametersSet::All => {
                    filter_parameters(
                        &BENCH_ALL_CLASSIC_PBS_PARAMETERS,
                        DesiredNoiseDistribution::Both,
                        DesiredBackend::Cpu, /* No parameters set are specific to GPU in this
                                              * vector */
                    )
                    .into_iter()
                    .map(|(params, name)| {
                        (
                            name.to_string(),
                            <ClassicPBSParameters as Into<AtomicPatternParameters>>::into(*params)
                                .to_owned()
                                .into(),
                        )
                    })
                    .collect()
                }
            }
        }

        pub fn benchmark_compression_parameters() -> Vec<(String, CryptoParametersRecord<u64>)> {
            vec![(
                BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
                (
                    BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                )
                    .into(),
            )]
        }

        pub fn multi_bit_benchmark_parameters(
        ) -> Vec<(String, CryptoParametersRecord<u64>, LweBskGroupingFactor)> {
            match get_parameters_set() {
                ParametersSet::Default => match get_param_type() {
                    ParamType::MultiBitDocumentation => {
                        SHORTINT_MULTI_BIT_BENCH_PARAMS_DOCUMENTATION
                            .iter()
                            .map(|(name, params)| {
                                (
                                    name.to_string(),
                                    <MultiBitPBSParameters as Into<AtomicPatternParameters>>::into(
                                        *params,
                                    )
                                    .to_owned()
                                    .into(),
                                    params.grouping_factor,
                                )
                            })
                            .collect()
                    }
                    _ => SHORTINT_MULTI_BIT_BENCH_PARAMS
                        .iter()
                        .map(|params| {
                            (
                                params.name(),
                                <MultiBitPBSParameters as Into<AtomicPatternParameters>>::into(
                                    *params,
                                )
                                .to_owned()
                                .into(),
                                params.grouping_factor,
                            )
                        })
                        .collect(),
                },
                ParametersSet::All => {
                    let desired_backend = if cfg!(feature = "gpu") {
                        DesiredBackend::Gpu
                    } else {
                        DesiredBackend::Cpu
                    };
                    filter_parameters(
                        &BENCH_ALL_MULTI_BIT_PBS_PARAMETERS,
                        DesiredNoiseDistribution::Both,
                        desired_backend,
                    )
                    .into_iter()
                    .map(|(params, name)| {
                        (
                            name.to_string(),
                            <MultiBitPBSParameters as Into<AtomicPatternParameters>>::into(*params)
                                .to_owned()
                                .into(),
                            params.grouping_factor,
                        )
                    })
                    .collect()
                }
            }
        }

        pub fn multi_bit_benchmark_parameters_with_grouping(
        ) -> Vec<(String, CryptoParametersRecord<u64>, LweBskGroupingFactor)> {
            match get_parameters_set() {
                ParametersSet::Default => match get_param_type() {
                    ParamType::MultiBitDocumentation => {
                        SHORTINT_MULTI_BIT_BENCH_PARAMS_DOCUMENTATION
                            .iter()
                            .map(|(name, params)| {
                                (
                                    name.to_string(),
                                    <MultiBitPBSParameters as Into<AtomicPatternParameters>>::into(
                                        *params,
                                    )
                                    .to_owned()
                                    .into(),
                                    params.grouping_factor,
                                )
                            })
                            .collect()
                    }
                    _ => SHORTINT_MULTI_BIT_BENCH_PARAMS
                        .iter()
                        .map(|params| {
                            (
                                params.name(),
                                <MultiBitPBSParameters as Into<AtomicPatternParameters>>::into(
                                    *params,
                                )
                                .to_owned()
                                .into(),
                                params.grouping_factor,
                            )
                        })
                        .collect(),
                },
                ParametersSet::All => {
                    let desired_backend = if cfg!(feature = "gpu") {
                        DesiredBackend::Gpu
                    } else {
                        DesiredBackend::Cpu
                    };
                    filter_parameters(
                        &BENCH_ALL_MULTI_BIT_PBS_PARAMETERS,
                        DesiredNoiseDistribution::Both,
                        desired_backend,
                    )
                    .into_iter()
                    .map(|(params, name)| {
                        (
                            name.to_string(),
                            <MultiBitPBSParameters as Into<AtomicPatternParameters>>::into(*params)
                                .to_owned()
                                .into(),
                            params.grouping_factor,
                        )
                    })
                    .collect()
                }
            }
        }
    }

    #[cfg(feature = "internal-keycache")]
    pub use shortint_params_keycache::*;
    use tfhe::shortint::parameters::current_params::meta::cpu::*;
    use tfhe::shortint::parameters::current_params::meta::gpu::*;
    use tfhe::shortint::parameters::MetaParameters;

    pub fn raw_benchmark_parameters() -> Vec<AtomicPatternParameters> {
        let is_multi_bit = match env::var("__TFHE_RS_PARAM_TYPE") {
            Ok(val) => val.to_lowercase() == "multi_bit",
            Err(_) => false,
        };

        if is_multi_bit {
            SHORTINT_MULTI_BIT_BENCH_PARAMS
                .iter()
                .map(|p| (*p).into())
                .collect()
        } else {
            SHORTINT_BENCH_PARAMS_TUNIFORM
                .iter()
                .chain(SHORTINT_BENCH_PARAMS_GAUSSIAN.iter())
                .map(|p| (*p).into())
                .collect()
        }
    }

    // This array has been built according to performance benchmarks measuring latency over a
    // matrix of 4 parameters set, 3 grouping factor and a wide range of threads values.
    // The values available here as u64 are the optimal number of threads to use for a given triplet
    // representing one or more parameters set.
    const MULTI_BIT_THREADS_ARRAY: [((MessageModulus, CarryModulus, LweBskGroupingFactor), u64);
        12] = [
        (
            (MessageModulus(2), CarryModulus(2), LweBskGroupingFactor(2)),
            5,
        ),
        (
            (MessageModulus(4), CarryModulus(4), LweBskGroupingFactor(2)),
            5,
        ),
        (
            (MessageModulus(8), CarryModulus(8), LweBskGroupingFactor(2)),
            5,
        ),
        (
            (
                MessageModulus(16),
                CarryModulus(16),
                LweBskGroupingFactor(2),
            ),
            5,
        ),
        (
            (MessageModulus(2), CarryModulus(2), LweBskGroupingFactor(3)),
            7,
        ),
        (
            (MessageModulus(4), CarryModulus(4), LweBskGroupingFactor(3)),
            9,
        ),
        (
            (MessageModulus(8), CarryModulus(8), LweBskGroupingFactor(3)),
            10,
        ),
        (
            (
                MessageModulus(16),
                CarryModulus(16),
                LweBskGroupingFactor(3),
            ),
            10,
        ),
        (
            (MessageModulus(2), CarryModulus(2), LweBskGroupingFactor(4)),
            11,
        ),
        (
            (MessageModulus(4), CarryModulus(4), LweBskGroupingFactor(4)),
            13,
        ),
        (
            (MessageModulus(8), CarryModulus(8), LweBskGroupingFactor(4)),
            11,
        ),
        (
            (
                MessageModulus(16),
                CarryModulus(16),
                LweBskGroupingFactor(4),
            ),
            11,
        ),
    ];

    /// Define the number of threads to use for  parameters doing multithreaded programmable
    /// bootstrapping.
    ///
    /// Parameters must have the same values between message and carry modulus.
    /// Grouping factor 2, 3 and 4 are the only ones that are supported.
    pub fn multi_bit_num_threads(
        message_modulus: u64,
        carry_modulus: u64,
        grouping_factor: usize,
    ) -> Option<u64> {
        // TODO Implement an interpolation mechanism for X_Y parameters set
        if message_modulus != carry_modulus || ![2, 3, 4].contains(&(grouping_factor as i32)) {
            return None;
        }
        let thread_map: HashMap<(MessageModulus, CarryModulus, LweBskGroupingFactor), u64> =
            HashMap::from_iter(MULTI_BIT_THREADS_ARRAY);
        thread_map
            .get(&(
                MessageModulus(message_modulus),
                CarryModulus(carry_modulus),
                LweBskGroupingFactor(grouping_factor),
            ))
            .copied()
    }

    pub static PARAMETERS_SET: OnceLock<ParametersSet> = OnceLock::new();

    pub enum ParametersSet {
        Default,
        All,
    }

    impl ParametersSet {
        pub fn from_env() -> Result<Self, String> {
            let raw_value = env::var("__TFHE_RS_PARAMS_SET").unwrap_or("default".to_string());
            match raw_value.to_lowercase().as_str() {
                "default" => Ok(ParametersSet::Default),
                "all" => Ok(ParametersSet::All),
                _ => Err(format!("parameters set '{raw_value}' is not supported")),
            }
        }
    }

    pub fn get_parameters_set() -> &'static ParametersSet {
        PARAMETERS_SET.get_or_init(|| ParametersSet::from_env().unwrap())
    }

    #[derive(Clone, Copy, Debug)]
    pub enum DesiredNoiseDistribution {
        Gaussian,
        TUniform,
        Both,
    }

    #[derive(Clone, Copy, Debug)]
    pub enum DesiredBackend {
        Cpu,
        Gpu,
    }

    impl DesiredBackend {
        fn matches_parameter_name_backend(&self, param_name: &str) -> bool {
            matches!(
                (self, param_name.to_lowercase().contains("gpu")),
                (DesiredBackend::Cpu, false) | (DesiredBackend::Gpu, true)
            )
        }
    }

    pub fn filter_parameters<'a, P: Copy + Into<AtomicPatternParameters>>(
        params: &[(&'a P, &'a str)],
        desired_noise_distribution: DesiredNoiseDistribution,
        desired_backend: DesiredBackend,
    ) -> Vec<(&'a P, &'a str)> {
        params
            .iter()
            .filter_map(|(p, name)| {
                let temp_param: AtomicPatternParameters = (**p).into();

                match (
                    temp_param.lwe_noise_distribution(),
                    desired_noise_distribution,
                ) {
                    // If it's one of the pairs, we continue the process.
                    (DynamicDistribution::Gaussian(_), DesiredNoiseDistribution::Gaussian)
                    | (DynamicDistribution::TUniform(_), DesiredNoiseDistribution::TUniform)
                    | (_, DesiredNoiseDistribution::Both) => (),
                    _ => return None,
                }

                if !desired_backend.matches_parameter_name_backend(name) {
                    return None;
                };

                Some((*p, *name))
            })
            .collect()
    }

    pub fn get_classical_tuniform_groups() -> Vec<MetaParameters> {
        vec![
            // Most complete 2_2 parameters set
            V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_1_1_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_3_3_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_4_4_KS_PBS_TUNIFORM_2M128,
        ]
    }

    pub fn get_multi_bit_tuniform_groups() -> Vec<MetaParameters> {
        // TODO Complete parameters groups once corresponding parameters set are available.
        vec![
            // Group 2
            // CPU ---
            V1_5_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128,
            // GPU ---
            V1_5_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128,
            // Group 3
            // CPU ---
            V1_5_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128,
            // GPU ---
            V1_5_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128,
            // Group 4
            // CPU ---
            V1_5_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128,
            V1_5_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128,
            // GPU ---
            V1_5_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128,
            V1_5_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128,
        ]
    }
}

#[cfg(feature = "shortint")]
pub use shortint_params::*;

#[cfg(feature = "integer")]
mod integer_params {
    use crate::params_aliases::*;
    use crate::utilities::EnvConfig;
    use itertools::iproduct;
    use std::vec::IntoIter;
    use tfhe::shortint::AtomicPatternParameters;

    /// An iterator that yields a succession of combinations
    /// of parameters and a num_block to achieve a certain bit_size ciphertext
    /// in radix decomposition
    pub struct ParamsAndNumBlocksIter {
        params_and_bit_sizes:
            itertools::Product<IntoIter<AtomicPatternParameters>, IntoIter<usize>>,
    }

    impl Default for ParamsAndNumBlocksIter {
        fn default() -> Self {
            let env_config = EnvConfig::new();

            if env_config.is_multi_bit {
                #[cfg(feature = "hpu")]
                panic!("Hpu doesn't implement MultiBit");

                #[cfg(not(feature = "hpu"))]
                {
                    #[cfg(feature = "gpu")]
                    let params = vec![
                        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                            .into(),
                    ];
                    #[cfg(not(feature = "gpu"))]
                    let params = vec![
                        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
                            .into(),
                    ];

                    let params_and_bit_sizes = iproduct!(params, env_config.bit_sizes());
                    Self {
                        params_and_bit_sizes,
                    }
                }
            } else {
                // FIXME One set of parameter is tested since we want to benchmark only quickest
                // operations.
                #[cfg(feature = "hpu")]
                let params = vec![BENCH_HPU_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128.into()];
                #[cfg(not(feature = "hpu"))]
                let params = vec![BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into()];

                let params_and_bit_sizes = iproduct!(params, env_config.bit_sizes());
                Self {
                    params_and_bit_sizes,
                }
            }
        }
    }

    impl Iterator for ParamsAndNumBlocksIter {
        type Item = (AtomicPatternParameters, usize, usize);

        fn next(&mut self) -> Option<Self::Item> {
            let (param, bit_size) = self.params_and_bit_sizes.next()?;
            let num_block =
                (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize;

            Some((param, num_block, bit_size))
        }
    }
}

#[cfg(feature = "integer")]
pub use integer_params::*;
