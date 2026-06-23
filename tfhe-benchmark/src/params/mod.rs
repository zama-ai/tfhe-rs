#[cfg(feature = "boolean")]
pub mod boolean_params {
    use crate::crypto_record::BenchPbsParams;
    use tfhe::boolean::parameters::{
        DEFAULT_PARAMETERS, DEFAULT_PARAMETERS_KS_PBS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    };

    pub fn benchmark_32bits_parameters() -> Vec<(String, BenchPbsParams<u32>)> {
        [
            ("BOOLEAN_DEFAULT_PARAMS", DEFAULT_PARAMETERS),
            (
                "BOOLEAN_TFHE_LIB_PARAMS",
                PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
            ),
            ("BOOLEAN_DEFAULT_PARAMS_KS_PBS", DEFAULT_PARAMETERS_KS_PBS),
        ]
        .iter()
        .map(|(name, params)| (name.to_string(), (*params).into()))
        .collect()
    }
}

#[cfg(feature = "boolean")]
pub use boolean_params::*;

#[cfg(feature = "shortint")]
pub mod shortint_params;

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
                #[cfg(feature = "gpu")]
                let params = vec![BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS.into()];
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                let params = vec![BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS.into()];

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
