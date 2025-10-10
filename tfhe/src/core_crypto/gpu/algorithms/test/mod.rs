use crate::core_crypto::algorithms::test::*;
use crate::core_crypto::prelude::*;

mod fft;
mod glwe_dot_product_with_clear;
mod glwe_sample_extraction;
mod lwe_keyswitch;
mod lwe_linear_algebra;
mod lwe_multi_bit_programmable_bootstrapping;
mod lwe_multi_bit_programmable_bootstrapping_128;
mod lwe_packing_keyswitch;
mod lwe_programmable_bootstrapping;
mod lwe_programmable_bootstrapping_128;
mod modulus_switch;
mod noise_distribution;
mod params;

pub struct CudaPackingKeySwitchKeys<Scalar: UnsignedInteger> {
    pub lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub glwe_sk: GlweSecretKey<Vec<Scalar>>,
    pub pksk: CudaLwePackingKeyswitchKey<Scalar>,
}

pub const MULTI_BIT_2_2_2_KS32_PARAMS: MultiBitTestKS32Params<u64> = MultiBitTestKS32Params {
    lwe_dimension: LweDimension(920),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(13),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus_log: MessageModulusLog(2),
    log2_p_fail: -134.345,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

// Macro to generate tests for all parameter sets
macro_rules! create_gpu_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_gpu_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_gpu_parameterized_test!($name
        {
            TEST_PARAMS_4_BITS_NATIVE_U64
        });
    };
}
macro_rules! create_gpu_multi_bit_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_gpu_ $name _ $param:lower>]() {
                $name(&$param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_gpu_multi_bit_parameterized_test!($name
        {
            MULTI_BIT_2_2_2_PARAMS,
            MULTI_BIT_2_2_3_PARAMS,
            MULTI_BIT_3_3_2_PARAMS,
            MULTI_BIT_3_3_3_PARAMS
        });
    };
}
macro_rules! create_gpu_multi_bit_ks32_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_gpu_ $name _ $param:lower>]() {
                $name(&$param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_gpu_multi_bit_ks32_parameterized_test!($name
        {
            MULTI_BIT_2_2_2_KS32_PARAMS
        });
    };
}
use crate::core_crypto::gpu::algorithms::test::params::MultiBitTestKS32Params;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use {
    create_gpu_multi_bit_ks32_parameterized_test, create_gpu_multi_bit_parameterized_test,
    create_gpu_parameterized_test,
};
