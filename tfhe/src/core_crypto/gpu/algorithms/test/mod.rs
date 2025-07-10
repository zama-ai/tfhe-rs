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
mod modulus_switch_noise_reduction;
mod noise_distribution;

pub struct CudaPackingKeySwitchKeys<Scalar: UnsignedInteger> {
    pub lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub glwe_sk: GlweSecretKey<Vec<Scalar>>,
    pub pksk: CudaLwePackingKeyswitchKey<Scalar>,
}

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

use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use {create_gpu_multi_bit_parameterized_test, create_gpu_parameterized_test};
