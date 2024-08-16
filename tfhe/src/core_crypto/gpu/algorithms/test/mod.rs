use crate::core_crypto::algorithms::test::*;

mod glwe_sample_extraction;
mod lwe_keyswitch;
mod lwe_linear_algebra;
mod lwe_multi_bit_programmable_bootstrapping;
mod lwe_packing_keyswitch;
mod lwe_programmable_bootstrapping;

pub struct CudaPackingKeySwitchKeys<Scalar: UnsignedInteger> {
    pub lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub glwe_sk: GlweSecretKey<Vec<Scalar>>,
    pub pksk: CudaLwePackingKeyswitchKey<Scalar>,
}

// Macro to generate tests for all parameter sets
macro_rules! create_gpu_parametrized_test{
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
        create_gpu_parametrized_test!($name
        {
            TEST_PARAMS_4_BITS_NATIVE_U64
        });
    };
}
macro_rules! create_gpu_multi_bit_parametrized_test{
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
        create_gpu_multi_bit_parametrized_test!($name
        {
            MULTI_BIT_2_2_2_PARAMS,
            MULTI_BIT_2_2_3_PARAMS,
            MULTI_BIT_3_3_2_PARAMS,
            MULTI_BIT_3_3_3_PARAMS
        });
    };
}

use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use {create_gpu_multi_bit_parametrized_test, create_gpu_parametrized_test};
