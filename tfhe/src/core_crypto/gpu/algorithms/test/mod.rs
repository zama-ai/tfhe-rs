use crate::core_crypto::algorithms::test::*;

mod lwe_keyswitch;
mod lwe_linear_algebra;
mod lwe_multi_bit_programmable_bootstrapping;
mod lwe_programmable_bootstrapping;

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
            MULTI_BIT_2_2_3_PARAMS
        });
    };
}

use {create_gpu_multi_bit_parametrized_test, create_gpu_parametrized_test};
