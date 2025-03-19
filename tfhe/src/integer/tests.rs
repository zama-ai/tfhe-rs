macro_rules! create_parameterized_test {
    (
        $name:ident {
            $($(#[$cfg:meta])* $param:ident),*
            $(,)?
        }
    ) => {
        ::paste::paste! {
            $(
                #[test]
                $(#[$cfg])*
                fn [<test_ $name _ $param:lower>]() {
                    $name($param)
                }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_test!($name
        {
            coverage => {
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
            },
            no_coverage => {
                TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
                TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
                TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64
            }
        });
    };

    ($name:ident { coverage => {$($param_cover:ident),* $(,)?}, no_coverage => {$($param_no_cover:ident),* $(,)?} }) => {
        ::paste::paste! {
            $(
                #[test]
                #[cfg(tarpaulin)]
                fn [<test_ $name _ $param_cover:lower>]() {
                    $name($param_cover)
                }
            )*
            $(
                #[test]
                #[cfg(not(tarpaulin))]
                fn [<test_ $name _ $param_no_cover:lower>]() {
                    $name($param_no_cover)
                }
            )*
        }
    };
}
macro_rules! create_parameterized_test_classical_params {
    (
        $name:ident
    ) => {
        $crate::integer::tests::create_parameterized_test!($name {
            coverage => {
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            },
            no_coverage => {
                TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
            }
        });
    };
}
pub(crate) use {create_parameterized_test, create_parameterized_test_classical_params};
