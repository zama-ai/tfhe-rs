macro_rules! create_parametrized_test {
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
        create_parametrized_test!($name
        {
            coverage => {
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
            },
            no_coverage => {
                PARAM_MESSAGE_1_CARRY_1_KS_PBS,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
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
macro_rules! create_parametrized_test_classical_params {
    (
        $name:ident
    ) => {
        $crate::integer::tests::create_parametrized_test!($name {
            coverage => {
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            },
            no_coverage => {
                PARAM_MESSAGE_1_CARRY_1_KS_PBS,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                PARAM_MESSAGE_4_CARRY_4_KS_PBS
            }
        });
    };
}
pub(crate) use {create_parametrized_test, create_parametrized_test_classical_params};
