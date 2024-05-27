use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_scalar_add_test, default_scalar_add_test, smart_scalar_add_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{RadixCiphertext, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_smart_scalar_add);
create_parametrized_test!(integer_default_scalar_add);
create_parametrized_test!(integer_default_overflowing_scalar_add);
create_parametrized_test!(integer_packed_scalar_add_assign_parallelized {
    // 4 bits minimum
   coverage => {
        COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
    },
    no_coverage => {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS,
        PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
        PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
        PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
    }
});

fn integer_smart_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_add_parallelized);
    smart_scalar_add_test(param, executor);
}

fn integer_default_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    default_scalar_add_test(param, executor);
}

fn integer_packed_scalar_add_assign_parallelized<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let func = |sks: &ServerKey, ct: &RadixCiphertext, scalar: u64| -> RadixCiphertext {
        let mut result = ct.clone();
        sks.packed_scalar_add_assign_parallelized(&mut result, scalar);
        result
    };
    let executor = CpuFunctionExecutor::new(func);
    default_scalar_add_test(param, executor);
}

fn integer_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_add_parallelized);
    default_overflowing_scalar_add_test(param, executor);
}
