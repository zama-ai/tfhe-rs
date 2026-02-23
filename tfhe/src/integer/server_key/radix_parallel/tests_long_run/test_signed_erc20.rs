use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_long_run::{
    NB_CTXT_LONG_RUN, NB_TESTS_LONG_RUN,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    BooleanBlock, IntegerCiphertext, IntegerKeyKind, RadixClientKey, ServerKey,
    SignedRadixCiphertext,
};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(whitepaper_erc20 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_parameterized_test!(no_cmux_erc20 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn whitepaper_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ge_executor = CpuFunctionExecutor::new(&ServerKey::ge_parallelized);
    let add_executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    let if_then_else_executor = CpuFunctionExecutor::new(&ServerKey::cmux_parallelized);
    let sub_executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    signed_whitepaper_erc20_test(
        param,
        ge_executor,
        add_executor,
        if_then_else_executor,
        sub_executor,
    );
}

fn no_cmux_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ge_executor = CpuFunctionExecutor::new(&ServerKey::ge_parallelized);
    let mul_executor = CpuFunctionExecutor::new(&ServerKey::mul_parallelized);
    let add_executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    let sub_executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    signed_no_cmux_erc20_test(param, ge_executor, mul_executor, add_executor, sub_executor);
}

pub(crate) fn signed_whitepaper_erc20_test<P, T1, T2, T3, T4>(
    param: P,
    mut ge_executor: T1,
    mut add_executor: T2,
    mut if_then_else_executor: T3,
    mut sub_executor: T4,
) where
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        BooleanBlock,
    >,
    T2: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
    T3: for<'a> FunctionExecutor<
        (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
        SignedRadixCiphertext,
    >,
    T4: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let mut rng = rand::rng();

    ge_executor.setup(&cks, sks.clone());
    add_executor.setup(&cks, sks.clone());
    if_then_else_executor.setup(&cks, sks.clone());
    sub_executor.setup(&cks, sks);

    for _ in 0..NB_TESTS_LONG_RUN {
        let clear_from_amount = rng.gen::<i64>();
        let clear_to_amount = rng.gen::<i64>();
        let clear_amount = rng.gen::<i64>();

        let from_amount = cks.encrypt_signed(clear_from_amount);
        let to_amount = cks.encrypt_signed(clear_to_amount);
        let amount = cks.encrypt_signed(clear_amount);

        let has_enough_funds = ge_executor.execute((&from_amount, &amount));

        let mut new_to_amount = add_executor.execute((&to_amount, &amount));
        new_to_amount =
            if_then_else_executor.execute((&has_enough_funds, &new_to_amount, &to_amount));

        let mut new_from_amount = sub_executor.execute((&from_amount, &amount));
        new_from_amount =
            if_then_else_executor.execute((&has_enough_funds, &new_from_amount, &from_amount));

        let decrypt_signed_new_from_amount: i64 = cks.decrypt_signed(&new_from_amount);
        let decrypt_signed_new_to_amount: i64 = cks.decrypt_signed(&new_to_amount);

        let expected_new_from_amount = if clear_from_amount >= clear_amount {
            clear_from_amount - clear_amount
        } else {
            clear_from_amount
        };
        let expected_new_to_amount = if clear_from_amount >= clear_amount {
            clear_to_amount + clear_amount
        } else {
            clear_to_amount
        };

        assert_eq!(
            decrypt_signed_new_from_amount, expected_new_from_amount,
            "Invalid erc20 result on from amount: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}, expected new from amount: {expected_new_from_amount}."
        );
        assert_eq!(
            decrypt_signed_new_to_amount, expected_new_to_amount,
            "Invalid erc20 result on to amount."
        );

        // Determinism check
        let has_enough_funds_1 = ge_executor.execute((&from_amount, &amount));

        let mut new_to_amount_1 = add_executor.execute((&to_amount, &amount));
        new_to_amount_1 =
            if_then_else_executor.execute((&has_enough_funds_1, &new_to_amount_1, &to_amount));

        let mut new_from_amount_1 = sub_executor.execute((&from_amount, &amount));
        new_from_amount_1 =
            if_then_else_executor.execute((&has_enough_funds_1, &new_from_amount_1, &from_amount));

        assert_eq!(
            new_from_amount, new_from_amount_1,
            "Determinism check failed on erc20 from amount"
        );
        assert_eq!(
            new_to_amount, new_to_amount_1,
            "Determinism check failed on erc20 to amount"
        );
    }
}

pub(crate) fn signed_no_cmux_erc20_test<P, T1, T2, T3, T4>(
    param: P,
    mut ge_executor: T1,
    mut mul_executor: T2,
    mut add_executor: T3,
    mut sub_executor: T4,
) where
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        BooleanBlock,
    >,
    T2: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
    T3: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
    T4: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let mut rng = rand::rng();

    ge_executor.setup(&cks, sks.clone());
    mul_executor.setup(&cks, sks.clone());
    add_executor.setup(&cks, sks.clone());
    sub_executor.setup(&cks, sks);

    for _ in 0..NB_TESTS_LONG_RUN {
        let clear_from_amount = rng.gen::<i64>();
        let clear_to_amount = rng.gen::<i64>();
        let clear_amount = rng.gen::<i64>();

        let from_amount = cks.encrypt_signed(clear_from_amount);
        let to_amount = cks.encrypt_signed(clear_to_amount);
        let amount = cks.encrypt_signed(clear_amount);

        let has_enough_funds = ge_executor.execute((&from_amount, &amount));
        let has_enough_funds_ct = SignedRadixCiphertext::from_blocks(vec![has_enough_funds.0]);
        let new_amount = mul_executor.execute((&amount, &has_enough_funds_ct));
        let new_to_amount = add_executor.execute((&to_amount, &new_amount));
        let new_from_amount = sub_executor.execute((&from_amount, &new_amount));

        let decrypt_signed_new_from_amount: i64 = cks.decrypt_signed(&new_from_amount);
        let decrypt_signed_new_to_amount: i64 = cks.decrypt_signed(&new_to_amount);

        let expected_new_from_amount = if clear_from_amount >= clear_amount {
            clear_from_amount - clear_amount
        } else {
            clear_from_amount
        };
        let expected_new_to_amount = if clear_from_amount >= clear_amount {
            clear_to_amount + clear_amount
        } else {
            clear_to_amount
        };

        assert_eq!(
            decrypt_signed_new_from_amount, expected_new_from_amount,
            "Invalid erc20 result on from amount: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}, expected new from amount: {expected_new_from_amount}."
        );
        assert_eq!(
            decrypt_signed_new_to_amount, expected_new_to_amount,
            "Invalid erc20 result on to amount."
        );

        // Determinism check
        let has_enough_funds_1 = ge_executor.execute((&from_amount, &amount));
        let has_enough_funds_ct_1 = SignedRadixCiphertext::from_blocks(vec![has_enough_funds_1.0]);
        let new_amount_1 = mul_executor.execute((&amount, &has_enough_funds_ct_1));
        let new_to_amount_1 = add_executor.execute((&to_amount, &new_amount_1));
        let new_from_amount_1 = sub_executor.execute((&from_amount, &new_amount_1));

        assert_eq!(
            new_from_amount, new_from_amount_1,
            "Determinism check failed on no cmux erc20 from amount"
        );
        assert_eq!(
            new_to_amount, new_to_amount_1,
            "Determinism check failed on no cmux erc20 to amount"
        );
    }
}
