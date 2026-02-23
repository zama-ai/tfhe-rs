use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_long_run::{
    NB_CTXT_LONG_RUN, NB_TESTS_LONG_RUN,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    BooleanBlock, IntegerCiphertext, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey,
};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(safe_erc20 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_parameterized_test!(whitepaper_erc20 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_parameterized_test!(no_cmux_erc20 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_parameterized_test!(overflow_erc20 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn safe_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let overflowing_add_executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    let overflowing_sub_executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    let if_then_else_executor = CpuFunctionExecutor::new(&ServerKey::cmux_parallelized);
    let bitwise_or_executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    safe_erc20_test(
        param,
        overflowing_add_executor,
        overflowing_sub_executor,
        if_then_else_executor,
        bitwise_or_executor,
    );
}

fn whitepaper_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ge_executor = CpuFunctionExecutor::new(&ServerKey::ge_parallelized);
    let add_executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    let if_then_else_executor = CpuFunctionExecutor::new(&ServerKey::cmux_parallelized);
    let sub_executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    whitepaper_erc20_test(
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
    no_cmux_erc20_test(param, ge_executor, mul_executor, add_executor, sub_executor);
}

fn overflow_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let overflowing_sub_executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    let if_then_else_executor = CpuFunctionExecutor::new(&ServerKey::cmux_parallelized);
    let not_executor = CpuFunctionExecutor::new(&ServerKey::boolean_bitnot);
    let mul_executor = CpuFunctionExecutor::new(&ServerKey::mul_parallelized);
    let add_executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    overflow_erc20_test(
        param,
        overflowing_sub_executor,
        if_then_else_executor,
        not_executor,
        mul_executor,
        add_executor,
    );
}

pub(crate) fn safe_erc20_test<P, T1, T2, T3, T4>(
    param: P,
    mut overflowing_add_executor: T1,
    mut overflowing_sub_executor: T2,
    mut if_then_else_executor: T3,
    mut bitor_executor: T4,
) where
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
    T2: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
    T3: for<'a> FunctionExecutor<
        (&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext),
        RadixCiphertext,
    >,
    T4: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let mut rng = rand::rng();

    overflowing_add_executor.setup(&cks, sks.clone());
    overflowing_sub_executor.setup(&cks, sks.clone());
    if_then_else_executor.setup(&cks, sks.clone());
    bitor_executor.setup(&cks, sks);

    for _ in 0..NB_TESTS_LONG_RUN {
        let clear_from_amount = rng.gen::<u64>();
        let clear_to_amount = rng.gen::<u64>();
        let clear_amount = rng.gen::<u64>();

        let from_amount = cks.encrypt(clear_from_amount);
        let to_amount = cks.encrypt(clear_to_amount);
        let amount = cks.encrypt(clear_amount);

        let (new_from, did_not_have_enough_funds) =
            overflowing_sub_executor.execute((&from_amount, &amount));
        let (new_to, did_not_have_enough_space) =
            overflowing_add_executor.execute((&to_amount, &amount));

        let decrypted_did_not_have_enough_funds: bool =
            cks.decrypt_bool(&did_not_have_enough_funds);
        let decrypted_did_not_have_enough_space: bool =
            cks.decrypt_bool(&did_not_have_enough_space);

        let did_not_have_enough_space_ct =
            RadixCiphertext::from_blocks(vec![did_not_have_enough_space.0]);
        let did_not_have_enough_funds_ct =
            RadixCiphertext::from_blocks(vec![did_not_have_enough_funds.0]);

        let something_not_ok_ct =
            bitor_executor.execute((&did_not_have_enough_funds_ct, &did_not_have_enough_space_ct));
        let something_not_ok = BooleanBlock(something_not_ok_ct.blocks.first().unwrap().clone());

        let new_from_amount =
            if_then_else_executor.execute((&something_not_ok, &from_amount, &new_from));
        let new_to_amount = if_then_else_executor.execute((&something_not_ok, &to_amount, &new_to));

        let decrypted_new_from_amount: u64 = cks.decrypt(&new_from_amount);
        let decrypted_new_to_amount: u64 = cks.decrypt(&new_to_amount);
        let decrypted_something_not_ok: bool = cks.decrypt_bool(&something_not_ok);

        let (expected_new_from, expected_did_not_have_enough_funds) =
            clear_from_amount.overflowing_sub(clear_amount);
        let (expected_new_to, expected_did_not_have_enough_space) =
            clear_to_amount.overflowing_add(clear_amount);

        let expected_something_not_ok =
            expected_did_not_have_enough_funds | expected_did_not_have_enough_space;
        let expected_new_to_amount = if expected_something_not_ok {
            clear_to_amount
        } else {
            expected_new_to
        };
        let expected_new_from_amount = if expected_something_not_ok {
            clear_from_amount
        } else {
            expected_new_from
        };

        assert_eq!(
            decrypted_did_not_have_enough_funds, expected_did_not_have_enough_funds,
            "Invalid erc20 result on enough funds: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}."
        );
        assert_eq!(
            decrypted_did_not_have_enough_space, expected_did_not_have_enough_space,
            "Invalid erc20 result on enough space: amount: {clear_amount}, to amount: {clear_to_amount}."
        );
        assert_eq!(
            decrypted_something_not_ok, expected_something_not_ok,
            "Invalid erc20 result on something nok: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}."
        );
        assert_eq!(
            decrypted_new_from_amount, expected_new_from_amount,
            "Invalid erc20 result on from amount: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}, expected new from amount: {expected_new_from_amount}."
        );
        assert_eq!(
            decrypted_new_to_amount, expected_new_to_amount,
            "Invalid erc20 result on to amount."
        );

        // Determinism check
        let (new_from_1, did_not_have_enough_funds_1) =
            overflowing_sub_executor.execute((&from_amount, &amount));
        let (new_to_1, did_not_have_enough_space_1) =
            overflowing_add_executor.execute((&to_amount, &amount));
        let did_not_have_enough_space_ct_1 =
            RadixCiphertext::from_blocks(vec![did_not_have_enough_space_1.0]);
        let did_not_have_enough_funds_ct_1 =
            RadixCiphertext::from_blocks(vec![did_not_have_enough_funds_1.0]);

        let something_not_ok_ct_1 = bitor_executor.execute((
            &did_not_have_enough_funds_ct_1,
            &did_not_have_enough_space_ct_1,
        ));
        let something_not_ok_1 =
            BooleanBlock(something_not_ok_ct_1.blocks.first().unwrap().clone());

        let new_from_amount_1 =
            if_then_else_executor.execute((&something_not_ok_1, &from_amount, &new_from_1));
        let new_to_amount_1 =
            if_then_else_executor.execute((&something_not_ok_1, &to_amount, &new_to_1));
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

pub(crate) fn whitepaper_erc20_test<P, T1, T2, T3, T4>(
    param: P,
    mut ge_executor: T1,
    mut add_executor: T2,
    mut if_then_else_executor: T3,
    mut sub_executor: T4,
) where
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    T2: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    T3: for<'a> FunctionExecutor<
        (&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext),
        RadixCiphertext,
    >,
    T4: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
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
        let clear_from_amount = rng.gen::<u64>();
        let clear_to_amount = rng.gen::<u64>();
        let clear_amount = rng.gen::<u64>();

        let from_amount = cks.encrypt(clear_from_amount);
        let to_amount = cks.encrypt(clear_to_amount);
        let amount = cks.encrypt(clear_amount);

        let has_enough_funds = ge_executor.execute((&from_amount, &amount));

        let mut new_to_amount = add_executor.execute((&to_amount, &amount));
        new_to_amount =
            if_then_else_executor.execute((&has_enough_funds, &new_to_amount, &to_amount));

        let mut new_from_amount = sub_executor.execute((&from_amount, &amount));
        new_from_amount =
            if_then_else_executor.execute((&has_enough_funds, &new_from_amount, &from_amount));

        let decrypted_new_from_amount: u64 = cks.decrypt(&new_from_amount);
        let decrypted_new_to_amount: u64 = cks.decrypt(&new_to_amount);

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
            decrypted_new_from_amount, expected_new_from_amount,
            "Invalid erc20 result on from amount: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}, expected new from amount: {expected_new_from_amount}."
        );
        assert_eq!(
            decrypted_new_to_amount, expected_new_to_amount,
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

pub(crate) fn no_cmux_erc20_test<P, T1, T2, T3, T4>(
    param: P,
    mut ge_executor: T1,
    mut mul_executor: T2,
    mut add_executor: T3,
    mut sub_executor: T4,
) where
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    T2: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    T3: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    T4: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
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
        let clear_from_amount = rng.gen::<u64>();
        let clear_to_amount = rng.gen::<u64>();
        let clear_amount = rng.gen::<u64>();

        let from_amount = cks.encrypt(clear_from_amount);
        let to_amount = cks.encrypt(clear_to_amount);
        let amount = cks.encrypt(clear_amount);

        let has_enough_funds = ge_executor.execute((&from_amount, &amount));
        let has_enough_funds_ct = RadixCiphertext::from_blocks(vec![has_enough_funds.0]);
        let new_amount = mul_executor.execute((&amount, &has_enough_funds_ct));
        let new_to_amount = add_executor.execute((&to_amount, &new_amount));
        let new_from_amount = sub_executor.execute((&from_amount, &new_amount));

        let decrypted_new_from_amount: u64 = cks.decrypt(&new_from_amount);
        let decrypted_new_to_amount: u64 = cks.decrypt(&new_to_amount);

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
            decrypted_new_from_amount, expected_new_from_amount,
            "Invalid erc20 result on from amount: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}, expected new from amount: {expected_new_from_amount}."
        );
        assert_eq!(
            decrypted_new_to_amount, expected_new_to_amount,
            "Invalid erc20 result on to amount."
        );

        // Determinism check
        let has_enough_funds_1 = ge_executor.execute((&from_amount, &amount));
        let has_enough_funds_ct_1 = RadixCiphertext::from_blocks(vec![has_enough_funds_1.0]);
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

pub(crate) fn overflow_erc20_test<P, T1, T2, T3, T4, T5>(
    param: P,
    mut overflowing_sub_executor: T1,
    mut if_then_else_executor: T2,
    mut not_executor: T3,
    mut mul_executor: T4,
    mut add_executor: T5,
) where
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
    T2: for<'a> FunctionExecutor<
        (&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext),
        RadixCiphertext,
    >,
    T3: for<'a> FunctionExecutor<&'a BooleanBlock, BooleanBlock>,
    T4: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    T5: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let mut rng = rand::rng();

    overflowing_sub_executor.setup(&cks, sks.clone());
    if_then_else_executor.setup(&cks, sks.clone());
    not_executor.setup(&cks, sks.clone());
    mul_executor.setup(&cks, sks.clone());
    add_executor.setup(&cks, sks);

    for _ in 0..NB_TESTS_LONG_RUN {
        let clear_from_amount = rng.gen::<u64>();
        let clear_to_amount = rng.gen::<u64>();
        let clear_amount = rng.gen::<u64>();

        let from_amount = cks.encrypt(clear_from_amount);
        let to_amount = cks.encrypt(clear_to_amount);
        let amount = cks.encrypt(clear_amount);

        let (new_from, did_not_have_enough_funds) =
            overflowing_sub_executor.execute((&from_amount, &amount));

        let new_from_amount =
            if_then_else_executor.execute((&did_not_have_enough_funds, &from_amount, &new_from));

        let had_enough_funds = not_executor.execute(&did_not_have_enough_funds);
        let had_enough_funds_ct = RadixCiphertext::from_blocks(vec![had_enough_funds.0]);
        let new_amount = mul_executor.execute((&amount, &had_enough_funds_ct));
        let new_to_amount = add_executor.execute((&to_amount, &new_amount));
        let decrypted_did_not_have_enough_funds: bool =
            cks.decrypt_bool(&did_not_have_enough_funds);

        let decrypted_new_from_amount: u64 = cks.decrypt(&new_from_amount);
        let decrypted_new_to_amount: u64 = cks.decrypt(&new_to_amount);

        let (expected_new_from, expected_did_not_have_enough_funds) =
            clear_from_amount.overflowing_sub(clear_amount);

        let expected_new_from_amount = if expected_did_not_have_enough_funds {
            clear_from_amount
        } else {
            expected_new_from
        };
        let expected_had_enough_funds = !expected_did_not_have_enough_funds;
        let expected_new_amount = if expected_had_enough_funds {
            clear_amount
        } else {
            0
        };
        let expected_new_to_amount = clear_to_amount + expected_new_amount;

        assert_eq!(
            decrypted_did_not_have_enough_funds, expected_did_not_have_enough_funds,
            "Invalid erc20 result on enough funds: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}."
        );
        assert_eq!(
            decrypted_new_from_amount, expected_new_from_amount,
            "Invalid erc20 result on from amount: original from amount: {clear_from_amount}, amount: {clear_amount}, to amount: {clear_to_amount}, expected new from amount: {expected_new_from_amount}."
        );
        assert_eq!(
            decrypted_new_to_amount, expected_new_to_amount,
            "Invalid erc20 result on to amount."
        );

        // Determinism check
        let (new_from_1, did_not_have_enough_funds_1) =
            overflowing_sub_executor.execute((&from_amount, &amount));

        let new_from_amount_1 = if_then_else_executor.execute((
            &did_not_have_enough_funds_1,
            &from_amount,
            &new_from_1,
        ));

        let had_enough_funds_1 = not_executor.execute(&did_not_have_enough_funds_1);
        let had_enough_funds_ct_1 = RadixCiphertext::from_blocks(vec![had_enough_funds_1.0]);
        let new_amount_1 = mul_executor.execute((&amount, &had_enough_funds_ct_1));
        let new_to_amount_1 = add_executor.execute((&to_amount, &new_amount_1));
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
